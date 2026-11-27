// Copyright (C) 2022-Present Intel Corporation
// SPDX-FileCopyrightText: 2022-present Intel Corporation
// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"fmt"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	nasLogger "github.com/omec-project/nas/v2/logger"
	ngapLogger "github.com/omec-project/ngap/v2/logger"
	openapiLogger "github.com/omec-project/openapi/v2/logger"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/openapi/v2/nfConfigApi"
	nrfCache "github.com/omec-project/openapi/v2/nrfcache"
	"github.com/omec-project/smf/callback"
	"github.com/omec-project/smf/consumer"
	smfContext "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/eventexposure"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/lawfulintercept"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/smf/metrics"
	"github.com/omec-project/smf/nfregistration"
	"github.com/omec-project/smf/oam"
	"github.com/omec-project/smf/pdusession"
	"github.com/omec-project/smf/pfcp"
	"github.com/omec-project/smf/pfcp/adapter"
	"github.com/omec-project/smf/pfcp/message"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/omec-project/smf/pfcp/upf"
	"github.com/omec-project/smf/polling"
	"github.com/omec-project/smf/producer"
	"github.com/omec-project/util/http2_util"
	utilLogger "github.com/omec-project/util/logger"
	"github.com/urfave/cli/v3"
	"go.uber.org/zap"
)

type SMF struct{}

type (
	// Config information.
	Config struct {
		cfg       string
		uerouting string
	}
)

var config Config

var smfCLi = []cli.Flag{
	&cli.StringFlag{
		Name:     "cfg",
		Usage:    "smf config file",
		Required: true,
	},
	&cli.StringFlag{
		Name:     "uerouting",
		Usage:    "uerouting config file",
		Required: true,
	},
}

func (*SMF) GetCliCmd() (flags []cli.Flag) {
	return smfCLi
}

func (smf *SMF) Initialize(c *cli.Command) error {
	config = Config{
		cfg:       c.String("cfg"),
		uerouting: c.String("uerouting"),
	}

	absPath, err := filepath.Abs(config.cfg)
	if err != nil {
		logger.CfgLog.Errorln(err)
		return err
	}

	if err = factory.InitConfigFactory(absPath); err != nil {
		return err
	}

	factory.SmfConfig.CfgLocation = absPath

	ueRoutingPath, err := filepath.Abs(config.uerouting)
	if err != nil {
		logger.CfgLog.Errorln(err)
		return err
	}

	if err := factory.InitRoutingConfigFactory(ueRoutingPath); err != nil {
		return err
	}

	smf.setLogLevel()
	go metrics.InitMetrics()

	if err := factory.CheckConfigVersion(); err != nil {
		return err
	}

	// Profiling is opt-in and bound to loopback only; the pprof handlers are
	// registered on a dedicated mux so they never leak onto other servers.
	if factory.SmfConfig.Configuration.DebugProfilePort != 0 {
		mux := http.NewServeMux()
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
		profSrv := &http.Server{
			Addr:              fmt.Sprintf("127.0.0.1:%d", factory.SmfConfig.Configuration.DebugProfilePort),
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			if err := profSrv.ListenAndServe(); err != nil {
				logger.InitLog.Warnf("start profiling server failed: %+v", err)
			}
		}()
	}
	return nil
}

func (smf *SMF) setLogLevel() {
	cfgLogger := factory.SmfConfig.Logger
	if cfgLogger == nil {
		logger.InitLog.Warnln("SMF config without log level setting, defaulting to `info`")
		return
	}

	utilLogger.ApplyLogSetting("SMF", cfgLogger.SMF, logger.InitLog, logger.SetLogLevel)
	utilLogger.ApplyLogSetting("NAS", cfgLogger.NAS, nasLogger.NasLog, nasLogger.SetLogLevel)
	utilLogger.ApplyLogSetting("NGAP", cfgLogger.NGAP, ngapLogger.NgapLog, ngapLogger.SetLogLevel)
	utilLogger.ApplyLogSetting("OpenApi", cfgLogger.OpenApi, openapiLogger.OpenapiLog, openapiLogger.SetLogLevel)
	utilLogger.ApplyLogSetting("Util", cfgLogger.Util, utilLogger.UtilLog, utilLogger.SetLogLevel)
}

// declineOptionalSubsystem logs that an optional subsystem did not start, and nothing that says
// which. The message names none, and the line carries no caller: util's logger records each
// line's call site, and the file and line of a call inside the Lawful Interception block would
// name the branch to anyone with the source.
func declineOptionalSubsystem() {
	logger.InitLog.WithOptions(zap.WithCaller(false)).Errorln("an optional subsystem failed to initialise")
}

func (smf *SMF) Start() {
	logger.InitLog.Infoln("SMF app initialising")

	// Init SMF Context
	smfCtxt := smfContext.InitSmfContext(&factory.SmfConfig)

	if smfCtxt == nil {
		logger.InitLog.Errorln("SMF context init failed")
		return
	}

	// Init UE Specific Config
	smfContext.InitSMFUERouting(&factory.UERoutingConfig)

	// Lawful Interception IRI-POI: start only when the opt-in Li config is
	// present; silent otherwise.
	if li := factory.SmfConfig.Configuration.Li; li != nil {
		// The keepalive timers and the strict `li`-block decode's verdict are passed on as the
		// operator wrote them and acted on inside Init. A refusal made here would be a return
		// from this function, which stops every other subsystem too — PFCP, the service-based
		// interface, registration with the network. Inside Init the refusal is scoped to
		// interception, and the fault reporter exists by then, so the ADMF is told that this
		// element is not intercepting.
		//
		// Inject the PFCP session-modification hook the mid-session CC trigger needs. Done
		// before Init mounts the X1 listener so the hook is in place before any tasking can
		// arrive.
		liBlockErr := factory.LiBlockError()
		lawfulintercept.SetSessionModifier(producer.ModifySessionForLI)
		// And the restart notification the adapter's PFCP handlers raise. It is a package
		// variable there rather than a direct call because pfcp/adapter may not import
		// lawfulintercept — pfcp/message imports the adapter, and lawfulintercept's tests
		// import pfcp/message — so this is where the two are joined. Only one of the native
		// and adapter handlers is active in a deployment, and a remedy present in one of them
		// is a remedy whose presence depends on enableUPFAdapter.
		adapter.POIRestarted = lawfulintercept.POIRestarted
		// And the restart hook the SMF's session restoration hangs off. See gateRestorationOnLI.
		gateRestorationOnLI()
		// And the three establishment hooks, for the same reason. Only one of the native and
		// adapter handlers is active in a deployment, so a hook present in one of them is a
		// hook whose presence depends on enableUPFAdapter: without them on the adapter path the
		// DUPL FAR would go to the UPF and the ActivateTask that authorises it would not.
		adapter.ReportEstablishment = lawfulintercept.ReportEstablishment
		adapter.ApplyCCAfterEstablishment = lawfulintercept.ApplyCCAfterEstablishment
		adapter.TriggerCC = lawfulintercept.TriggerCC
		// And the answer to this element's own PFCP modifications, for the same reason.
		adapter.LIModificationAnswered = lawfulintercept.ModificationAnswered
		if err := lawfulintercept.Init(liConfig(li, liBlockErr)); err != nil {
			// Do not name the subsystem or echo err (which carries LI-identifying
			// text) on the general operator log: that would reveal to an unauthorized
			// operator that this NE is LI-provisioned, which network-element-level
			// undetectability forbids. A listener-bind failure is already reported to
			// the ADMF over X1 from within Init; an earlier failure (e.g. bad LI
			// credentials) has no X1 channel yet and, pending a restricted LI log sink,
			// is surfaced only non-attributably here.
			declineOptionalSubsystem()
		}
	}

	// Init Kafka stream before spawning goroutines that may publish metric events.
	if err := metrics.InitialiseKafkaStream(factory.SmfConfig.Configuration); err != nil {
		logger.InitLog.Errorf("initialise kafka stream failed, %v", err)
	}

	if smfCtxt.EnableNrfCaching {
		logger.InitLog.Infof("enable NRF caching feature for %d seconds", smfCtxt.NrfCacheEvictionInterval)
		nrfCache.InitNrfCaching(smfCtxt.NrfCacheEvictionInterval*time.Second, consumer.SendNrfForNfInstance)
	}

	registrationChan := make(chan []nfConfigApi.SessionManagement, 100)
	contextUpdateChan := make(chan []nfConfigApi.SessionManagement, 100)
	ctx, cancelServices := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signalChannel
		smf.Terminate(cancelServices, &wg)
		os.Exit(0)
	}()
	wg.Add(3)

	go func() {
		defer wg.Done()
		polling.StartPollingService(
			ctx,
			factory.SmfConfig.Configuration.WebuiUri,
			registrationChan,
			contextUpdateChan,
		)
	}()

	go func() {
		defer wg.Done()
		nfregistration.StartNfRegistrationService(ctx, registrationChan)
	}()

	smfSelf := smfContext.SMF_Self()
	// Update SMF context using polled config
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				logger.InitLog.Infoln("received cancellation signal. Shutting down context update routine")
				return
			case cfg := <-contextUpdateChan:
				factory.SmfConfigSyncLock.Lock()
				err := smfContext.UpdateSmfContext(smfSelf, cfg)
				factory.SmfConfigSyncLock.Unlock()
				if err != nil {
					logger.PollConfigLog.Errorf("SMF context update failed: %v", err)
					continue
				}
				logger.PollConfigLog.Infof("SMF context updated from WebConsole config with %d slice(s)", len(cfg))
				smfContext.AllocateUPFID()
				logger.AppLog.Debugf("UserPlaneInformation: %+v", smfSelf.UserPlaneInformation)
				if smfSelf.UserPlaneInformation != nil && smfSelf.UserPlaneInformation.UPFs != nil {
					for _, upfNode := range smfSelf.UserPlaneInformation.UPFs {
						logger.AppLog.Debugf("UPF: %+v", upfNode)
						if upfNode == nil {
							continue
						}

						upfNode.UPF.UpfLock.RLock()
						alreadyAssociated := upfNode.UPF.UPFStatus == smfContext.AssociatedSetUpSuccess || upfNode.UPF.UPFStatus == smfContext.AssociatedSettingUp
						upfNode.UPF.UpfLock.RUnlock()
						if !alreadyAssociated {
							nodeID := upfNode.NodeID.ResolveNodeIdToIp()
							if nodeID == nil {
								logger.AppLog.Warnf("failed to resolve NodeId for UPF %v", upfNode)
								continue
							}

							// Sent under UpfLock, as probeUpf sends it: with the UPF adapter the response is
							// handled synchronously inside the send, and its handler relies on the caller's
							// lock to make the association status and the new recovery timestamp visible
							// together (HandleAdapterPfcpRsp).
							upfNode.UPF.UpfLock.Lock()
							err = message.SendPfcpAssociationSetupRequest(upfNode.NodeID, upfNode.Port)
							if err != nil {
								upfNode.UPF.UpfLock.Unlock()
								logger.AppLog.Warnf("failed to send PFCP Association Setup Request to UPF %v: %v", upfNode, err)
								continue
							}
							logger.AppLog.Infof("PFCP Association Setup Request sent to UPF %v", upfNode)

							// The request has only been sent, not yet acknowledged. Marking the UPF as
							// AssociatedSettingUp (instead of AssociatedSetUpSuccess) avoids callers like
							// ensureDataPathUpfAssociated treating the UPF as ready and sending PFCP Session
							// Establishment Requests that race the in-flight association, which the UPF can
							// reject with "no association found for NodeID". AssociatedSetUpSuccess is set
							// only by HandlePfcpAssociationSetupResponse once the UPF actually accepts.
							// pfcp/upf.ProbeInactiveUpfs retries the request if that response never comes.
							// The response may already have arrived and flipped this to
							// AssociatedSetUpSuccess; don't downgrade it back to pending.
							if upfNode.UPF.UPFStatus != smfContext.AssociatedSetUpSuccess {
								upfNode.UPF.UPFStatus = smfContext.AssociatedSettingUp
								upfNode.UPF.AssociationSetupSentAt = time.Now()
							}
							status := upfNode.UPF.UPFStatus
							upfNode.UPF.UpfLock.Unlock()

							logger.AppLog.Infof("UPF %v status updated to %v", upfNode, status)
						} else {
							logger.AppLog.Debugf("UPF %v already associated, skipping PFCP request", upfNode)
						}
					}
				} else {
					logger.AppLog.Warnln("UserPlaneInformation is nil, skipping PFCP association")
				}
			}
		}
	}()
	go func() {
		logger.InitLog.Infoln("InitPfcpAssociationRequest")
		go upf.InitPfcpHeartbeatRequest()
		go upf.ProbeInactiveUpfs()
	}()
	router := utilLogger.NewGinWithZap(logger.GinLog)
	oam.AddService(router)
	callback.AddService(router)
	for _, serviceName := range factory.SmfConfig.Configuration.ServiceNameList {
		switch models.ServiceName(serviceName) {
		case models.SERVICENAME_NSMF_PDUSESSION:
			pdusession.AddService(router)
		case models.SERVICENAME_NSMF_EVENT_EXPOSURE:
			eventexposure.AddService(router)
		}
	}

	if factory.SmfConfig.Configuration.EnableDbStore {
		logger.InitLog.Infoln("SetupSmfCollection")
		smfContext.SetupSmfCollection()
		// Init DRSM for unique FSEID/FTEID
		if err := smfCtxt.InitDrsm(); err != nil {
			logger.InitLog.Errorf("initialise drsm failed, %+v", err)
		}
	} else {
		logger.InitLog.Infoln("DB is disabled, not initialising drsm")
	}

	udp.Run(pfcp.Dispatch)
	time.Sleep(1000 * time.Millisecond)

	HTTPAddr := fmt.Sprintf("%s:%d", smfSelf.BindingIPv4, smfSelf.SBIPort)
	// TLS key logging is a debugging aid: off unless the operator sets SSLKEYLOGFILE (see http2_util.NewSBIServer).
	if err := http2_util.ListenAndServeSBI(HTTPAddr, router, factory.SmfConfig.Configuration.Sbi.Scheme, smfSelf.PEM, smfSelf.Key, logger.InitLog); err != nil {
		logger.InitLog.Fatalf("HTTP server setup failed: %+v", err)
	}
}

func (smf *SMF) Terminate(cancelServices context.CancelFunc, wg *sync.WaitGroup) {
	logger.InitLog.Infoln("terminating SMF")
	cancelServices()
	nfregistration.DeregisterNF()
	wg.Wait()
	logger.InitLog.Infoln("SMF terminated")
}

// ungatedRestart is the restart hook as the producer installed it, kept so that applying the gate
// again wraps that hook rather than the gate: a gate wrapping a gate takes the same node's lock
// twice and deadlocks under UpfLock.
var ungatedRestart func(smfContext.NodeID, time.Time)

// gateRestorationOnLI wraps the restart hook the SMF's session restoration hangs off, rather
// than calling the interception discard beside it: the record of what a restarted UPF held is
// settled before any of its sessions is re-installed, on every path that detects a restart,
// because restoration can be reached only through this hook.
func gateRestorationOnLI() {
	if ungatedRestart == nil {
		ungatedRestart = smfContext.OnRestart
	}
	if ungatedRestart == nil {
		return
	}
	smfContext.OnRestart = lawfulintercept.GateRestoration(lawfulintercept.RestartHooks{
		Restore: ungatedRestart,
		Abandon: producer.AbandonRestorationOnUPF,
		Release: producer.ReleaseSessionsOnUPF,
	})
}

// liConfig maps the factory's li block onto the interception subsystem's configuration.
func liConfig(li *factory.Li, blockErr error) lawfulintercept.Config {
	triggers := make([]lawfulintercept.UPFTrigger, 0, len(li.UPFTriggers))
	for _, t := range li.UPFTriggers {
		triggers = append(triggers, lawfulintercept.UPFTrigger{
			NodeID: t.NodeID, X1URL: t.X1URL, NEID: t.NEID,
		})
	}
	dests := make([]lawfulintercept.Destination, 0, len(li.Destinations))
	for _, d := range li.Destinations {
		dests = append(dests, lawfulintercept.Destination{
			DID: d.DID, DeliveryType: d.DeliveryType, Address: d.Address,
		})
	}

	return lawfulintercept.Config{
		BlockError: blockErr,
		X1Listen:   li.X1Listen, MDF2: li.MDF2, NEID: li.NEID,
		Cert: li.Cert, Key: li.Key, CACert: li.CACert,
		MDF3: li.MDF3, UPFTriggers: triggers,
		Destinations: dests,
		AdmfURL:      li.AdmfURL, AdmfID: li.AdmfID, KeepaliveTimeout: li.KeepaliveTimeout,
		KeepaliveTimeP1:        li.KeepaliveTimeP1,
		KeepaliveTimeP3:        li.KeepaliveTimeP3,
		KeepaliveRetainTasking: li.KeepaliveRetainTasking,
		KeepaliveDisabled:      li.KeepaliveDisabled,
		X2X3KeepaliveEnabled:   li.X2X3KeepaliveEnabled,
		X2X3KeepaliveTimeP1:    li.X2X3KeepaliveTimeP1,
		X2X3KeepaliveTimeP2:    li.X2X3KeepaliveTimeP2,
		DeactivateAllTasks:     li.DeactivateAllTasks,
		RemoveAllDestinations:  li.RemoveAllDestinations,
	}
}
