// SPDX-FileCopyrightText: 2022-present Intel Corporation
// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"fmt"
	"net/http"
	_ "net/http/pprof" // Using package only for invoking initialization.
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	nasLogger "github.com/omec-project/nas/logger"
	ngapLogger "github.com/omec-project/ngap/logger"
	openapiLogger "github.com/omec-project/openapi/logger"
	"github.com/omec-project/openapi/models"
	"github.com/omec-project/openapi/nfConfigApi"
	nrfCache "github.com/omec-project/openapi/nrfcache"
	"github.com/omec-project/smf/callback"
	"github.com/omec-project/smf/consumer"
	smfContext "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/eventexposure"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/smf/metrics"
	"github.com/omec-project/smf/nfregistration"
	"github.com/omec-project/smf/oam"
	"github.com/omec-project/smf/pdusession"
	"github.com/omec-project/smf/pfcp"
	"github.com/omec-project/smf/pfcp/message"
	"github.com/omec-project/smf/pfcp/udp"
	"github.com/omec-project/smf/pfcp/upf"
	"github.com/omec-project/smf/polling"
	"github.com/omec-project/util/http2_util"
	utilLogger "github.com/omec-project/util/logger"
	"github.com/urfave/cli/v3"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
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

	if err := factory.CheckConfigVersion(); err != nil {
		return err
	}

	// Initiating a server for profiling
	if factory.SmfConfig.Configuration.DebugProfilePort != 0 {
		addr := fmt.Sprintf(":%d", factory.SmfConfig.Configuration.DebugProfilePort)
		go func() {
			err := http.ListenAndServe(addr, nil)
			if err != nil {
				logger.InitLog.Warnf("start profiling server failed: %+v", err)
			}
		}()
	}
	return nil
}

func (smf *SMF) setLogLevel() {
	if factory.SmfConfig.Logger == nil {
		logger.InitLog.Warnln("SMF config without log level setting")
		return
	}

	if factory.SmfConfig.Logger.SMF != nil {
		if factory.SmfConfig.Logger.SMF.DebugLevel != "" {
			if level, err := zapcore.ParseLevel(factory.SmfConfig.Logger.SMF.DebugLevel); err != nil {
				logger.InitLog.Warnf("SMF Log level [%s] is invalid, set to [info] level",
					factory.SmfConfig.Logger.SMF.DebugLevel)
				logger.SetLogLevel(zap.InfoLevel)
			} else {
				logger.InitLog.Infof("SMF Log level is set to [%s] level", level)
				logger.SetLogLevel(level)
			}
		} else {
			logger.InitLog.Infoln("SMF Log level is default set to [info] level")
			logger.SetLogLevel(zap.InfoLevel)
		}
	}

	if factory.SmfConfig.Logger.NAS != nil {
		if factory.SmfConfig.Logger.NAS.DebugLevel != "" {
			if level, err := zapcore.ParseLevel(factory.SmfConfig.Logger.NAS.DebugLevel); err != nil {
				nasLogger.NasLog.Warnf("NAS Log level [%s] is invalid, set to [info] level",
					factory.SmfConfig.Logger.NAS.DebugLevel)
				logger.SetLogLevel(zap.InfoLevel)
			} else {
				nasLogger.SetLogLevel(level)
			}
		} else {
			nasLogger.NasLog.Warnln("NAS Log level not set. Default set to [info] level")
			nasLogger.SetLogLevel(zap.InfoLevel)
		}
	}

	if factory.SmfConfig.Logger.NGAP != nil {
		if factory.SmfConfig.Logger.NGAP.DebugLevel != "" {
			if level, err := zapcore.ParseLevel(factory.SmfConfig.Logger.NGAP.DebugLevel); err != nil {
				ngapLogger.NgapLog.Warnf("NGAP Log level [%s] is invalid, set to [info] level",
					factory.SmfConfig.Logger.NGAP.DebugLevel)
				ngapLogger.SetLogLevel(zap.InfoLevel)
			} else {
				ngapLogger.SetLogLevel(level)
			}
		} else {
			ngapLogger.NgapLog.Warnln("NGAP Log level not set. Default set to [info] level")
			ngapLogger.SetLogLevel(zap.InfoLevel)
		}
	}

	if factory.SmfConfig.Logger.OpenApi != nil {
		if factory.SmfConfig.Logger.OpenApi.DebugLevel != "" {
			if level, err := zapcore.ParseLevel(factory.SmfConfig.Logger.OpenApi.DebugLevel); err != nil {
				openapiLogger.OpenapiLog.Warnf("OpenApi Log level [%s] is invalid, set to [info] level",
					factory.SmfConfig.Logger.OpenApi.DebugLevel)
				openapiLogger.SetLogLevel(zap.InfoLevel)
			} else {
				openapiLogger.SetLogLevel(level)
			}
		} else {
			openapiLogger.OpenapiLog.Warnln("OpenApi Log level not set. Default set to [info] level")
			openapiLogger.SetLogLevel(zap.InfoLevel)
		}
	}

	if factory.SmfConfig.Logger.Util != nil {
		if factory.SmfConfig.Logger.Util.DebugLevel != "" {
			if level, err := zapcore.ParseLevel(factory.SmfConfig.Logger.Util.DebugLevel); err != nil {
				utilLogger.UtilLog.Warnf("Util (drsm, fsm, etc.) Log level [%s] is invalid, set to [info] level",
					factory.SmfConfig.Logger.Util.DebugLevel)
				utilLogger.SetLogLevel(zap.InfoLevel)
			} else {
				utilLogger.SetLogLevel(level)
			}
		} else {
			utilLogger.UtilLog.Warnln("Util (drsm, fsm, etc.) Log level not set. Default set to [info] level")
			utilLogger.SetLogLevel(zap.InfoLevel)
		}
	}

	// Initialize Statistics
	go metrics.InitMetrics()
}

func (smf *SMF) FilterCli(c *cli.Command) (args []string) {
	for _, flag := range smf.GetCliCmd() {
		name := flag.Names()[0]
		value := fmt.Sprint(c.Generic(name))
		if value == "" {
			continue
		}

		args = append(args, "--"+name, value)
	}
	return args
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
				logger.InitLog.Info("received cancellation signal. Shutting down context update routine.")
				return
			case cfg := <-contextUpdateChan:
				factory.SmfConfigSyncLock.Lock()
				err := smfContext.UpdateSmfContext(smfSelf, cfg)
				factory.SmfConfigSyncLock.Unlock()
				if err != nil {
					logger.PollConfigLog.Errorf("SMF context update failed: %v", err)
					continue
				}
				logger.PollConfigLog.Debugln("SMF context updated from WebConsole config")
				smfContext.AllocateUPFID()
				logger.AppLog.Debugf("UserPlaneInformation: %+v", smfSelf.UserPlaneInformation)
				if smfSelf.UserPlaneInformation != nil && smfSelf.UserPlaneInformation.UPFs != nil {
					for _, upfNode := range smfSelf.UserPlaneInformation.UPFs {
						logger.AppLog.Debugf("UPF: %+v", upfNode)
						if upfNode == nil {
							continue
						}

						if upfNode.UPF.UPFStatus != smfContext.AssociatedSetUpSuccess {
							nodeID := upfNode.NodeID.ResolveNodeIdToIp()
							if nodeID == nil {
								logger.AppLog.Warnf("failed to resolve NodeId for UPF %v", upfNode)
								continue
							}

							err = message.SendPfcpAssociationSetupRequest(upfNode.NodeID, upfNode.Port)
							if err != nil {
								logger.AppLog.Warnf("failed to send PFCP Association Setup Request to UPF %v: %v", upfNode, err)
							} else {
								logger.AppLog.Infof("PFCP Association Setup Request sent to UPF %v", upfNode)
							}
							upfNode.UPF.UpfLock.Lock()
							upfNode.UPF.UPFStatus = smfContext.AssociatedSetUpSuccess
							upfNode.UPF.UpfLock.Unlock()

							logger.AppLog.Infof("UPF %v status updated to AssociatedSetUpSuccess", upfNode)
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
		case models.ServiceName_NSMF_PDUSESSION:
			pdusession.AddService(router)
		case models.ServiceName_NSMF_EVENT_EXPOSURE:
			eventexposure.AddService(router)
		}
	}

	if factory.SmfConfig.Configuration.EnableDbStore {
		logger.InitLog.Infoln("SetupSmfCollection")
		smfContext.SetupSmfCollection()
		// Init DRSM for unique FSEID/FTEID
		if err := smfCtxt.InitDrsm(); err != nil {
			logger.InitLog.Errorf("initialise drsm failed, %v ", err.Error())
		}
	} else {
		logger.InitLog.Infoln("DB is disabled, not initialising drsm")
	}

	// Init Kafka stream
	if err := metrics.InitialiseKafkaStream(factory.SmfConfig.Configuration); err != nil {
		logger.InitLog.Errorf("initialise kafka stream failed, %v ", err.Error())
	}

	udp.Run(pfcp.Dispatch)
	time.Sleep(1000 * time.Millisecond)

	HTTPAddr := fmt.Sprintf("%s:%d", smfSelf.BindingIPv4, smfSelf.SBIPort)
	sslLog := filepath.Dir(factory.SmfConfig.CfgLocation) + "/sslkey.log"
	server, err := http2_util.NewServer(HTTPAddr, sslLog, router)
	if server == nil || err != nil {
		logger.InitLog.Errorf("initialize HTTP server failed: %v", err)
		return
	}

	serverScheme := factory.SmfConfig.Configuration.Sbi.Scheme
	switch serverScheme {
	case "http":
		err = server.ListenAndServe()
	case "https":
		err = server.ListenAndServeTLS(smfSelf.PEM, smfSelf.Key)
	default:
		logger.InitLog.Fatalf("HTTP server setup failed: invalid server scheme %+v", serverScheme)
		return
	}

	if err != nil {
		logger.InitLog.Fatalln("HTTP server setup failed:", err)
	}
}

func (smf *SMF) Terminate(cancelServices context.CancelFunc, wg *sync.WaitGroup) {
	logger.InitLog.Infoln("terminating SMF")
	cancelServices()
	nfregistration.DeregisterNF()
	wg.Wait()
	logger.InitLog.Infoln("SMF terminated")
}

func (smf *SMF) Exec(c *cli.Command) error {
	return nil
}
