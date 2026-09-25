// SPDX-FileCopyrightText: 2022-present Intel Corporation
// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/omec-project/nas/v2/nasConvert"
	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/openapi/v2/Namf_Communication"
	"github.com/omec-project/openapi/v2/Nnrf_NFDiscovery"
	"github.com/omec-project/openapi/v2/Npcf_SMPolicyControl"
	"github.com/omec-project/openapi/v2/models"
	nrfCache "github.com/omec-project/openapi/v2/nrfcache"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/smf/metrics"
	"github.com/omec-project/smf/msgtypes/svcmsgtypes"
	"github.com/omec-project/smf/qos"
	errors "github.com/omec-project/smf/smferrors"
	"github.com/omec-project/smf/transaction"
	util "github.com/omec-project/smf/util"
	"github.com/omec-project/util/httpwrapper"
	mi "github.com/omec-project/util/metricinfo"
	"go.uber.org/zap"
)

const (
	CONNECTED                  = "Connected"
	DISCONNECTED               = "Disconnected"
	IDLE                       = "Idle"
	PDU_SESS_REL_CMD    string = "PDUSessionReleaseCommand"
	PDU_SESS_REL_REJECT string = "PDUSessionReleaseReject"
)

var (
	smContextPool    sync.Map
	canonicalRef     sync.Map
	seidSMContextMap sync.Map
)

var smContextActive uint64

type SMContextState uint

const (
	SmStateInit SMContextState = iota
	SmStateActivePending
	SmStateActive
	SmStateInActivePending
	SmStateModify
	SmStatePfcpCreatePending
	SmStatePfcpModify
	SmStatePfcpRelease
	SmStateRelease
	SmStateN1N2TransferPending
	SmStateMax
)

func init() {
}

func incSMContextActive() uint64 {
	// The add returns the new value. Reading the variable again is a plain load racing with every
	// other caller's atomic store, and it can return a count from a different moment than the one
	// this call produced.
	return atomic.AddUint64(&smContextActive, 1)
}

func decSMContextActive() uint64 {
	return atomic.AddUint64(&smContextActive, ^uint64(0))
}

type UeIpAddr struct {
	Ip          net.IP
	UpfProvided bool
}

type SMContext struct {
	Ref string `json:"ref" yaml:"ref" bson:"ref"`

	// SUPI or PEI
	Supi              string `json:"supi,omitempty" yaml:"supi" bson:"supi,omitempty"`
	Pei               string `json:"pei,omitempty" yaml:"pei" bson:"pei,omitempty"`
	Identifier        string `json:"identifier" yaml:"identifier" bson:"identifier"`
	Gpsi              string `json:"gpsi,omitempty" yaml:"gpsi" bson:"gpsi,omitempty"`
	Dnn               string `json:"dnn" yaml:"dnn" bson:"dnn"`
	UeTimeZone        string `json:"ueTimeZone,omitempty" yaml:"ueTimeZone" bson:"ueTimeZone,omitempty"` // ignore
	ServingNfId       string `json:"servingNfId,omitempty" yaml:"servingNfId" bson:"servingNfId,omitempty"`
	SmStatusNotifyUri string `json:"smStatusNotifyUri,omitempty" yaml:"smStatusNotifyUri" bson:"smStatusNotifyUri,omitempty"`

	UpCnxState         models.UpCnxState         `json:"upCnxState,omitempty" yaml:"upCnxState" bson:"upCnxState,omitempty"`
	AMFProfile         models.NFProfileDiscovery `json:"amfProfile,omitempty" yaml:"amfProfile" bson:"amfProfile,omitempty"`
	SelectedPCFProfile models.NFProfileDiscovery `json:"selectedPCFProfile,omitempty" yaml:"selectedPCFProfile" bson:"selectedPCFProfile,omitempty"`
	AnType             models.AccessType         `json:"anType" yaml:"anType" bson:"anType"`
	RatType            models.RatType            `json:"ratType,omitempty" yaml:"ratType" bson:"ratType,omitempty"`

	// ExtendedNasSmTimer is the AMF's indication that the extended NAS timer values for access
	// via a satellite NG-RAN cell apply to this session (TS 24.501 subclause 4.23.4).
	ExtendedNasSmTimer bool `json:"extendedNasSmTimer,omitempty" yaml:"extendedNasSmTimer" bson:"extendedNasSmTimer,omitempty"`

	// T3591Value and T3591Source are resolved once per session, as subclause 4.23.4 requires the
	// value to be calculated at the start of a procedure and not recalculated until it completes,
	// restarts or aborts. Ordinarily that is at creation, in SetCreateData. A session restored
	// from a record written before this field existed carries zero, and startT3591Locked resolves
	// it there rather than arming a timer with an interval time.NewTicker refuses.
	T3591Value time.Duration `json:"t3591Value,omitempty" yaml:"t3591Value" bson:"t3591Value,omitempty"`

	// T3591 is the live retransmission timer for a modification awaiting the UE's answer. It is
	// a goroutine handle, so it is neither serialised nor restored with the session.
	// NwModificationPending is true from the moment the network commits to modifying this session
	// until the procedure ends, however it ends. It is what makes a colliding UE request
	// recognisable, per TS 24.501 subclause 6.3.2.5 item d.
	//
	// T3591 alone will not do. It is armed only once the Command has gone out, and the procedure
	// starts a PFCP round trip earlier — a UE request arriving in that window is just as much a
	// collision as one arriving later, and would otherwise be refused instead of disregarded.
	//
	// Read and written under SMLock.
	// Not persisted, for the same reason T3591 and Realign are not: it describes a procedure that
	// is in flight right now. Restoring it from the database would leave a session with a
	// modification permanently pending — no timer, no procedure, and every UE modification request
	// for that session disregarded from then on.
	NwModificationPending bool `json:"-" yaml:"-" bson:"-"`

	// RevertInFlight is open from the moment a modification whose user plane was programmed is
	// abandoned until the revert that puts the user plane back has finished, and nil otherwise. A
	// new modification waits for it: built first, it would be undone by the revert, which restores
	// the committed rules over whatever the new one had just programmed. Not persisted, as the
	// fields above are not.
	RevertInFlight chan struct{} `json:"-" yaml:"-" bson:"-"`

	// RanAnswerPending is true from the moment a modification is sent towards the radio until its
	// response or failure is acted on, or until the modification is abandoned. It is what tells a
	// stale answer from the one this session is waiting for; NwModificationPending cannot, because
	// it tracks the UE's half and the UE can answer before the radio does.
	RanAnswerPending bool `json:"-" yaml:"-" bson:"-"`

	T3591 *Timer `json:"-" yaml:"-" bson:"-"`

	// Realign is set when the radio access network established only part of a modification. It is
	// acted on once the UE acknowledges that modification, not before.
	Realign *PendingRealignment `json:"-" yaml:"-" bson:"-"`

	// CommittedBeforeRanAnswer holds the update a UE completion committed while the radio's answer
	// was still outstanding. The two answers can arrive in either order, and the realignment is
	// normally built by the completion, by pruning the still-pending update to what the radio
	// established. When the UE is first there is no longer a pending update to prune -- it has been
	// committed whole, refused flows and all -- so the answer that follows has to build the
	// correction itself, and this is what it builds it from. Cleared as soon as that answer is
	// acted on, when the modification is abandoned, and when the next one replaces it.
	CommittedBeforeRanAnswer *qos.PolicyUpdate       `json:"-" yaml:"-" bson:"-"`
	T3591Source              NasTimerSource          `json:"t3591Source,omitempty" yaml:"t3591Source" bson:"t3591Source,omitempty"`
	PresenceInLadn           models.PresenceState    `json:"presenceInLadn,omitempty" yaml:"presenceInLadn" bson:"presenceInLadn,omitempty"` // ignore
	HoState                  models.HoState          `json:"hoState,omitempty" yaml:"hoState" bson:"hoState,omitempty"`
	DnnConfiguration         models.DnnConfiguration `json:"dnnConfiguration,omitempty" yaml:"dnnConfiguration" bson:"dnnConfiguration,omitempty"` // ?

	Snssai         *models.Snssai       `json:"snssai" yaml:"snssai" bson:"snssai"`
	HplmnSnssai    *models.Snssai       `json:"hplmnSnssai,omitempty" yaml:"hplmnSnssai" bson:"hplmnSnssai,omitempty"`
	ServingNetwork models.PlmnIdNid     `json:"servingNetwork,omitempty" yaml:"servingNetwork" bson:"servingNetwork,omitempty"`
	UeLocation     *models.UserLocation `json:"ueLocation,omitempty" yaml:"ueLocation" bson:"ueLocation,omitempty"`
	AddUeLocation  *models.UserLocation `json:"addUeLocation,omitempty" yaml:"addUeLocation" bson:"addUeLocation,omitempty"` // ignore

	// PDUAddress             net.IP `json:"pduAddress,omitempty" yaml:"pduAddress" bson:"pduAddress,omitempty"`
	PDUAddress *UeIpAddr `json:"pduAddress,omitempty" yaml:"pduAddress" bson:"pduAddress,omitempty"`

	// Client
	SMPolicyClient      *Npcf_SMPolicyControl.APIClient `json:"smPolicyClient,omitempty" yaml:"smPolicyClient" bson:"smPolicyClient,omitempty"`                // ?
	CommunicationClient *Namf_Communication.APIClient   `json:"communicationClient,omitempty" yaml:"communicationClient" bson:"communicationClient,omitempty"` // ?

	// encountered a cycle via *context.GTPTunnel
	Tunnel *UPTunnel `json:"-" yaml:"tunnel" bson:"-"`

	BPManager *BPManager `json:"bpManager,omitempty" yaml:"bpManager" bson:"bpManager,omitempty"` // ignore

	DNNInfo *SnssaiSmfDnnInfo `json:"dnnInfo,omitempty" yaml:"dnnInfo" bson:"dnnInfo,omitempty"`

	// PCO Related
	ProtocolConfigurationOptions *ProtocolConfigurationOptions `json:"protocolConfigurationOptions" yaml:"protocolConfigurationOptions" bson:"protocolConfigurationOptions"` // ignore

	SubGsmLog      *zap.SugaredLogger `json:"-" yaml:"subGsmLog" bson:"-,"`     // ignore
	SubPfcpLog     *zap.SugaredLogger `json:"-" yaml:"subPfcpLog" bson:"-"`     // ignore
	SubPduSessLog  *zap.SugaredLogger `json:"-" yaml:"subPduSessLog" bson:"-"`  // ignore
	SubCtxLog      *zap.SugaredLogger `json:"-" yaml:"subCtxLog" bson:"-"`      // ignore
	SubConsumerLog *zap.SugaredLogger `json:"-" yaml:"subConsumerLog" bson:"-"` // ignore
	SubFsmLog      *zap.SugaredLogger `json:"-" yaml:"subFsmLog" bson:"-"`      // ignore
	SubQosLog      *zap.SugaredLogger `json:"-" yaml:"subQosLog" bson:"-"`      // ignore

	// encountered a cycle via *context.SMContext
	ActiveTxn *transaction.Transaction `json:"-" yaml:"activeTxn" bson:"-,"` // ignore
	// SM Policy related
	// Updates in policy from PCF
	SmPolicyUpdates []*qos.PolicyUpdate `json:"smPolicyUpdates" yaml:"smPolicyUpdates" bson:"smPolicyUpdates"` // ignore
	// Holds Session/PCC Rules and Qos/Cond/Charging Data
	SmPolicyData qos.SmCtxtPolicyData `json:"smPolicyData" yaml:"smPolicyData" bson:"smPolicyData"`
	// unsupported structure - madatory!
	SBIPFCPCommunicationChan chan PFCPSessionResponseStatus `json:"-" yaml:"sbiPFCPCommunicationChan" bson:"-"` // ignore

	PendingUPF PendingUPF `json:"pendingUPF,omitempty" yaml:"pendingUPF" bson:"pendingUPF,omitempty"` // ignore
	// NodeID(string form) to PFCP Session Context
	PFCPContext map[string]*PFCPSessionContext `json:"-" yaml:"pfcpContext" bson:"-"`
	// TxnBus per subscriber
	TxnBus transaction.TxnBus `json:"-" yaml:"txnBus" bson:"-"` // ignore
	// SMTxnBusLock sync.Mutex         `json:"smTxnBusLock,omitempty" yaml:"smTxnBusLock" bson:"smTxnBusLock,omitempty"` // ignore
	SMTxnBusLock sync.Mutex `json:"-" yaml:"smTxnBusLock" bson:"-"` // ignore
	// lock
	// SMLock sync.Mutex `json:"smLock,omitempty" yaml:"smLock" bson:"smLock,omitempty"` // ignore
	SMLock sync.Mutex `json:"-" yaml:"smLock" bson:"-"` // ignore

	SMContextState                      SMContextState `json:"smContextState" yaml:"smContextState" bson:"smContextState"`
	PDUSessionID                        int32          `json:"pduSessionID" yaml:"pduSessionID" bson:"pduSessionID"`
	OldPduSessionId                     int32          `json:"oldPduSessionId,omitempty" yaml:"oldPduSessionId" bson:"oldPduSessionId,omitempty"`
	SelectedPDUSessionType              uint8          `json:"selectedPDUSessionType,omitempty" yaml:"selectedPDUSessionType" bson:"selectedPDUSessionType,omitempty"`
	UnauthenticatedSupi                 bool           `json:"unauthenticatedSupi,omitempty" yaml:"unauthenticatedSupi" bson:"unauthenticatedSupi,omitempty"`                                                 // ignore
	PDUSessionRelease_DUE_TO_DUP_PDU_ID bool           `json:"pduSessionRelease_DUE_TO_DUP_PDU_ID,omitempty" yaml:"pduSessionRelease_DUE_TO_DUP_PDU_ID" bson:"pduSessionRelease_DUE_TO_DUP_PDU_ID,omitempty"` // ignore
	LocalPurged                         bool           `json:"localPurged,omitempty" yaml:"localPurged" bson:"localPurged,omitempty"`                                                                         // ignore
	// NAS
	Pti                     uint8 `json:"pti,omitempty" yaml:"pti" bson:"pti,omitempty"` // ignore
	EstAcceptCause5gSMValue uint8 `json:"estAcceptCause5gSMValue,omitempty" yaml:"estAcceptCause5gSMValue" bson:"estAcceptCause5gSMValue,omitempty"`

	// activeIP, activeUpf and activeEnterprise are the ip/upf/enterprise labels the
	// smf_pdu_session_profile series was published with on entering SmStateActive. Leaving
	// Active must delete that exact series; re-deriving these labels at that later point can
	// disagree with what was recorded on entry (e.g. the tunnel resolves differently, or
	// PDUAddress.Ip has already been reset by ReleaseUeIpAddr) and leave the original series
	// behind.
	activeIP         string `json:"-" yaml:"-" bson:"-"`
	activeUpf        string `json:"-" yaml:"-" bson:"-"`
	activeEnterprise string `json:"-" yaml:"-" bson:"-"`

	// lastUpfName and lastUpfIP are the UPF identity getSmCtxtUpf most recently resolved from
	// the tunnel. releaseTunnel clears Tunnel before RemoveSMContext publishes the terminal
	// disconnect event, so without this the final Kafka event would report an empty UPF.
	lastUpfName string `json:"-" yaml:"-" bson:"-"`
	lastUpfIP   string `json:"-" yaml:"-" bson:"-"`
}

func canonicalName(identifier string, pduSessID int32) (canonical string) {
	return fmt.Sprintf("%s-%d", identifier, pduSessID)
}

func ResolveRef(identifier string, pduSessID int32) (ref string, err error) {
	if value, ok := canonicalRef.Load(canonicalName(identifier, pduSessID)); ok {
		ref = value.(string)
		err = nil
	} else {
		ref = ""
		err = fmt.Errorf(
			"UE '%s' - PDUSessionID '%d' not found in SMContext", identifier, pduSessID)
	}
	return
}

func NewSMContext(identifier string, pduSessID int32) (smContext *SMContext) {
	smContext = new(SMContext)
	// Create Ref and identifier
	smContext.Ref = uuid.New().URN()

	smContext.SMContextState = SmStateInit
	smContext.Identifier = identifier
	smContext.PDUSessionID = pduSessID
	smContext.PFCPContext = make(map[string]*PFCPSessionContext)

	// initialize SM Policy Data
	smContext.SBIPFCPCommunicationChan = make(chan PFCPSessionResponseStatus, 1)
	smContext.SmPolicyUpdates = make([]*qos.PolicyUpdate, 0)
	smContext.SmPolicyData.Initialize()

	smContext.ProtocolConfigurationOptions = &ProtocolConfigurationOptions{
		DNSIPv4Request: false,
		DNSIPv6Request: false,
	}

	// initialise log tags
	smContext.initLogTags()

	// Published only once it is fully built, and this is the last thing built. Anything that finds
	// the context -- by ref, by canonical name, or by ranging the pool -- would otherwise be able
	// to observe one whose maps, channels or loggers have not been assigned yet: a data race on
	// every field above, and a nil dereference on the Sub*Log fields, which every handler uses
	// before it does anything else. Publishing after the maps but before initLogTags would close
	// the first of those and leave the second.
	smContextPool.Store(smContext.Ref, smContext)
	canonicalRef.Store(canonicalName(identifier, pduSessID), smContext.Ref)

	// Sess Stats
	smContextActive := incSMContextActive()
	metrics.SetSessStats(SMF_Self().NfInstanceID, smContextActive)

	return smContext
}

func (smContext *SMContext) initLogTags() {
	smContext.SubPfcpLog = logger.PfcpLog.With("uuid", smContext.Ref, "id", smContext.Identifier, "pduid", smContext.PDUSessionID)
	smContext.SubCtxLog = logger.CtxLog.With("uuid", smContext.Ref, "id", smContext.Identifier, "pduid", smContext.PDUSessionID)
	smContext.SubPduSessLog = logger.PduSessLog.With("uuid", smContext.Ref, "id", smContext.Identifier, "pduid", smContext.PDUSessionID)
	smContext.SubGsmLog = logger.GsmLog.With("uuid", smContext.Ref, "id", smContext.Identifier, "pduid", smContext.PDUSessionID)
	smContext.SubConsumerLog = logger.ConsumerLog.With("uuid", smContext.Ref, "id", smContext.Identifier, "pduid", smContext.PDUSessionID)
	smContext.SubFsmLog = logger.FsmLog.With("uuid", smContext.Ref, "id", smContext.Identifier, "pduid", smContext.PDUSessionID)
	smContext.SubQosLog = logger.QosLog.With("uuid", smContext.Ref, "id", smContext.Identifier, "pduid", smContext.PDUSessionID)
}

// WaitForOwedRevert blocks while a revert is owed on the session, and returns holding nothing. The
// caller must hold neither SMLock nor the transaction bus lock: the revert takes SMLock to build.
func (smContext *SMContext) WaitForOwedRevert() {
	for {
		smContext.SMLock.Lock()
		owed := smContext.RevertInFlight
		smContext.SMLock.Unlock()
		if owed == nil {
			return
		}
		<-owed
	}
}

func (smContext *SMContext) ChangeState(nextState SMContextState) {
	if smContext.SMContextState == nextState {
		// Not a real transition (e.g. a retry/no-op ChangeState call with the same target
		// state): skip the metrics/Kafka publish below so callers that re-invoke ChangeState
		// for logging purposes don't emit duplicate terminal events.
		return
	}
	if smContext.SMContextState == SmStateRelease {
		// RemoveSMContext already deleted this session from the pool. The FSM handler that
		// triggered it still returns a "next" state of its own (e.g. SmStateInit) and
		// HandleEvent applies it unconditionally, so without this guard a released session
		// would keep mutating state and re-publishing Kafka events (potentially resurrecting
		// it downstream) after it no longer exists. Release is terminal.
		return
	}

	// Update Subscriber profile Metrics
	if nextState == SmStateActive || smContext.SMContextState == SmStateActive {
		if nextState == SmStateActive {
			upf, _ := smContext.getSmCtxtUpf()

			// enterprise name
			ent := "na"
			if smfContext.EnterpriseList != nil {
				entMap := *smfContext.EnterpriseList
				smContext.SubCtxLog.Debugf("context state change, Enterprises configured = [%v], subscriber slice sst [%v], sd [%v]",
					entMap, smContext.Snssai.Sst, smContext.Snssai.Sd)
				ent = entMap[strconv.Itoa(int(smContext.Snssai.GetSst()))+smContext.Snssai.GetSd()]
			} else {
				smContext.SubCtxLog.Debug("context state change, enterprise info not available")
			}

			smContext.activeIP = smContext.PDUAddress.Ip.String()
			smContext.activeUpf = upf
			smContext.activeEnterprise = ent
			metrics.SetSessProfileStats(smContext.Identifier, smContext.activeIP, nextState.String(),
				upf, ent, 1)
		} else {
			// Delete the exact series recorded on entry rather than setting a fresh one to 0:
			// re-deriving the ip/upf/enterprise labels now can disagree with what was recorded
			// then (e.g. ReleaseUeIpAddr has already reset PDUAddress.Ip to 0.0.0.0 by this point)
			// and leave the original "active" series behind forever, showing the session twice.
			metrics.DeleteSessProfileStats(smContext.Identifier, smContext.activeIP, smContext.SMContextState.String(),
				smContext.activeUpf, smContext.activeEnterprise)
		}
	}

	smContext.SubCtxLog.Infof("context state change, current state[%v] next state[%v]",
		smContext.SMContextState.String(), nextState.String())
	smContext.SMContextState = nextState

	// Published after the state is updated so the Kafka event reports the state being entered,
	// not the one being left.
	smContext.PublishSmCtxtInfo()
}

// *** add unit test ***//
func GetSMContext(ref string) (smContext *SMContext) {
	if value, ok := smContextPool.Load(ref); ok {
		smContext = value.(*SMContext)
	} else if factory.SmfConfig.Configuration.EnableDbStore && !IsSmContextDeleteFailed(ref) {
		// IsSmContextDeleteFailed excludes refs whose by-ref document RemoveSMContextLocked
		// could not delete: without that check, a pool miss right after a failed delete would
		// read the still-present, released document back from Mongo and resurrect it here.
		if dbContext := GetSMContextByRefInDB(ref); dbContext != nil {
			smContextPool.Store(ref, dbContext)
			smContext = dbContext
		}
	}

	return
}

// SessionsAnchoredOn returns the SM contexts that hold a PFCP session on the given node.
//
// There is no index from a user-plane node to the sessions anchored on it, so this ranges the
// pool. The PFCP context of each session is keyed by the node's address, which is the same key
// the session establishment path uses, so membership is a lookup rather than a walk of the data
// path.
//
// The result is a snapshot. Sessions established after it are already correct on a node that has
// just restarted and must not be re-installed, and sessions released after it must not be
// resurrected — so callers work from the list as taken and re-check liveness before acting on any
// entry.
// The second return names the sessions that could not be examined, rather than counting them.
//
// A session whose lock could not be taken cannot have its PFCPContext read, so there is no way to
// tell whether it is anchored on this node or on another one -- and counting it against this node
// makes a UPF with nothing on it report sessions it does not have. The references are returned so
// the caller can decide which of them it has previously seen on this node; Ref is assigned before
// the context is published to the pool and never changes, so reading it without the lock is safe.
// The third return counts sessions anchored here whose first establishment is still outstanding.
// They are excluded from restoration deliberately -- reissuing over an establishment in flight
// overwrites it -- but a caller that sees no anchored sessions must not conclude the node is empty
// when this is non-zero.
func SessionsAnchoredOn(nodeID NodeID) (anchoredSessions []*SMContext, couldNotExamine []string, stillEstablishing int) {
	nodeIP := nodeID.ResolveNodeIdToIp().String()

	anchored := make([]*SMContext, 0)
	unexaminable := make([]string, 0)
	scanned, superseded, establishing := 0, 0, 0
	otherKeys := make(map[string]int)
	smContextPool.Range(func(_, value any) bool {
		smContext, ok := value.(*SMContext)
		if !ok || smContext == nil {
			return true
		}
		scanned++

		// TryLock, never Lock. This ranges every session in the pool, so blocking on one session's
		// lock makes a global sweep wait on a single session's procedure. The codebase holds SMLock
		// across network calls -- the N1N2 transfer to the AMF, among others -- so that wait is
		// unbounded, and a sweep stuck behind it never returns. Observed on a cluster: one session
		// held the lock and every subsequent restoration for that UPF stopped before its first log
		// line.
		//
		// Skipping a session whose lock is held is the right answer rather than a concession. A
		// session mid-procedure is being established, modified or torn down, and none of those is a
		// session the restarted node was holding.
		if !smContext.SMLock.TryLock() {
			unexaminable = append(unexaminable, smContext.Ref)
			return true
		}
		pfcpContext, onThisNode := smContext.PFCPContext[nodeIP]
		// A session the node has never acknowledged is not a session it was holding. The entry is
		// created when the rules are allocated and RemoteSEID is filled in only when the
		// establishment response arrives, so a zero that restoration did not write means an
		// establishment is still outstanding: a session being set up alongside the restart rather
		// than one lost to it.
		//
		// Restoring one overwrites the establishment in flight. Seen on a cluster, three
		// milliseconds either side of the race: the UE address was pinned to the SMF's placeholder
		// before the UPF had chosen one, and the subscriber came up on an address outside the pool
		// with no downlink -- a worse outcome than the stall this change exists to fix.
		neverAcknowledged := onThisNode && pfcpContext.RemoteSEID == 0 && !pfcpContext.ClearedByRestoration
		identifier, pduSessionID, ref := smContext.Identifier, smContext.PDUSessionID, smContext.Ref
		if !onThisNode {
			for key := range smContext.PFCPContext {
				otherKeys[key]++
			}
		}
		smContext.SMLock.Unlock()

		if !onThisNode {
			return true
		}
		if neverAcknowledged {
			establishing++
			return true
		}
		if !isCurrent(identifier, pduSessionID, ref) {
			superseded++
			return true
		}
		anchored = append(anchored, smContext)
		return true
	})

	// Logged unconditionally. A sweep that reports only when it skipped something is silent in the
	// case that matters most -- finding nothing at all -- and that silence cost a diagnosis round:
	// "no sessions anchored" with no way to tell an empty pool from a mis-keyed lookup.
	logger.CtxLog.Infof("sessions anchored on %s: %d of %d scanned (%d could not be examined and may be "+
		"on any node, %d superseded by a later session for the same subscriber, %d still being established)",
		nodeIP, len(anchored), scanned, len(unexaminable), superseded, establishing)
	if len(anchored) == 0 && len(otherKeys) > 0 {
		// Separates an empty pool from a lookup that did not match: if sessions are anchored under
		// some other key, the node identity resolved differently here than when they were created.
		logger.CtxLog.Warnf("no session matched %s, but the pool holds sessions anchored under %v",
			nodeIP, otherKeys)
	}
	return anchored, unexaminable, establishing
}

// isCurrent reports whether this context is still the one the subscriber's PDU session resolves to.
//
// A context is superseded rather than released when a UE establishes the same PDU session again
// without the old one being torn down -- a simulator restarted, a UE that re-attached after losing
// the network. The canonical reference for that subscriber and session identifier is repointed at
// the new context, and the old one stays in the pool describing a session nothing will ever use.
//
// Restoring one is worse than skipping it. It programs the recovered user plane with a rule for a UE
// address that is gone, and it spends restoration effort the live session needed. Observed on a
// cluster: the rule installed after a restart named a UE address two sessions out of date, while the
// live session was never restored.
func isCurrent(identifier string, pduSessionID int32, ref string) bool {
	current, err := ResolveRef(identifier, pduSessionID)
	if err != nil {
		return false
	}
	return current == ref
}

// *** add unit test ***//
func RemoveSMContext(ref string) {
	var smContext *SMContext
	value, ok := smContextPool.Load(ref)
	if !ok {
		logger.CtxLog.Warnf("RemoveSMContext: no SMContext found for ref %s", ref)
		return
	}

	smContext, ok = value.(*SMContext)
	if !ok || smContext == nil {
		logger.CtxLog.Warnf("removeSMContext: invalid SMContext type or nil for ref %s", ref)
		return
	}

	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()
	RemoveSMContextLocked(smContext)
}

// RemoveSMContextLocked does the release transition, DB deletes, and pool/canonicalRef cleanup for
// smContext. The caller must already hold smContext.SMLock: RemoveSMContext acquires it before
// calling this; producer's restoration release path (markReleasedAndBuild) already holds it - to
// keep the release atomic with the N1N2 release-command build that follows - and calls this
// directly instead of RemoveSMContext to avoid relocking the same, non-reentrant mutex.
//
// Holding SMLock here also serializes this against AsyncStoreSmContextInDB, which takes the same
// lock and checks for SmStateRelease before enqueueing: a write can never be enqueued after the DB
// deletes below and resurrect the document.
func RemoveSMContextLocked(smContext *SMContext) {
	smContext.SubCtxLog.Infof("RemoveSMContext, SM context released ")
	smContext.ChangeState(SmStateRelease)

	for _, pfcpSessionContext := range smContext.PFCPContext {
		seidSMContextMap.Delete(pfcpSessionContext.LocalSEID)
		if factory.SmfConfig.Configuration.EnableDbStore {
			DeleteSmContextInDBBySEID(pfcpSessionContext.LocalSEID)
		}
	}

	if factory.SmfConfig.Configuration.EnableDbStore {
		// The SEID loop above only reaches the main by-ref document via a SEID mapping, so a
		// context released before any PFCP session was ever established (e.g. a create
		// rollback) still needs this unconditional delete to remove its by-ref document -
		// otherwise a stale, non-terminal document could be read back and resurrected into the
		// pool by a later GetSMContext.
		DeleteSmContextInDBByRef(smContext.Ref)
	}

	// Release UE IP-Address
	err := smContext.ReleaseUeIpAddr()
	if err != nil {
		smContext.SubCtxLog.Errorf("release UE IP-Address failed, %v", err)
	}

	smContextPool.Delete(smContext.Ref)

	// NewSMContext registers the canonical entry under Identifier, not Supi -- and Supi is still
	// empty here for a context that never ran SetCreateData. Deleting by Supi in that case would
	// leave the canonical entry behind, resolvable to a ref that no longer exists in the pool.
	// Use CompareAndDelete so a replacement context (created after this one was superseded via
	// restoration) is not accidentally unlinked from the canonical map.
	canonicalRef.CompareAndDelete(canonicalName(smContext.Identifier, smContext.PDUSessionID), smContext.Ref)
	// Sess Stats
	smContextActive := decSMContextActive()
	metrics.SetSessStats(SMF_Self().NfInstanceID, smContextActive)
}

// *** add unit test ***//
func GetSMContextBySEID(SEID uint64) (smContext *SMContext) {
	if value, ok := seidSMContextMap.Load(SEID); ok {
		smContext = value.(*SMContext)
	} else {
		if factory.SmfConfig.Configuration.EnableDbStore {
			smContext = GetSMContextBySEIDInDB(SEID)
		}
	}
	return
}

func (smContext *SMContext) ReleaseUeIpAddr() error {
	if smContext.PDUAddress == nil {
		logger.CtxLog.Warnf("ReleaseUeIpAddr: PduSessionUeAddress is nil, skipping release")
		return nil
	}
	if ip := smContext.PDUAddress.Ip; ip != nil && !smContext.PDUAddress.UpfProvided {
		smContext.SubPduSessLog.Infof("Release IP[%s]", smContext.PDUAddress.Ip.String())
		smContext.DNNInfo.UeIPAllocator.Release(smContext.Supi, ip)
		smContext.PDUAddress.Ip = net.IPv4(0, 0, 0, 0)
	}
	return nil
}

// *** add unit test ***//
func (smContext *SMContext) SetCreateData(createData *models.SmContextCreateData) {
	smContext.Gpsi = createData.GetGpsi()
	smContext.Supi = createData.GetSupi()
	smContext.Dnn = createData.GetDnn()
	smContext.Snssai = createData.SNssai
	smContext.HplmnSnssai = createData.HplmnSnssai
	smContext.ServingNetwork = createData.GetServingNetwork()
	smContext.AnType = createData.GetAnType()
	smContext.RatType = createData.GetRatType()
	smContext.ExtendedNasSmTimer = createData.GetExtendedNasSmTimerInd()
	smContext.T3591Value, smContext.T3591Source = ResolveT3591(
		factory.SmfConfig.Configuration.T3591, smContext.ExtendedNasSmTimer)
	smContext.SubCtxLog.Infof("T3591 for this session is %s, decided by %s",
		smContext.T3591Value, smContext.T3591Source)
	metrics.IncrementNasTimerStats("T3591", string(smContext.T3591Source), smContext.T3591Value.String())
	smContext.PresenceInLadn = createData.GetPresenceInLadn()
	smContext.UeLocation = createData.UeLocation
	smContext.UeTimeZone = createData.GetUeTimeZone()
	smContext.AddUeLocation = createData.AddUeLocation
	smContext.OldPduSessionId = createData.GetOldPduSessionId()
	smContext.ServingNfId = createData.GetServingNfId()
}

// RebuildCommunicationClient reconstructs the Namf_Communication API client
// from the stored AMFProfile. This is needed after recovering an SMContext from
// MongoDB, since CommunicationClient is not serializable.
func (smContext *SMContext) RebuildCommunicationClient() {
	// Clear any existing client first so stale data does not linger if the
	// (re-discovered) AMF profile has no namf-comm service.
	smContext.CommunicationClient = nil
	service, ok := util.FindServiceByName(util.NFProfileDiscoveryServices(&smContext.AMFProfile), models.SERVICENAME_NAMF_COMM)
	if !ok {
		return
	}
	communicationConf := Namf_Communication.NewConfiguration()
	serverConfig := &communicationConf.Servers[0]
	if apiRootVar, exists := serverConfig.Variables["apiRoot"]; exists {
		apiRootVar.DefaultValue = service.GetApiPrefix()
		serverConfig.Variables["apiRoot"] = apiRootVar
	}
	smContext.CommunicationClient = Namf_Communication.NewAPIClient(communicationConf)
}

// RebuildSMPolicyClient reconstructs the Npcf_SMPolicyControl API client
// from the stored SelectedPCFProfile after recovering an SMContext from MongoDB.
func (smContext *SMContext) RebuildSMPolicyClient() {
	smContext.SMPolicyClient = nil
	service, ok := util.FindServiceByName(util.NFProfileDiscoveryServices(&smContext.SelectedPCFProfile), models.SERVICENAME_NPCF_SMPOLICYCONTROL)
	if !ok {
		return
	}
	cfg := Npcf_SMPolicyControl.NewConfiguration()
	serverConfig := &cfg.Servers[0]
	if apiRootVar, exists := serverConfig.Variables["apiRoot"]; exists {
		apiRootVar.DefaultValue = service.GetApiPrefix()
		serverConfig.Variables["apiRoot"] = apiRootVar
	}
	smContext.SMPolicyClient = Npcf_SMPolicyControl.NewAPIClient(cfg)
}

func (smContext *SMContext) BuildCreatedData() (createdData *models.SmContextCreatedData) {
	createdData = models.NewSmContextCreatedData()
	createdData.SNssai = smContext.Snssai
	return
}

func (smContext *SMContext) PDUAddressToNAS() (addr [12]byte, addrLen uint8) {
	copy(addr[:], smContext.PDUAddress.Ip)
	switch smContext.SelectedPDUSessionType {
	case nasMessage.PDUSessionTypeIPv4:
		addrLen = 4 + 1
	case nasMessage.PDUSessionTypeIPv6:
	case nasMessage.PDUSessionTypeIPv4IPv6:
		addrLen = 12 + 1
	}
	return
}

// PCFSelection will select PCF for this SM Context
func (smContext *SMContext) PCFSelection() error {
	// Send NFDiscovery for find PCF
	localVarOptionals := Nnrf_NFDiscovery.ApiSearchNFInstancesRequest{}

	var rep *models.SearchResult
	var res *http.Response
	var err error

	if SMF_Self().EnableNrfCaching {
		rep, err = nrfCache.SearchNFInstances(context.Background(), SMF_Self().NrfUri, models.NFTYPE_PCF, models.NFTYPE_SMF, localVarOptionals)
		if err != nil {
			return err
		}
	} else {
		localVarOptionals := SMF_Self().
			NFDiscoveryClient.
			NFInstancesStoreAPI.
			SearchNFInstances(context.TODO())
		localVarOptionals = localVarOptionals.TargetNfType(models.NFTYPE_PCF)
		localVarOptionals = localVarOptionals.RequesterNfType(models.NFTYPE_SMF)
		rep, res, err = SMF_Self().
			NFDiscoveryClient.
			NFInstancesStoreAPI.
			SearchNFInstancesExecute(localVarOptionals)
		if err != nil {
			metrics.IncrementSvcNrfMsgStats(SMF_Self().NfInstanceID, string(svcmsgtypes.NnrfNFDiscoveryPcf), "In", "Failure", err.Error())
			return err
		}
		defer func() {
			if rspCloseErr := res.Body.Close(); rspCloseErr != nil {
				logger.PduSessLog.Errorf("SmfEventExposureNotification response body cannot close: %+v", rspCloseErr)
			}
		}()

		if res != nil {
			if status := res.StatusCode; status != http.StatusOK {
				metrics.IncrementSvcNrfMsgStats(SMF_Self().NfInstanceID, string(svcmsgtypes.NnrfNFDiscoveryPcf), "In", "Failure", "")
				logger.CtxLog.Warnf("NFDiscovery PCF return status: %d", status)
			}
		}

		// Select PCF from available PCF
		metrics.IncrementSvcNrfMsgStats(SMF_Self().NfInstanceID, string(svcmsgtypes.NnrfNFDiscoveryPcf), "In", http.StatusText(res.StatusCode), "")
	}

	smContext.SelectedPCFProfile = rep.NfInstances[0]

	// Create SMPolicyControl Client for this SM Context
	if service, ok := util.FindServiceByName(util.NFProfileDiscoveryServices(&smContext.SelectedPCFProfile), models.SERVICENAME_NPCF_SMPOLICYCONTROL); ok {
		cfg := Npcf_SMPolicyControl.NewConfiguration()
		serverConfig := &cfg.Servers[0]
		if apiRootVar, exists := serverConfig.Variables["apiRoot"]; exists {
			apiRootVar.DefaultValue = service.GetApiPrefix()
			serverConfig.Variables["apiRoot"] = apiRootVar
		}
		smContext.SMPolicyClient = Npcf_SMPolicyControl.NewAPIClient(cfg)
	}

	return nil
}

func (smContext *SMContext) GetNodeIDByLocalSEID(seid uint64) (nodeID NodeID) {
	for _, pfcpCtx := range smContext.PFCPContext {
		if pfcpCtx.LocalSEID == seid {
			nodeID = pfcpCtx.NodeID
		}
	}

	return
}

// RemoteSEIDByLocalSEID returns the SEID the user-plane function assigned to the session
// this element knows by seid.
//
// A PFCP message carries the SEID assigned by whoever receives it, so a request the UPF
// sends arrives under this element's own SEID and the response to it has to go back under
// the UPF's. Echoing the request's value instead -- which is what this element did, with a
// TODO admitting it -- is inert only for as long as no cause is sent that makes the peer
// read the field.
func (smContext *SMContext) RemoteSEIDByLocalSEID(seid uint64) (uint64, bool) {
	for _, pfcpCtx := range smContext.PFCPContext {
		if pfcpCtx.LocalSEID == seid {
			return pfcpCtx.RemoteSEID, true
		}
	}

	return 0, false
}

func (smContext *SMContext) AllocateLocalSEIDForDataPath(dataPath *DataPath) {
	logger.PduSessLog.Debugln("in AllocateLocalSEIDForDataPath")
	for curDataPathNode := dataPath.FirstDPNode; curDataPathNode != nil; curDataPathNode = curDataPathNode.Next() {
		NodeIDtoIP := curDataPathNode.UPF.NodeID.ResolveNodeIdToIp().String()
		logger.PduSessLog.Debugln("NodeIDtoIP:", NodeIDtoIP)
		if _, exist := smContext.PFCPContext[NodeIDtoIP]; !exist {
			allocatedSEID, err := AllocateLocalSEID()
			if err != nil {
				logger.PduSessLog.Errorf("allocateLocalSEID failed, %v", err)
			}
			smContext.PFCPContext[NodeIDtoIP] = &PFCPSessionContext{
				PDRs:      make(map[uint16]*PDR),
				NodeID:    curDataPathNode.UPF.NodeID,
				LocalSEID: allocatedSEID,
			}

			seidSMContextMap.Store(allocatedSEID, smContext)

			if factory.SmfConfig.Configuration.EnableDbStore {
				StoreSeidContextInDB(allocatedSEID, smContext)
				StoreRefToSeidInDB(allocatedSEID, smContext)
			}
		}
	}
}

func (smContext *SMContext) PutPDRtoPFCPSession(nodeID NodeID, pdrList map[string]*PDR) error {
	// TODO: Iterate over PDRS
	NodeIDtoIP := nodeID.ResolveNodeIdToIp().String()
	if pfcpSessCtx, exist := smContext.PFCPContext[NodeIDtoIP]; exist {
		for name, pdr := range pdrList {
			pfcpSessCtx.PDRs[pdrList[name].PDRID] = pdr
		}
	} else {
		return fmt.Errorf("error, can't find PFCPContext[%s] to put PDR(%v)", NodeIDtoIP, pdrList)
	}
	return nil
}

func (smContext *SMContext) RemovePDRfromPFCPSession(nodeID NodeID, pdr *PDR) {
	NodeIDtoIP := nodeID.ResolveNodeIdToIp().String()
	pfcpSessCtx := smContext.PFCPContext[NodeIDtoIP]
	delete(pfcpSessCtx.PDRs, pdr.PDRID)
}

func (smContext *SMContext) isAllowedPDUSessionType(requestedPDUSessionType uint8) error {
	dnnPDUSessionType := smContext.DnnConfiguration.PduSessionTypes
	if !dnnPDUSessionType.HasDefaultSessionType() {
		return fmt.Errorf("this SMContext[%s] has no subscription pdu session type info", smContext.Ref)
	}

	allowIPv4 := false
	allowIPv6 := false
	allowEthernet := false

	for _, allowedPDUSessionType := range smContext.DnnConfiguration.PduSessionTypes.AllowedSessionTypes {
		switch allowedPDUSessionType {
		case models.PDUSESSIONTYPE_IPV4:
			allowIPv4 = true
		case models.PDUSESSIONTYPE_IPV6:
			allowIPv6 = true
		case models.PDUSESSIONTYPE_IPV4_V6:
			allowIPv4 = true
			allowIPv6 = true
		case models.PDUSESSIONTYPE_ETHERNET:
			allowEthernet = true
		}
	}

	supportedPDUSessionType := SMF_Self().SupportedPDUSessionType
	switch supportedPDUSessionType {
	case "IPv4":
		if !allowIPv4 {
			return fmt.Errorf("no SupportedPDUSessionType[%q] in DNN[%s] configuration", supportedPDUSessionType, smContext.Dnn)
		}
	case "IPv6":
		if !allowIPv6 {
			return fmt.Errorf("no SupportedPDUSessionType[%q] in DNN[%s] configuration", supportedPDUSessionType, smContext.Dnn)
		}
	case "IPv4v6":
		if !allowIPv4 && !allowIPv6 {
			return fmt.Errorf("no SupportedPDUSessionType[%q] in DNN[%s] configuration", supportedPDUSessionType, smContext.Dnn)
		}
	case "Ethernet":
		if !allowEthernet {
			return fmt.Errorf("no SupportedPDUSessionType[%q] in DNN[%s] configuration", supportedPDUSessionType, smContext.Dnn)
		}
	}

	smContext.EstAcceptCause5gSMValue = 0
	switch nasConvert.PDUSessionTypeToModels(requestedPDUSessionType) {
	case models.PDUSESSIONTYPE_IPV4:
		if allowIPv4 {
			smContext.SelectedPDUSessionType = nasConvert.ModelsToPDUSessionType(models.PDUSESSIONTYPE_IPV4)
		} else {
			return fmt.Errorf("PduSessionType_IPV4 is not allowed in DNN[%s] configuration", smContext.Dnn)
		}
	case models.PDUSESSIONTYPE_IPV6:
		if allowIPv6 {
			smContext.SelectedPDUSessionType = nasConvert.ModelsToPDUSessionType(models.PDUSESSIONTYPE_IPV6)
		} else {
			return fmt.Errorf("PduSessionType_IPV6 is not allowed in DNN[%s] configuration", smContext.Dnn)
		}
	case models.PDUSESSIONTYPE_IPV4_V6:
		if allowIPv4 && allowIPv6 {
			smContext.SelectedPDUSessionType = nasConvert.ModelsToPDUSessionType(models.PDUSESSIONTYPE_IPV4_V6)
		} else if allowIPv4 {
			smContext.SelectedPDUSessionType = nasConvert.ModelsToPDUSessionType(models.PDUSESSIONTYPE_IPV4)
			smContext.EstAcceptCause5gSMValue = nasMessage.Cause5GSMPDUSessionTypeIPv4OnlyAllowed
		} else if allowIPv6 {
			smContext.SelectedPDUSessionType = nasConvert.ModelsToPDUSessionType(models.PDUSESSIONTYPE_IPV6)
			smContext.EstAcceptCause5gSMValue = nasMessage.Cause5GSMPDUSessionTypeIPv6OnlyAllowed
		} else {
			return fmt.Errorf("PduSessionType_IPV4_V6 is not allowed in DNN[%s] configuration", smContext.Dnn)
		}
	case models.PDUSESSIONTYPE_ETHERNET:
		if allowEthernet {
			smContext.SelectedPDUSessionType = nasConvert.ModelsToPDUSessionType(models.PDUSESSIONTYPE_ETHERNET)
		} else {
			return fmt.Errorf("PduSessionType_ETHERNET is not allowed in DNN[%s] configuration", smContext.Dnn)
		}
	case models.PDUSESSIONTYPE_UNSTRUCTURED:
		smContext.SelectedPDUSessionType = nasConvert.ModelsToPDUSessionType(models.PDUSESSIONTYPE_UNSTRUCTURED)
		return fmt.Errorf("unstructured PDU Session type")
	default:
		return fmt.Errorf("requested PDU Sesstion type[%d] is not supported", requestedPDUSessionType)
	}
	return nil
}

// SM Policy related operation

// SelectedSessionRule - return the SMF selected session rule for this SM Context
func (smContext *SMContext) SelectedSessionRule() *models.SessionRule {
	logger.CtxLog.Debugf("SelectedSessionRule len(smContext.SmPolicyUpdates): %v", len(smContext.SmPolicyUpdates))

	if len(smContext.SmPolicyUpdates) > 0 {
		policyUpdate := smContext.SmPolicyUpdates[0]
		if policyUpdate != nil {
			logger.CtxLog.Debugf("SelectedSessionRule smContext.SmPolicyUpdates[0]: %v", policyUpdate)
			if policyUpdate.SessRuleUpdate != nil {
				logger.CtxLog.Debugf("SelectedSessionRule smContext.SmPolicyUpdates[0].SessRuleUpdate: %v", policyUpdate.SessRuleUpdate)
				if policyUpdate.SessRuleUpdate.ActiveSessRule != nil {
					logger.CtxLog.Debugf("SelectedSessionRule smContext.SmPolicyUpdates[0].SessRuleUpdate.ActiveSessRule: %v", policyUpdate.SessRuleUpdate.ActiveSessRule)
					return policyUpdate.SessRuleUpdate.ActiveSessRule
				}
			}
		}
	}

	logger.CtxLog.Debugf("SelectedSessionRule smContext.SmPolicyData: %v", smContext.SmPolicyData)
	logger.CtxLog.Debugf("SelectedSessionRule smContext.SmPolicyData.SmCtxtSessionRules: %v", smContext.SmPolicyData.SmCtxtSessionRules)
	logger.CtxLog.Debugf("SelectedSessionRule smContext.SmPolicyData.SmCtxtSessionRules.ActiveRule: %v", smContext.SmPolicyData.SmCtxtSessionRules.ActiveRule)

	return smContext.SmPolicyData.SmCtxtSessionRules.ActiveRule
}

func (smContextState SMContextState) String() string {
	switch smContextState {
	case SmStateInit:
		return "SmStateInit"
	case SmStateActivePending:
		return "SmStateActivePending"
	case SmStateActive:
		return "SmStateActive"
	case SmStateInActivePending:
		return "SmStateInActivePending"
	case SmStateModify:
		return "SmStateModify"
	case SmStatePfcpCreatePending:
		return "SmStatePfcpCreatePending"
	case SmStatePfcpModify:
		return "SmStatePfcpModify"
	case SmStatePfcpRelease:
		return "SmStatePfcpRelease"
	case SmStateRelease:
		return "SmStateRelease"
	case SmStateN1N2TransferPending:
		return "SmStateN1N2TransferPending"

	default:
		return "Unknown State"
	}
}

func (smContext *SMContext) GeneratePDUSessionEstablishmentReject(cause string) *httpwrapper.Response {
	responseBody := models.NewPostSmContexts400Response()
	responseBody.SetJsonData(models.SmContextCreateError{
		Error: errors.ErrorType[cause],
	})
	httpResponse := &httpwrapper.Response{
		Header: nil,
		Status: int(*errors.ErrorType[cause].Status),
		Body:   responseBody,
	}

	if buf, err := BuildGSMPDUSessionEstablishmentReject(
		smContext,
		errors.ErrorCause[cause]); err != nil {
		return httpResponse
	} else {
		tmpFile, err := util.CreatePayloadTempFile(buf)
		if err != nil {
			logger.PduSessLog.Errorln(err)
		} else {
			body := httpResponse.Body.(*models.PostSmContexts400Response)
			body.SetBinaryDataN1SmMessage(tmpFile)
			jsonData := body.GetJsonData()
			jsonData.SetN1SmMsg(models.RefToBinaryData{ContentId: "n1SmMsg"})
			body.SetJsonData(jsonData)
		}
	}

	return httpResponse
}

// CommitSmPolicyDecision applies or discards the pending policy update, taking SMLock itself.
//
// Callers that already hold SMLock must use CommitSmPolicyDecisionLocked instead. SMLock is a
// plain mutex and is not reentrant, so calling this from under it deadlocks the session — and
// because the update path holds the lock with a defer, the session stays wedged and its HTTP
// handler never returns.
func (smContext *SMContext) CommitSmPolicyDecision(status bool) error {
	smContext.SMLock.Lock()
	defer smContext.SMLock.Unlock()
	return smContext.CommitSmPolicyDecisionLocked(status)
}

// CommitSmPolicyDecisionLocked is CommitSmPolicyDecision for a caller that already holds SMLock.
func (smContext *SMContext) CommitSmPolicyDecisionLocked(status bool) error {
	if len(smContext.SmPolicyUpdates) == 0 {
		// Nothing pending. Reachable whenever a message that commits or discards arrives without
		// a modification in flight — a retransmitted PDU SESSION MODIFICATION COMPLETE is the
		// ordinary case — and indexing here would take the SMF down.
		outcome := "discard"
		if status {
			outcome = "commit"
		}

		logger.CtxLog.Warnf("no pending SM policy update to %s", outcome)
		return nil
	}

	if status {
		err := qos.CommitSmPolicyDecision(&smContext.SmPolicyData, smContext.SmPolicyUpdates[0])
		if err != nil {
			logger.CtxLog.Errorf("failed to commit SM Policy Decision, %v", err)
		}
	}

	// Release 0th index update
	if len(smContext.SmPolicyUpdates) >= 1 {
		smContext.SmPolicyUpdates = smContext.SmPolicyUpdates[1:]
	}

	// Notify PCF of failure ?
	// TODO
	return nil
}

func (smContext *SMContext) getSmCtxtUpf() (name, ip string) {
	var upfName, upfIP string
	// Keyed on Tunnel/data-path presence rather than SMContextState: the state field already
	// reflects whichever side of the transition PublishSmCtxtInfo is called on, so gating on
	// SmStateActive here would drop the UPF the session is leaving on every disconnect event.
	// The default path is resolved by lookup rather than assuming pool key 1, since a tunnel
	// can exist with no data path yet (e.g. the no-available-path failure in
	// PDUSessionSMContextCreate), in which case there's nothing to report.
	if smContext.Tunnel == nil {
		// releaseTunnel already cleared the tunnel by the time RemoveSMContext publishes the
		// terminal disconnect event; fall back to the UPF this last resolved to rather than
		// reporting none.
		return smContext.lastUpfName, smContext.lastUpfIP
	}
	defaultPath := smContext.Tunnel.DataPathPool.GetDefaultPath()
	if defaultPath == nil || defaultPath.FirstDPNode == nil || defaultPath.FirstDPNode.UPF == nil {
		return smContext.lastUpfName, smContext.lastUpfIP
	}
	upf := defaultPath.FirstDPNode.UPF

	// Set UPF FQDN name if provided else IP-address
	if upf.NodeID.NodeIdType == NodeIdTypeFqdn {
		upfName = string(upf.NodeID.NodeIdValue)
		upfName = strings.Split(upfName, ".")[0]
		// Cache-only lookup: this runs under SMLock on every state transition, so a
		// synchronous DNS resolution here (as ResolveNodeIdToIp would do on a cache miss)
		// could block release/modify/create request goroutines on a slow/unresponsive resolver.
		if ip := upf.NodeID.ResolveNodeIdToIpCached(); ip != nil {
			upfIP = ip.String()
		}
	} else {
		upfName = upf.GetUPFIP()
		upfIP = upf.GetUPFIP()
	}
	if upfIP == "" {
		// A transient FQDN cache miss with the tunnel still present (e.g. HandlePduSessionContextReplacement
		// calls RemoveSMContext, which publishes the terminal event, before releaseTunnel runs): fall
		// back to the last resolved UPF instead of reporting none for this event.
		return smContext.lastUpfName, smContext.lastUpfIP
	}
	// Not updated on a miss (handled above): the snapshot must only ever hold a fully resolved UPF.
	smContext.lastUpfName, smContext.lastUpfIP = upfName, upfIP
	return upfName, upfIP
}

// Collect Ctxt info and publish on Kafka stream
func (smContext *SMContext) PublishSmCtxtInfo() {
	if !*factory.SmfConfig.Configuration.KafkaInfo.EnableKafka {
		return
	}
	var op mi.SubscriberOp
	kafkaSmCtxt := mi.CoreSubscriber{}

	// Populate kafka sm ctxt struct
	kafkaSmCtxt.Imsi = smContext.Supi
	if smContext.PDUAddress != nil && smContext.PDUAddress.Ip != nil {
		kafkaSmCtxt.IPAddress = smContext.PDUAddress.Ip.String()
	}
	kafkaSmCtxt.SmfSubState, op = mapPduSessStateToMetricStateAndOp(smContext.SMContextState)
	kafkaSmCtxt.SmfId = smContext.Ref
	kafkaSmCtxt.Slice = "sd:" + smContext.Snssai.GetSd() + " sst:" + strconv.Itoa(int(smContext.Snssai.GetSst()))
	kafkaSmCtxt.Dnn = smContext.Dnn
	kafkaSmCtxt.UpfName, kafkaSmCtxt.UpfAddr = smContext.getSmCtxtUpf()
	kafkaSmCtxt.SmfIp = SMF_Self().PodIp

	// Send to stream
	err := publishPduSessEvent(kafkaSmCtxt, op)
	if err != nil {
		smContext.SubCtxLog.Errorf("failed to publish sm ctxt info on kafka stream: %v", err)
	}
}

// publishPduSessEvent is a seam over metrics.GetWriter().PublishPduSessEvent so tests can
// capture published Kafka events without a real broker.
var publishPduSessEvent = func(ctxt mi.CoreSubscriber, op mi.SubscriberOp) error {
	return metrics.GetWriter().PublishPduSessEvent(ctxt, op)
}

func mapPduSessStateToMetricStateAndOp(state SMContextState) (string, mi.SubscriberOp) {
	switch state {
	case SmStateInit:
		// Never the terminal transition: teardown paths (a PFCP send failure while
		// SmStatePfcpCreatePending, the UE-driven release complete, the duplicate-PDU-ID
		// path) all call ChangeState(SmStateInit) immediately before RemoveSMContext enters
		// SmStateRelease, which is what actually removes the session and reports Del.
		// Reporting Del here too would double it; report the in-progress Mod instead.
		return IDLE, mi.SubsOpMod
	case SmStateActivePending:
		return IDLE, mi.SubsOpMod
	case SmStateActive:
		return CONNECTED, mi.SubsOpMod
	case SmStateInActivePending:
		return IDLE, mi.SubsOpMod
	case SmStateModify:
		return CONNECTED, mi.SubsOpMod
	case SmStatePfcpCreatePending:
		// Only reachable from SmStateInit (a brand-new PDU session waiting on its first
		// PFCP session establishment), so this is always the subscriber's initial create.
		return IDLE, mi.SubsOpAdd
	case SmStatePfcpModify:
		return CONNECTED, mi.SubsOpMod
	case SmStatePfcpRelease:
		// Releasing the PFCP session is the start of teardown, not its completion: this can
		// still roll back to SmStateActive (PFCP release timeout/failure) or continue on to
		// SmStateInActivePending without the session ever being removed. Reporting a Del here
		// as well as on the SmStateRelease transition that follows would tell downstream
		// consumers about a deletion that may not happen, and doubles the one that does.
		// SmStateRelease - reached only via RemoveSMContext, which also deletes the pool
		// entry - is the sole terminal transition that reports Del.
		return IDLE, mi.SubsOpMod
	case SmStateRelease:
		return DISCONNECTED, mi.SubsOpDel
	case SmStateN1N2TransferPending:
		return IDLE, mi.SubsOpMod
	default:
		return "unknown", mi.SubsOpDel
	}
}

// StopT3591 stops the modification retransmission timer if one is running.
//
// The caller must hold SMLock. NwModificationPending and T3591 are session state like any other
// here, and every current call site is already under it: the N1 and N2 update handlers run under
// the lock HandlePDUSessionSMContextUpdate takes, and startT3591Locked is documented as requiring
// it. There is deliberately no unlocked variant - SMLock is not reentrant, so one taken here would
// wedge the session for its callers.
//
// It is idempotent, and safe to call when no modification is in flight, because both happen: an
// acknowledgement can arrive after the timer has already abandoned the procedure, and a UE can
// retransmit that acknowledgement.
func (smContext *SMContext) StopT3591() {
	// Cleared before the nil check, not after: the network's procedure is pending from the moment
	// it commits, which is a PFCP round trip before T3591 is armed. A terminus reached inside that
	// window still has to settle the session.
	smContext.NwModificationPending = false
	if smContext.T3591 == nil {
		return
	}
	smContext.T3591.Stop()
	smContext.T3591 = nil
}
