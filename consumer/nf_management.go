// SPDX-FileCopyrightText: 2022-present Intel Corporation
// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package consumer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/mohae/deepcopy"
	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/Nnrf_NFDiscovery"
	"github.com/omec-project/openapi/v2/Nnrf_NFManagement"
	"github.com/omec-project/openapi/v2/Nudm_SDM"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/openapi/v2/nfConfigApi"
	nrfCache "github.com/omec-project/openapi/v2/nrfcache"
	smfContext "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/smf/metrics"
	"github.com/omec-project/smf/msgtypes/svcmsgtypes"
	"github.com/omec-project/smf/util"
)

var newNrfNFManagementHTTPClient = func() *http.Client {
	return nil
}

const podIPPlaceholder = "POD_IP"

// n1n2TransferTimeout is the HTTP timeout for a single N1N2MessageTransfer attempt.
// Kept short so that retries with AMF re-discovery can happen within the UE's T3580 window.
const n1n2TransferTimeout = 5 * time.Second

func normalizeAdvertisedSmfHost(nfProfile *models.NFProfile) {
	if nfProfile == nil {
		return
	}
	advertisedHost := ""
	if factory.SmfConfig.Configuration != nil && factory.SmfConfig.Configuration.Sbi != nil {
		configuredRegisterIPv4 := factory.SmfConfig.Configuration.Sbi.RegisterIPv4
		if configuredRegisterIPv4 != "" && configuredRegisterIPv4 != podIPPlaceholder && net.ParseIP(configuredRegisterIPv4) == nil {
			advertisedHost = configuredRegisterIPv4
		} else if configuredRegisterIPv4 == podIPPlaceholder && factory.SmfConfig.Configuration.SmfName != "" {
			advertisedHost = strings.ToLower(factory.SmfConfig.Configuration.SmfName)
		}
	}
	if advertisedHost == "" {
		return
	}
	for index := range nfProfile.NfServices {
		service := &nfProfile.NfServices[index]
		service.ApiPrefix = openapi.PtrString(fmt.Sprintf("%s://%s:%d", service.Scheme, advertisedHost, smfContext.SMF_Self().SBIPort))
		for versionIndex := range service.Versions {
			service.Versions[versionIndex].ApiFullVersion = fmt.Sprintf("%s://%s:%d/%s/v1", service.Scheme, advertisedHost, smfContext.SMF_Self().SBIPort, service.ServiceName)
		}
	}
}

func newNrfNFManagementClient(nrfURI string) *Nnrf_NFManagement.APIClient {
	cfg := Nnrf_NFManagement.NewConfiguration()
	serverConfig := &cfg.Servers[0]
	if apiRootVar, exists := serverConfig.Variables["apiRoot"]; exists {
		apiRootVar.DefaultValue = nrfURI
		serverConfig.Variables["apiRoot"] = apiRootVar
	}
	if httpClient := newNrfNFManagementHTTPClient(); httpClient != nil {
		cfg.HTTPClient = httpClient
	}
	return Nnrf_NFManagement.NewAPIClient(cfg)
}

func newNrfNFDiscoveryClient(nrfURI string) *Nnrf_NFDiscovery.APIClient {
	cfg := Nnrf_NFDiscovery.NewConfiguration()
	serverConfig := &cfg.Servers[0]
	if apiRootVar, exists := serverConfig.Variables["apiRoot"]; exists {
		apiRootVar.DefaultValue = nrfURI
		serverConfig.Variables["apiRoot"] = apiRootVar
	}
	return Nnrf_NFDiscovery.NewAPIClient(cfg)
}

func getNfProfile(smfCtx *smfContext.SMFContext, sessionCfgs []nfConfigApi.SessionManagement) (models.NFProfile, error) {
	if len(sessionCfgs) == 0 {
		return models.NFProfile{}, openapi.ReportError("session management config is empty")
	}
	if smfCtx == nil {
		return models.NFProfile{}, openapi.ReportError("SMF context is nil")
	}

	snssais := buildSNssais(sessionCfgs)
	plmnList := buildPlmnList(sessionCfgs)
	smfInfo := buildSmfInfo(sessionCfgs)
	serviceNames := []string{"nsmf-pdusession"}
	if factory.SmfConfig.Configuration != nil && len(factory.SmfConfig.Configuration.ServiceNameList) > 0 {
		serviceNames = factory.SmfConfig.Configuration.ServiceNameList
	}
	advertisedRegisterIPv4 := smfCtx.RegisterIPv4
	if factory.SmfConfig.Configuration != nil && factory.SmfConfig.Configuration.Sbi != nil {
		configuredRegisterIPv4 := factory.SmfConfig.Configuration.Sbi.RegisterIPv4
		if configuredRegisterIPv4 != "" && configuredRegisterIPv4 != podIPPlaceholder && net.ParseIP(configuredRegisterIPv4) == nil {
			advertisedRegisterIPv4 = configuredRegisterIPv4
		} else if configuredRegisterIPv4 == podIPPlaceholder && factory.SmfConfig.Configuration.SmfName != "" {
			advertisedRegisterIPv4 = strings.ToLower(factory.SmfConfig.Configuration.SmfName)
		}
	}
	nfServices := make([]models.NFService, 0, len(serviceNames))
	for _, serviceName := range serviceNames {
		nfServices = append(nfServices, models.NFService{
			ServiceInstanceId: smfCtx.NfInstanceID + "-" + serviceName,
			ServiceName:       models.ServiceName(serviceName),
			Scheme:            smfCtx.URIScheme,
			NfServiceStatus:   models.NFSERVICESTATUS_REGISTERED,
			ApiPrefix:         openapi.PtrString(fmt.Sprintf("%s://%s:%d", smfCtx.URIScheme, advertisedRegisterIPv4, smfCtx.SBIPort)),
			Versions: []models.NFServiceVersion{{
				ApiVersionInUri: "v1",
				ApiFullVersion:  fmt.Sprintf("%s://%s:%d/nsmf-pdusession/v1", smfCtx.URIScheme, advertisedRegisterIPv4, smfCtx.SBIPort),
			}},
			AllowedPlmns: plmnList,
		})
	}

	nfProf := models.NFProfile{
		NfInstanceId:  smfCtx.NfInstanceID,
		NfType:        models.NFTYPE_SMF,
		NfStatus:      models.NFSTATUS_REGISTERED,
		Ipv4Addresses: []string{advertisedRegisterIPv4},
		NfServices:    nfServices,
		SmfInfo:       &smfInfo,
		SNssais:       snssais,
		PlmnList:      plmnList,
		AllowedPlmns:  plmnList,
	}
	logger.ConsumerLog.Debugln("NF Profile is created using session management config")
	return nfProf, nil
}

func buildSmfInfo(sessionCfgs []nfConfigApi.SessionManagement) models.SmfInfo {
	snssaiSmfInfoList := []models.SnssaiSmfInfoItem{}
	for _, sessionCfg := range sessionCfgs {
		snssai := models.Snssai{
			Sst: sessionCfg.Snssai.GetSst(),
		}
		if sd, ok := sessionCfg.Snssai.GetSdOk(); ok {
			snssai.Sd = sd
		}
		item := models.SnssaiSmfInfoItem{
			SNssai: snssai,
		}
		dnnList := []models.DnnSmfInfoItem{}
		for _, ipdomain := range sessionCfg.IpDomain {
			if ipdomain.DnnName != "" {
				dnnList = append(dnnList, models.DnnSmfInfoItem{Dnn: ipdomain.DnnName})
			}
		}

		if len(dnnList) > 0 {
			item.DnnSmfInfoList = dnnList
		}
		snssaiSmfInfoList = append(snssaiSmfInfoList, item)
	}

	return models.SmfInfo{SNssaiSmfInfoList: snssaiSmfInfoList}
}

func buildPlmnList(sessionCfgs []nfConfigApi.SessionManagement) []models.PlmnId {
	plmns := []models.PlmnId{}
	for _, sessionCfg := range sessionCfgs {
		plmns = append(plmns, models.PlmnId{
			Mcc: sessionCfg.PlmnId.GetMcc(),
			Mnc: sessionCfg.PlmnId.GetMnc(),
		})
	}
	return plmns
}

func buildSNssais(sessionCfgs []nfConfigApi.SessionManagement) []models.Snssai {
	snssais := []models.Snssai{}
	for _, sessionCfg := range sessionCfgs {
		snssai := models.Snssai{
			Sst: sessionCfg.Snssai.GetSst(),
		}
		if sd, ok := sessionCfg.Snssai.GetSdOk(); ok {
			snssai.Sd = sd
		}
		snssais = append(snssais, snssai)
	}
	return snssais
}

var SendRegisterNFInstance = func(sessionManagementConfig []nfConfigApi.SessionManagement) (prof *models.NFProfile, resourceNrfUri string, err error) {
	self := smfContext.SMF_Self()
	nfProfile, err := getNfProfile(self, sessionManagementConfig)
	if err != nil {
		return &models.NFProfile{}, "", err
	}
	normalizeAdvertisedSmfHost(&nfProfile)
	logger.ConsumerLog.Debugf("sending registration request with NFProfile %+v", nfProfile)
	client := newNrfNFManagementClient(self.NrfUri)
	metrics.IncrementSvcNrfMsgStats(self.NfInstanceID, string(svcmsgtypes.NnrfNFRegister), "Out", "", "")

	apiRegisterNFInstanceRequest := client.NFInstanceIDDocumentAPI.RegisterNFInstance(context.TODO(), nfProfile.NfInstanceId)
	apiRegisterNFInstanceRequest = apiRegisterNFInstanceRequest.NFProfile(nfProfile)
	receivedNfProfile, res, err := client.NFInstanceIDDocumentAPI.RegisterNFInstanceExecute(apiRegisterNFInstanceRequest)
	if err != nil {
		metrics.IncrementSvcNrfMsgStats(self.NfInstanceID, string(svcmsgtypes.NnrfNFRegister), "In", "Failure", err.Error())
		return &models.NFProfile{}, "", err
	}
	if res == nil {
		metrics.IncrementSvcNrfMsgStats(self.NfInstanceID, string(svcmsgtypes.NnrfNFRegister), "In", "Failure", "NoResponse")
		return &models.NFProfile{}, "", openapi.ReportError("no response from server")
	}

	metrics.IncrementSvcNrfMsgStats(self.NfInstanceID, string(svcmsgtypes.NnrfNFRegister), "In", http.StatusText(res.StatusCode), "")

	switch res.StatusCode {
	case http.StatusOK:
		logger.ConsumerLog.Debugln("SMF NF profile updated with complete replacement")
		return receivedNfProfile, "", nil
	case http.StatusCreated:
		resourceUri := res.Header.Get("Location")
		resourceNrfUri = resourceUri[:strings.Index(resourceUri, "/nnrf-nfm/")]
		retrieveNfInstanceId := resourceUri[strings.LastIndex(resourceUri, "/")+1:]
		self.NfInstanceID = retrieveNfInstanceId
		logger.ConsumerLog.Debugln("SMF NF profile registered to the NRF")
		return receivedNfProfile, resourceNrfUri, nil
	default:
		return receivedNfProfile, "", openapi.ReportError("unexpected status code returned by the NRF %d", res.StatusCode)
	}
}

var SendDeregisterNFInstance = func() error {
	logger.ConsumerLog.Infoln("send Deregister NFInstance")

	smfSelf := smfContext.SMF_Self()
	nfId := smfSelf.NfInstanceID

	client := newNrfNFManagementClient(smfSelf.NrfUri)

	metrics.IncrementSvcNrfMsgStats(nfId, string(svcmsgtypes.NnrfNFInstanceDeRegister), "Out", "", "")
	apiDeregisterNFInstanceRequest := client.NFInstanceIDDocumentAPI.DeregisterNFInstance(context.Background(), nfId)
	res, err := client.NFInstanceIDDocumentAPI.DeregisterNFInstanceExecute(apiDeregisterNFInstanceRequest)
	if err != nil {
		if res != nil {
			defer res.Body.Close()
			metrics.IncrementSvcNrfMsgStats(nfId, string(svcmsgtypes.NnrfNFInstanceDeRegister), "In", http.StatusText(res.StatusCode), err.Error())
		} else {
			metrics.IncrementSvcNrfMsgStats(nfId, string(svcmsgtypes.NnrfNFInstanceDeRegister), "In", "Failure", "NoResponse")
		}
		logger.ConsumerLog.Warnf("deregister failed: %v", err)
		return err
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusNoContent {
		metrics.IncrementSvcNrfMsgStats(nfId, string(svcmsgtypes.NnrfNFInstanceDeRegister), "In", http.StatusText(res.StatusCode), "")
		logger.ConsumerLog.Infof("Deregister successful: %d", res.StatusCode)
		return nil
	}

	metrics.IncrementSvcNrfMsgStats(nfId, string(svcmsgtypes.NnrfNFInstanceDeRegister), "In", http.StatusText(res.StatusCode), "UnexpectedCode")
	logger.ConsumerLog.Warnf("unexpected response code during deregister: %d", res.StatusCode)
	return openapi.ReportError("unexpected response code: %d", res.StatusCode)
}

var SendUpdateNFInstance = func(patchItem []models.PatchItem) (receivedNfProfile *models.NFProfile, problemDetails *models.ProblemDetails, err error) {
	logger.ConsumerLog.Debugln("send update NFInstance")

	smfSelf := smfContext.SMF_Self()
	client := newNrfNFManagementClient(smfSelf.NrfUri)

	var res *http.Response
	apiUpdateNFInstanceRequest := client.NFInstanceIDDocumentAPI.UpdateNFInstance(context.Background(), smfSelf.NfInstanceID)
	apiUpdateNFInstanceRequest = apiUpdateNFInstanceRequest.PatchItem(patchItem)
	receivedNfProfile, res, err = client.NFInstanceIDDocumentAPI.UpdateNFInstanceExecute(apiUpdateNFInstanceRequest)
	if err != nil {
		if problem, handledErr := util.HandleOpenAPIError(err); problem != nil {
			return &models.NFProfile{}, problem, nil
		} else if handledErr != nil {
			return &models.NFProfile{}, nil, handledErr
		}
	}

	if res == nil {
		return &models.NFProfile{}, nil, openapi.ReportError("no response from server")
	}
	if res.StatusCode == http.StatusOK || res.StatusCode == http.StatusNoContent {
		if receivedNfProfile == nil {
			receivedNfProfile = &models.NFProfile{}
		}
		return receivedNfProfile, nil, nil
	}
	return &models.NFProfile{}, nil, openapi.ReportError("unexpected response code")
}

func getSvcMsgType(nfType models.NFType) svcmsgtypes.SmfMsgType {
	var svcMsgType svcmsgtypes.SmfMsgType

	switch nfType {
	case models.NFTYPE_AMF:
		svcMsgType = svcmsgtypes.NnrfNFDiscoveryAmf
	case models.NFTYPE_PCF:
		svcMsgType = svcmsgtypes.NnrfNFDiscoveryPcf
	case models.NFTYPE_UDM:
		svcMsgType = svcmsgtypes.NnrfNFDiscoveryUdm
	}
	return svcMsgType
}

func SendNrfForNfInstance(ctx context.Context, nrfUri string, targetNfType, requestNfType models.NFType,
	apiSearchNFInstancesRequest Nnrf_NFDiscovery.ApiSearchNFInstancesRequest,
) (*models.SearchResult, error) {
	client := newNrfNFDiscoveryClient(nrfUri)
	if apiSearchNFInstancesRequest.ApiService == nil {
		apiSearchNFInstancesRequest = client.NFInstancesStoreAPI.SearchNFInstances(ctx)
	}
	apiSearchNFInstancesRequest = apiSearchNFInstancesRequest.TargetNfType(targetNfType)
	apiSearchNFInstancesRequest = apiSearchNFInstancesRequest.RequesterNfType(requestNfType)
	result, httpResp, localErr := client.NFInstancesStoreAPI.SearchNFInstancesExecute(apiSearchNFInstancesRequest)

	svcMsgType := getSvcMsgType(targetNfType)

	metrics.IncrementSvcNrfMsgStats(smfContext.SMF_Self().NfInstanceID, string(svcMsgType), "Out", "", "")

	if localErr == nil {
		if result == nil {
			metrics.IncrementSvcNrfMsgStats(smfContext.SMF_Self().NfInstanceID, string(svcMsgType), "In", "Failure", "NilResult")
			return nil, openapi.ReportError("SearchNFInstances returned nil result")
		}
		if result.NfInstances == nil {
			if status := httpResp.StatusCode; status != http.StatusOK {
				logger.ConsumerLog.Warnln("handler returned wrong status code", status)
			}

			logger.ConsumerLog.Warnln("NfInstances is nil")
			metrics.IncrementSvcNrfMsgStats(smfContext.SMF_Self().NfInstanceID, string(svcMsgType), "In", http.StatusText(httpResp.StatusCode), "NilInstance")
			return result, openapi.ReportError("NfInstances is nil")
		}

		metrics.IncrementSvcNrfMsgStats(smfContext.SMF_Self().NfInstanceID, string(svcMsgType), "In", http.StatusText(httpResp.StatusCode), "")
	} else if httpResp != nil {
		defer func() {
			if resCloseErr := httpResp.Body.Close(); resCloseErr != nil {
				logger.ConsumerLog.Errorf("SearchNFInstances response body cannot close: %+v", resCloseErr)
			}
		}()

		logger.ConsumerLog.Warnln("handler returned wrong status code", httpResp.Status)
		if httpResp.Status != localErr.Error() {
			metrics.IncrementSvcNrfMsgStats(smfContext.SMF_Self().NfInstanceID, string(svcMsgType), "In", http.StatusText(httpResp.StatusCode), httpResp.Status)
		} else {
			metrics.IncrementSvcNrfMsgStats(smfContext.SMF_Self().NfInstanceID, string(svcMsgType), "In", http.StatusText(httpResp.StatusCode), localErr.Error())
		}
	} else {
		metrics.IncrementSvcNrfMsgStats(smfContext.SMF_Self().NfInstanceID, string(svcMsgType), "In", "Failure", "NoResponse")
	}

	if result == nil {
		return nil, localErr
	}

	smfSelf := smfContext.SMF_Self()

	for _, nfProfile := range result.NfInstances {
		if _, ok := smfSelf.NfStatusSubscriptions.Load(nfProfile.NfInstanceId); !ok {
			nrfSubscriptionData := models.SubscriptionData{
				NfStatusNotificationUri: fmt.Sprintf("%s://%s:%d/nsmf-callback/nf-status-notify",
					smfSelf.URIScheme,
					smfSelf.RegisterIPv4,
					smfSelf.SBIPort),
				SubscrCond: &models.SubscrCond{NfInstanceIdCond: &models.NfInstanceIdCond{NfInstanceId: openapi.PtrString(nfProfile.NfInstanceId)}},
				ReqNfType:  requestNfType.Ptr(),
			}
			logger.ConsumerLog.Debugf("Preparing NRF Subscription to %s with payload: %+v", nrfUri, nrfSubscriptionData)
			nrfSubData, problemDetails, err := SendCreateSubscription(nrfUri, nrfSubscriptionData)
			if problemDetails != nil {
				logger.ConsumerLog.Errorf("SendCreateSubscription to NRF, Problem[%+v]", problemDetails)
			} else if err != nil {
				logger.ConsumerLog.Errorf("SendCreateSubscription error[%+v]", err)
			} else if nrfSubData == nil {
				logger.ConsumerLog.Warnln("SendCreateSubscription returned nil subscription data")
				continue
			}
			smfSelf.NfStatusSubscriptions.Store(nfProfile.GetNfInstanceId(), nrfSubData.GetSubscriptionId())
		}
	}
	return result, localErr
}

func SendNFDiscoveryUDM() (*models.ProblemDetails, error) {
	localVarOptionals := Nnrf_NFDiscovery.ApiSearchNFInstancesRequest{}

	var result *models.SearchResult
	var localErr error
	ctx := context.Background()

	if smfContext.SMF_Self().EnableNrfCaching {
		result, localErr = nrfCache.SearchNFInstances(ctx, smfContext.SMF_Self().NrfUri, models.NFTYPE_UDM, models.NFTYPE_SMF, localVarOptionals)
		if localErr != nil {
			logger.ConsumerLog.Warnf("UDM discovery via NRF cache failed: %v, retrying direct NRF query", localErr)
			result, localErr = SendNrfForNfInstance(ctx, smfContext.SMF_Self().NrfUri, models.NFTYPE_UDM, models.NFTYPE_SMF, localVarOptionals)
		} else if result == nil || len(result.NfInstances) == 0 {
			logger.ConsumerLog.Warnln("UDM discovery via NRF cache returned no instances, retrying direct NRF query")
			result, localErr = SendNrfForNfInstance(ctx, smfContext.SMF_Self().NrfUri, models.NFTYPE_UDM, models.NFTYPE_SMF, localVarOptionals)
		}
	} else {
		result, localErr = SendNrfForNfInstance(ctx, smfContext.SMF_Self().NrfUri, models.NFTYPE_UDM, models.NFTYPE_SMF, localVarOptionals)
	}

	if localErr == nil {
		if result == nil || len(result.NfInstances) == 0 {
			return nil, openapi.ReportError("UDM discovery returned no NF instances")
		}
		smfContext.SMF_Self().UDMProfile = result.NfInstances[0]

		for _, service := range smfContext.SMF_Self().UDMProfile.NfServices {
			if service.ServiceName == models.SERVICENAME_NUDM_SDM {
				SDMConf := Nudm_SDM.NewConfiguration()
				serverConfig := &SDMConf.Servers[0]
				if apiRootVar, exists := serverConfig.Variables["apiRoot"]; exists {
					apiRootVar.DefaultValue = service.GetApiPrefix()
					serverConfig.Variables["apiRoot"] = apiRootVar
				}
				smfContext.SMF_Self().SubscriberDataManagementClient = Nudm_SDM.NewAPIClient(SDMConf)
			}
		}

		if smfContext.SMF_Self().SubscriberDataManagementClient == nil {
			logger.ConsumerLog.Warnln("sdm client failed")
		}
	} else {
		if problem, handledErr := util.HandleOpenAPIError(localErr); problem != nil {
			return problem, nil
		} else if handledErr != nil && handledErr != localErr {
			return nil, handledErr
		}

		return nil, localErr
	}
	return nil, nil
}

func SendNFDiscoveryServingAMF(smContext *smfContext.SMContext) (*models.ProblemDetails, error) {
	localVarOptionals := Nnrf_NFDiscovery.ApiSearchNFInstancesRequest{}

	localVarOptionals = localVarOptionals.TargetNfInstanceId(smContext.ServingNfId)

	var result *models.SearchResult
	var localErr error
	ctx := context.Background()
	if smfContext.SMF_Self().EnableNrfCaching {
		result, localErr = nrfCache.SearchNFInstances(ctx, smfContext.SMF_Self().NrfUri, models.NFTYPE_AMF, models.NFTYPE_SMF, localVarOptionals)
	} else {
		result, localErr = SendNrfForNfInstance(ctx, smfContext.SMF_Self().NrfUri, models.NFTYPE_AMF, models.NFTYPE_SMF, localVarOptionals)
	}

	if localErr == nil {
		if result.NfInstances == nil {
			return nil, openapi.ReportError("NfInstances is nil")
		}
		smContext.SubConsumerLog.Info("send NF Discovery Serving AMF Successful")
		smContext.AMFProfile = deepcopy.Copy(result.NfInstances[0]).(models.NFProfileDiscovery)
	} else {
		if problem, handledErr := util.HandleOpenAPIError(localErr); problem != nil {
			return problem, nil
		} else if handledErr != nil && handledErr != localErr {
			return nil, handledErr
		}

		return nil, localErr
	}
	return nil, nil
}

// SendN1N2TransferWithRediscovery sends an N1N2MessageTransfer request using the
// SMContext's CommunicationClient. If the request fails (including timeout), it
// queries NRF directly (bypassing the cache) and tries every other AMF candidate
// until one succeeds. This handles the case where NRF has multiple stale
// registrations left behind by prior AMF pod restarts.
func SendN1N2TransferWithRediscovery(ctx context.Context, smContext *smfContext.SMContext,
	n1n2Request *models.N1N2MessageTransferRequest,
) (*models.N1N2MessageTransferRspData, error) {
	// Re-discovery mutates AMFProfile/ServingNfId/CommunicationClient while trying
	// candidates. Snapshot them so a failed or aborted re-discovery leaves the session
	// pointing at its original serving AMF rather than the last (failed) candidate —
	// otherwise ServingNfId would be corrupted for later targeted discovery. Restored
	// unless a transfer succeeds (committed).
	origProfile := smContext.AMFProfile
	origServingNfId := smContext.ServingNfId
	origClient := smContext.CommunicationClient
	committed := false
	defer func() {
		if !committed {
			smContext.AMFProfile = origProfile
			smContext.ServingNfId = origServingNfId
			smContext.CommunicationClient = origClient
		}
	}()

	if smContext.CommunicationClient == nil {
		// Client not built yet (e.g. SMContext recovered from DB). Prefer rebuilding
		// from the session's existing AMFProfile so we don't needlessly switch AMFs;
		// only seed from NRF if that still leaves the client nil.
		smContext.RebuildCommunicationClient()
		if smContext.CommunicationClient == nil {
			if err := selectAmfFromNrf(ctx, smContext); err != nil {
				return nil, fmt.Errorf("AMF discovery failed: %w", err)
			}
		}
	}

	// First attempt with the currently-selected AMF
	rspData, err := tryN1N2Transfer(ctx, smContext, n1n2Request)
	if err == nil {
		committed = true
		return rspData, nil
	}
	// Only re-discover on transport-level failures (no HTTP response). An HTTP error
	// from a reachable AMF, or a cancelled caller context, must not trigger retries
	// against other AMFs (would risk duplicate N1/N2 delivery / ignore cancellation).
	if !shouldRediscoverAMF(ctx, err) {
		return rspData, err
	}
	smContext.SubPduSessLog.Warnf("N1N2Transfer failed (%v), attempting AMF re-discovery", err)

	// First attempt failed — fetch all AMF candidates from NRF (bypassing cache)
	// and try each, rebuilding the client from fresh NRF data. Candidates with a
	// different NfInstanceId are tried first (handles the AMF-restarted-with-a-new-
	// NfInstanceId case, where the failed id is a stale/dead entry); the candidate
	// with the same NfInstanceId as the one that just failed is tried last, since
	// its NRF profile may carry an updated ApiPrefix (AMF re-registered in place
	// with the same id but a new endpoint).
	candidates, discErr := fetchAmfCandidates(ctx)
	if discErr != nil {
		return nil, fmt.Errorf("N1N2Transfer failed and AMF re-discovery failed: %w", errors.Join(err, discErr))
	}

	attempted := 0
	for _, candidate := range orderAmfCandidates(candidates, smContext.ServingNfId) {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("N1N2Transfer aborted during AMF re-discovery: %w", ctx.Err())
		}
		if useErr := useAmfProfile(smContext, candidate); useErr != nil {
			smContext.SubPduSessLog.Warnf("AMF candidate %s unusable: %v", candidate.GetNfInstanceId(), useErr)
			continue
		}
		attempted++
		smContext.SubPduSessLog.Infof("AMF re-discovery retry %d: trying NfInstanceId %s", attempted, candidate.GetNfInstanceId())
		rspData, err = tryN1N2Transfer(ctx, smContext, n1n2Request)
		if err == nil {
			smContext.SubPduSessLog.Infof("AMF re-discovery succeeded on attempt %d with NfInstanceId %s", attempted, candidate.GetNfInstanceId())
			committed = true
			return rspData, nil
		}
		smContext.SubPduSessLog.Warnf("AMF re-discovery retry %d failed: %v", attempted, err)
	}

	if attempted == 0 {
		return nil, fmt.Errorf("N1N2Transfer failed (%w) and no alternative AMF candidates available", err)
	}
	return nil, fmt.Errorf("N1N2Transfer failed after %d AMF candidates; last error: %w", attempted, err)
}

// shouldRediscoverAMF reports whether an N1N2MessageTransfer error warrants AMF
// re-discovery and retry. Only transport-level failures (connection refused, TLS,
// or our own per-attempt timeout — i.e. no HTTP response was received) qualify.
// A cancelled/expired caller context, or an HTTP error returned by a reachable AMF
// (surfaced as openapi.GenericOpenAPIError), must NOT trigger retries against other
// AMFs: that would risk duplicate N1/N2 delivery and ignore the caller's intent.
func shouldRediscoverAMF(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return false // caller cancelled or deadline exceeded
	}
	// The generated client returns *openapi.GenericOpenAPIError; also check the value
	// form defensively in case a code path returns it by value.
	var apiErrPtr *openapi.GenericOpenAPIError
	var apiErrVal openapi.GenericOpenAPIError
	if errors.As(err, &apiErrPtr) || errors.As(err, &apiErrVal) {
		return false // the AMF responded with an HTTP error — it is reachable
	}
	return true
}

// tryN1N2Transfer makes a single N1N2MessageTransfer call with a short timeout.
func tryN1N2Transfer(ctx context.Context, smContext *smfContext.SMContext,
	n1n2Request *models.N1N2MessageTransferRequest,
) (*models.N1N2MessageTransferRspData, error) {
	tryCtx, cancel := context.WithTimeout(ctx, n1n2TransferTimeout)
	defer cancel()
	apiReq := smContext.CommunicationClient.
		N1N2MessageCollectionCollectionAPI.
		N1N2MessageTransfer(tryCtx, smContext.Supi).
		N1N2MessageTransferReqData(n1n2Request.GetJsonData())
	if binaryDataN1Message := n1n2Request.GetBinaryDataN1Message(); binaryDataN1Message != nil {
		apiReq = apiReq.BinaryDataN1Message(binaryDataN1Message)
	}
	if binaryDataN2Information := n1n2Request.GetBinaryDataN2Information(); binaryDataN2Information != nil {
		apiReq = apiReq.BinaryDataN2Information(binaryDataN2Information)
	}
	rspData, _, err := smContext.CommunicationClient.
		N1N2MessageCollectionCollectionAPI.
		N1N2MessageTransferExecute(apiReq)
	return rspData, err
}

// orderAmfCandidates returns all candidates, preserving NRF order, but moves any
// candidate whose NfInstanceId equals failedNfId to the end. Every candidate is
// retried (the per-attempt timeout bounds the cost of dead ones): a different
// NfInstanceId is the live AMF when it restarted with a new id, and the same
// NfInstanceId may carry a refreshed ApiPrefix when the AMF re-registered in place.
func orderAmfCandidates(candidates []models.NFProfileDiscovery, failedNfId string) []models.NFProfileDiscovery {
	out := make([]models.NFProfileDiscovery, 0, len(candidates))
	var sameID []models.NFProfileDiscovery
	for _, c := range candidates {
		if c.GetNfInstanceId() == failedNfId {
			sameID = append(sameID, c)
			continue
		}
		out = append(out, c)
	}
	return append(out, sameID...)
}

// searchAmfInstancesNoSubscribe queries NRF directly (cache-bypassing) for AMF instances
// WITHOUT creating NF-status subscriptions. SendNrfForNfInstance subscribes to every
// returned instance; for best-effort re-discovery that would subscribe the SMF to every
// AMF in the deployment (including dead ones), which is an unwanted side effect. If
// targetNfInstanceId is non-empty the query is targeted at that single AMF.
func searchAmfInstancesNoSubscribe(ctx context.Context, targetNfInstanceId string) (*models.SearchResult, error) {
	client := newNrfNFDiscoveryClient(smfContext.SMF_Self().NrfUri)
	req := client.NFInstancesStoreAPI.SearchNFInstances(ctx).
		TargetNfType(models.NFTYPE_AMF).
		RequesterNfType(models.NFTYPE_SMF)
	if targetNfInstanceId != "" {
		req = req.TargetNfInstanceId(targetNfInstanceId)
	}
	result, httpResp, err := client.NFInstancesStoreAPI.SearchNFInstancesExecute(req)
	if httpResp != nil && httpResp.Body != nil {
		defer func() {
			if cerr := httpResp.Body.Close(); cerr != nil {
				logger.ConsumerLog.Errorf("SearchNFInstances response body cannot close: %+v", cerr)
			}
		}()
	}
	if err != nil {
		return nil, err
	}
	return result, nil
}

// fetchAmfCandidates queries NRF directly (bypassing the cache and without subscribing)
// for all registered AMFs. It derives its timeout from the caller's ctx so caller
// cancellation/deadlines are honoured, while still bounding the wait if NRF is slow.
func fetchAmfCandidates(ctx context.Context) ([]models.NFProfileDiscovery, error) {
	queryCtx, cancel := context.WithTimeout(ctx, n1n2TransferTimeout)
	defer cancel()
	result, err := searchAmfInstancesNoSubscribe(queryCtx, "")
	if err != nil {
		return nil, fmt.Errorf("broad AMF discovery failed: %w", err)
	}
	if result == nil || len(result.GetNfInstances()) == 0 {
		return nil, fmt.Errorf("broad AMF discovery returned no AMF instances")
	}
	return result.GetNfInstances(), nil
}

// useAmfProfile selects the given AMF profile on the SMContext and rebuilds the CommunicationClient.
func useAmfProfile(smContext *smfContext.SMContext, profile models.NFProfileDiscovery) error {
	smContext.AMFProfile = deepcopy.Copy(profile).(models.NFProfileDiscovery)
	smContext.ServingNfId = smContext.AMFProfile.GetNfInstanceId()
	smContext.RebuildCommunicationClient()
	if smContext.CommunicationClient == nil {
		return fmt.Errorf("AMF profile %s has no Namf_Communication service", profile.GetNfInstanceId())
	}
	return nil
}

// selectAmfFromNrf installs an AMF on the SMContext via a direct (cache-bypassing) NRF
// query, used to bootstrap a nil CommunicationClient. It prefers a targeted lookup by the
// session's ServingNfId (the AMF that actually serves this UE), so we don't silently switch
// the session to an unrelated AMF; it falls back to the first broad candidate only if
// ServingNfId is unset or the targeted lookup yields nothing.
func selectAmfFromNrf(ctx context.Context, smContext *smfContext.SMContext) error {
	if servingNfId := smContext.ServingNfId; servingNfId != "" {
		smContext.SubPduSessLog.Infof("AMF discovery: targeted NRF lookup for ServingNfId %s (bypassing cache)", servingNfId)
		queryCtx, cancel := context.WithTimeout(ctx, n1n2TransferTimeout)
		result, err := searchAmfInstancesNoSubscribe(queryCtx, servingNfId)
		cancel()
		if err == nil && result != nil && len(result.GetNfInstances()) > 0 {
			return useAmfProfile(smContext, result.GetNfInstances()[0])
		}
		smContext.SubPduSessLog.Warnf("targeted AMF lookup for ServingNfId %s found nothing, falling back to broad discovery", servingNfId)
	} else {
		smContext.SubPduSessLog.Infof("AMF discovery: no ServingNfId, broad NRF lookup (bypassing cache)")
	}

	candidates, err := fetchAmfCandidates(ctx)
	if err != nil {
		return err
	}
	return useAmfProfile(smContext, candidates[0])
}

func SendCreateSubscription(nrfUri string, nrfSubscriptionData models.SubscriptionData) (nrfSubData *models.SubscriptionData, problemDetails *models.ProblemDetails, err error) {
	logger.ConsumerLog.Debugln("send Create Subscription")

	client := newNrfNFManagementClient(nrfUri)

	var res *http.Response
	apiCreateSubscriptionRequest := client.SubscriptionsCollectionAPI.CreateSubscription(context.TODO())
	apiCreateSubscriptionRequest = apiCreateSubscriptionRequest.SubscriptionData(nrfSubscriptionData)
	nrfSubData, res, err = client.SubscriptionsCollectionAPI.CreateSubscriptionExecute(apiCreateSubscriptionRequest)
	if res != nil {
		defer util.CloseResponseBody(res)
	}
	if err == nil {
		return nrfSubData, nil, nil
	} else if res != nil {
		if res.Status != err.Error() {
			logger.ConsumerLog.Errorf("SendCreateSubscription received error response: %v", res.Status)
			return nrfSubData, nil, err
		}
		if problem, handledErr := util.HandleOpenAPIError(err); problem != nil {
			return nrfSubData, problem, nil
		} else if handledErr != nil {
			return nrfSubData, nil, handledErr
		}
	} else {
		err = openapi.ReportError("server no response")
	}
	return nrfSubData, problemDetails, err
}

func SendRemoveSubscription(subscriptionId string) (problemDetails *models.ProblemDetails, err error) {
	logger.ConsumerLog.Infoln("send Remove Subscription")

	smfSelf := smfContext.SMF_Self()
	client := newNrfNFManagementClient(smfSelf.NrfUri)
	var res *http.Response

	apiRemoveSubscriptionRequest := client.SubscriptionIDDocumentAPI.RemoveSubscription(context.Background(), subscriptionId)
	res, err = client.SubscriptionIDDocumentAPI.RemoveSubscriptionExecute(apiRemoveSubscriptionRequest)
	if res != nil {
		defer util.CloseResponseBody(res)
	}
	if err == nil {
		return nil, nil
	} else if res != nil {
		if res.Status != err.Error() {
			return nil, openapi.ReportError("RemoveSubscription received error response: %s", res.Status)
		}
		if problem, handledErr := util.HandleOpenAPIError(err); problem != nil {
			return problem, nil
		} else if handledErr != nil {
			return nil, handledErr
		}
	} else {
		err = openapi.ReportError("server no response")
	}
	return problemDetails, err
}
