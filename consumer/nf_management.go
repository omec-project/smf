// SPDX-FileCopyrightText: 2022-present Intel Corporation
// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package consumer

import (
	"context"
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
	now := time.Now()
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
				Expiry:          &now,
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
