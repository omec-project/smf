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
	"net/http"
	"strings"
	"time"

	"github.com/antihax/optional"
	"github.com/mohae/deepcopy"
	"github.com/omec-project/openapi"
	"github.com/omec-project/openapi/Nnrf_NFDiscovery"
	"github.com/omec-project/openapi/Nnrf_NFManagement"
	"github.com/omec-project/openapi/Nudm_SubscriberDataManagement"
	"github.com/omec-project/openapi/models"
	"github.com/omec-project/openapi/nfConfigApi"
	nrfCache "github.com/omec-project/openapi/nrfcache"
	smfContext "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/smf/metrics"
	"github.com/omec-project/smf/msgtypes/svcmsgtypes"
)

func getNfProfile(smfCtx *smfContext.SMFContext, cfgs []nfConfigApi.SessionManagement) (models.NfProfile, error) {
	if smfCtx == nil {
		return models.NfProfile{}, fmt.Errorf("SMF context is nil")
	}

	nfProf := models.NfProfile{
		NfInstanceId:  smfCtx.NfInstanceID,
		NfType:        models.NfType_SMF,
		NfStatus:      models.NfStatus_REGISTERED,
		Ipv4Addresses: []string{smfCtx.RegisterIPv4},
	}

	// build SmfInfo
	var snssaiSmfInfoList []models.SnssaiSmfInfoItem

	for _, sm := range cfgs {
		item := models.SnssaiSmfInfoItem{
			SNssai: &models.Snssai{
				Sst: sm.Snssai.Sst,
				Sd: func() string {
					if sm.Snssai.Sd != nil {
						return *sm.Snssai.Sd
					}
					return ""
				}(),
			},
		}

		var dnnList []models.DnnSmfInfoItem
		for _, ipdom := range sm.IpDomain {
			if ipdom.DnnName == "" {
				continue
			}
			dnnList = append(dnnList, models.DnnSmfInfoItem{Dnn: ipdom.DnnName})
		}
		if len(dnnList) > 0 {
			item.DnnSmfInfoList = &dnnList
			snssaiSmfInfoList = append(snssaiSmfInfoList, item)
		}
	}

	nfProf.SmfInfo = &models.SmfInfo{SNssaiSmfInfoList: &snssaiSmfInfoList}

	now := time.Now()
	ver := []models.NfServiceVersion{{
		ApiVersionInUri: "v1",
		ApiFullVersion:  fmt.Sprintf("https://%s:%d/nsmf-pdusession/v1", smfCtx.RegisterIPv4, smfCtx.SBIPort),
		Expiry:          &now,
	}}
	nfProf.NfServices = &[]models.NfService{{
		ServiceInstanceId: smfCtx.NfInstanceID,
		ServiceName:       models.ServiceName_NSMF_PDUSESSION,
		Scheme:            models.UriScheme_HTTPS,
		NfServiceStatus:   models.NfServiceStatus_REGISTERED,
		ApiPrefix:         fmt.Sprintf("https://%s:%d", smfCtx.RegisterIPv4, smfCtx.SBIPort),
		Versions:          &ver,
	}}

	return nfProf, nil
}

var SendRegisterNFInstance = func(sessionManagementConfig []nfConfigApi.SessionManagement) (prof models.NfProfile, resourceNrfUri string, err error) {
	self := smfContext.SMF_Self()
	nfProfile, err := getNfProfile(self, sessionManagementConfig)
	if err != nil {
		return models.NfProfile{}, "", err
	}

	configuration := Nnrf_NFManagement.NewConfiguration()
	configuration.SetBasePath(self.NrfUri)
	client := Nnrf_NFManagement.NewAPIClient(configuration)
	metrics.IncrementSvcNrfMsgStats(self.NfInstanceID, string(svcmsgtypes.NnrfNFRegister), "Out", "", "")

	receivedNfProfile, res, err := client.NFInstanceIDDocumentApi.RegisterNFInstance(context.TODO(), nfProfile.NfInstanceId, nfProfile)
	logger.ConsumerLog.Debugf("RegisterNFInstance done using profile: %+v", nfProfile)

	if err != nil {
		metrics.IncrementSvcNrfMsgStats(self.NfInstanceID, string(svcmsgtypes.NnrfNFRegister), "In", "Failure", err.Error())
		return models.NfProfile{}, "", err
	}
	if res == nil {
		metrics.IncrementSvcNrfMsgStats(self.NfInstanceID, string(svcmsgtypes.NnrfNFRegister), "In", "Failure", "NoResponse")
		return models.NfProfile{}, "", fmt.Errorf("no response from server")
	}

	metrics.IncrementSvcNrfMsgStats(self.NfInstanceID, string(svcmsgtypes.NnrfNFRegister), "In", http.StatusText(res.StatusCode), "")

	switch res.StatusCode {
	case http.StatusOK: // NFUpdate
		logger.ConsumerLog.Debugln("SMF NF profile updated with complete replacement")
		return receivedNfProfile, "", nil
	case http.StatusCreated: // NFRegister
		resourceUri := res.Header.Get("Location")
		resourceNrfUri = resourceUri[:strings.Index(resourceUri, "/nnrf-nfm/")]
		retrieveNfInstanceId := resourceUri[strings.LastIndex(resourceUri, "/")+1:]
		self.NfInstanceID = retrieveNfInstanceId
		logger.ConsumerLog.Debugln("SMF NF profile registered to the NRF")
		return receivedNfProfile, resourceNrfUri, nil
	default:
		return receivedNfProfile, "", fmt.Errorf("unexpected status code returned by the NRF %d", res.StatusCode)
	}
}

var SendDeregisterNFInstance = func() error {
	logger.ConsumerLog.Infoln("send Deregister NFInstance")

	smfSelf := smfContext.SMF_Self()
	nfId := smfSelf.NfInstanceID

	// Setup NRF API client
	cfg := Nnrf_NFManagement.NewConfiguration()
	cfg.SetBasePath(smfSelf.NrfUri)
	client := Nnrf_NFManagement.NewAPIClient(cfg)

	// OUT metric: Deregister attempted
	metrics.IncrementSvcNrfMsgStats(nfId, string(svcmsgtypes.NnrfNFInstanceDeRegister), "Out", "", "")

	res, err := client.NFInstanceIDDocumentApi.DeregisterNFInstance(context.Background(), nfId)
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
	return fmt.Errorf("unexpected response code: %d", res.StatusCode)
}

var SendUpdateNFInstance = func(patchItem []models.PatchItem) (receivedNfProfile models.NfProfile, problemDetails *models.ProblemDetails, err error) {
	logger.ConsumerLog.Debugln("send Update NFInstance")

	smfSelf := smfContext.SMF_Self()
	configuration := Nnrf_NFManagement.NewConfiguration()
	configuration.SetBasePath(smfSelf.NrfUri)
	client := Nnrf_NFManagement.NewAPIClient(configuration)

	var res *http.Response
	receivedNfProfile, res, err = client.NFInstanceIDDocumentApi.UpdateNFInstance(context.Background(), smfSelf.NfInstanceID, patchItem)
	if err != nil {
		var openapiErr openapi.GenericOpenAPIError
		if errors.As(err, &openapiErr) {
			if model := openapiErr.Model(); model != nil {
				if problem, ok := model.(models.ProblemDetails); ok {
					return models.NfProfile{}, &problem, nil
				}
			}
		}
		return models.NfProfile{}, nil, err
	}

	if res == nil {
		return models.NfProfile{}, nil, fmt.Errorf("no response from server")
	}
	if res.StatusCode == http.StatusOK || res.StatusCode == http.StatusNoContent {
		return receivedNfProfile, nil, nil
	}
	return models.NfProfile{}, nil, fmt.Errorf("unexpected response code")
}

func getSvcMsgType(nfType models.NfType) svcmsgtypes.SmfMsgType {
	var svcMsgType svcmsgtypes.SmfMsgType

	switch nfType {
	case models.NfType_AMF:
		svcMsgType = svcmsgtypes.NnrfNFDiscoveryAmf
	case models.NfType_PCF:
		svcMsgType = svcmsgtypes.NnrfNFDiscoveryPcf
	case models.NfType_UDM:
		svcMsgType = svcmsgtypes.NnrfNFDiscoveryUdm
	}
	return svcMsgType
}

func SendNrfForNfInstance(nrfUri string, targetNfType, requestNfType models.NfType,
	param *Nnrf_NFDiscovery.SearchNFInstancesParamOpts,
) (models.SearchResult, error) {
	result, httpResp, localErr := smfContext.SMF_Self().
		NFDiscoveryClient.
		NFInstancesStoreApi.
		SearchNFInstances(context.TODO(), targetNfType, requestNfType, param)

	svcMsgType := getSvcMsgType(targetNfType)

	metrics.IncrementSvcNrfMsgStats(smfContext.SMF_Self().NfInstanceID, string(svcMsgType), "Out", "", "")

	if localErr == nil {
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
		localErr = openapi.ReportError("server no response")
	}

	smfSelf := smfContext.SMF_Self()

	for _, nfProfile := range result.NfInstances {
		if _, ok := smfSelf.NfStatusSubscriptions.Load(nfProfile.NfInstanceId); !ok {
			nrfSubscriptionData := models.NrfSubscriptionData{
				NfStatusNotificationUri: fmt.Sprintf("%s://%s:%d/nsmf-callback/v1/nf-status-notify",
					smfSelf.URIScheme,
					smfSelf.RegisterIPv4,
					smfSelf.SBIPort),
				SubscrCond: &models.NfInstanceIdCond{NfInstanceId: nfProfile.NfInstanceId},
				ReqNfType:  requestNfType,
			}
			nrfSubData, problemDetails, err := SendCreateSubscription(nrfUri, nrfSubscriptionData, targetNfType)
			if problemDetails != nil {
				logger.ConsumerLog.Errorf("SendCreateSubscription to NRF, Problem[%+v]", problemDetails)
			} else if err != nil {
				logger.ConsumerLog.Errorf("SendCreateSubscription error[%+v]", err)
			}
			smfSelf.NfStatusSubscriptions.Store(nfProfile.NfInstanceId, nrfSubData.SubscriptionId)
		}
	}
	return result, localErr
}

func SendNFDiscoveryUDM() (*models.ProblemDetails, error) {
	localVarOptionals := Nnrf_NFDiscovery.SearchNFInstancesParamOpts{}

	var result models.SearchResult
	var localErr error

	if smfContext.SMF_Self().EnableNrfCaching {
		result, localErr = nrfCache.SearchNFInstances(smfContext.SMF_Self().NrfUri, models.NfType_UDM, models.NfType_SMF, &localVarOptionals)
	} else {
		result, localErr = SendNrfForNfInstance(smfContext.SMF_Self().NrfUri, models.NfType_UDM, models.NfType_SMF, &localVarOptionals)
	}

	if localErr == nil {
		smfContext.SMF_Self().UDMProfile = result.NfInstances[0]

		for _, service := range *smfContext.SMF_Self().UDMProfile.NfServices {
			if service.ServiceName == models.ServiceName_NUDM_SDM {
				SDMConf := Nudm_SubscriberDataManagement.NewConfiguration()
				SDMConf.SetBasePath(service.ApiPrefix)
				smfContext.SMF_Self().SubscriberDataManagementClient = Nudm_SubscriberDataManagement.NewAPIClient(SDMConf)
			}
		}

		if smfContext.SMF_Self().SubscriberDataManagementClient == nil {
			logger.ConsumerLog.Warnln("sdm client failed")
		}
	} else {
		apiError, ok := localErr.(openapi.GenericOpenAPIError)
		if ok {
			problem := apiError.Model().(models.ProblemDetails)
			return &problem, nil
		}

		return nil, localErr
	}
	return nil, nil
}

func SendNFDiscoveryPCF() (problemDetails *models.ProblemDetails, err error) {
	localVarOptionals := Nnrf_NFDiscovery.SearchNFInstancesParamOpts{}

	var result models.SearchResult
	var localErr error

	if smfContext.SMF_Self().EnableNrfCaching {
		result, localErr = nrfCache.SearchNFInstances(smfContext.SMF_Self().NrfUri, models.NfType_PCF, models.NfType_SMF, &localVarOptionals)
	} else {
		result, localErr = SendNrfForNfInstance(smfContext.SMF_Self().NrfUri, models.NfType_PCF, models.NfType_SMF, &localVarOptionals)
	}

	if localErr == nil {
		logger.ConsumerLog.Debugln(result.NfInstances)
	} else {
		apiError, ok := localErr.(openapi.GenericOpenAPIError)
		if ok {
			problem := apiError.Model().(models.ProblemDetails)
			return &problem, nil
		}

		return nil, localErr
	}

	return problemDetails, err
}

func SendNFDiscoveryServingAMF(smContext *smfContext.SMContext) (*models.ProblemDetails, error) {
	localVarOptionals := Nnrf_NFDiscovery.SearchNFInstancesParamOpts{}

	localVarOptionals.TargetNfInstanceId = optional.NewInterface(smContext.ServingNfId)

	var result models.SearchResult
	var localErr error

	if smfContext.SMF_Self().EnableNrfCaching {
		result, localErr = nrfCache.SearchNFInstances(smfContext.SMF_Self().NrfUri, models.NfType_AMF, models.NfType_SMF, &localVarOptionals)
	} else {
		result, localErr = SendNrfForNfInstance(smfContext.SMF_Self().NrfUri, models.NfType_AMF, models.NfType_SMF, &localVarOptionals)
	}

	if localErr == nil {
		if result.NfInstances == nil {
			return nil, openapi.ReportError("NfInstances is nil")
		}
		smContext.SubConsumerLog.Info("send NF Discovery Serving AMF Successful")
		smContext.AMFProfile = deepcopy.Copy(result.NfInstances[0]).(models.NfProfile)
	} else {
		apiError, ok := localErr.(openapi.GenericOpenAPIError)
		if ok {
			problem := apiError.Model().(models.ProblemDetails)
			return &problem, nil
		}

		return nil, localErr
	}
	return nil, nil
}

func SendCreateSubscription(nrfUri string, nrfSubscriptionData models.NrfSubscriptionData) (nrfSubData models.NrfSubscriptionData, problemDetails *models.ProblemDetails, err error) {
	logger.ConsumerLog.Debugln("send Create Subscription")

	// Set client and set url
	configuration := Nnrf_NFManagement.NewConfiguration()
	configuration.SetBasePath(nrfUri)
	client := Nnrf_NFManagement.NewAPIClient(configuration)

	var res *http.Response
	nrfSubData, res, err = client.SubscriptionsCollectionApi.CreateSubscription(context.TODO(), nrfSubscriptionData)
	if err == nil {
		return
	} else if res != nil {
		defer func() {
			if resCloseErr := res.Body.Close(); resCloseErr != nil {
				logger.ConsumerLog.Errorf("SendCreateSubscription response cannot close: %+v", resCloseErr)
			}
		}()
		if res.Status != err.Error() {
			logger.ConsumerLog.Errorf("SendCreateSubscription received error response: %v", res.Status)
			return
		}
		problem := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		problemDetails = &problem
	} else {
		err = fmt.Errorf("server no response")
	}
	return
}

func SendRemoveSubscription(subscriptionId string) (problemDetails *models.ProblemDetails, err error) {
	logger.ConsumerLog.Infoln("send Remove Subscription")

	smfSelf := smfContext.SMF_Self()
	// Set client and set url
	configuration := Nnrf_NFManagement.NewConfiguration()
	configuration.SetBasePath(smfSelf.NrfUri)
	client := Nnrf_NFManagement.NewAPIClient(configuration)
	var res *http.Response

	res, err = client.SubscriptionIDDocumentApi.RemoveSubscription(context.Background(), subscriptionId)
	if err == nil {
		return
	} else if res != nil {
		defer func() {
			if bodyCloseErr := res.Body.Close(); bodyCloseErr != nil {
				err = fmt.Errorf("RemoveSubscription's response body cannot close: %w", bodyCloseErr)
			}
		}()
		if res.Status != err.Error() {
			return
		}
		problem := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		problemDetails = &problem
	} else {
		err = fmt.Errorf("server no response")
	}
	return
}
