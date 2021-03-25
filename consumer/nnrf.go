package consumer

import (
	"context"
	"fmt"
	"free5gc/lib/openapi"
	"free5gc/lib/openapi/Nnrf_NFDiscovery"
	"free5gc/lib/openapi/Nudm_SubscriberDataManagement"
	"free5gc/lib/openapi/models"
	"free5gc/lib/msgtypes"
	smf_context "free5gc/src/smf/context"
	"free5gc/src/smf/logger"
	"free5gc/src/smf/metrics"
	"net/http"

	"strings"
	"time"

	"github.com/antihax/optional"
	"github.com/mohae/deepcopy"
)

func SendNFRegistration() error {

	//set nfProfile
	profile := models.NfProfile{
		NfInstanceId:  smf_context.SMF_Self().NfInstanceID,
		NfType:        models.NfType_SMF,
		NfStatus:      models.NfStatus_REGISTERED,
		Ipv4Addresses: []string{smf_context.SMF_Self().RegisterIPv4},
		NfServices:    smf_context.NFServices,
		SmfInfo:       smf_context.SmfInfo,
	}
	var rep models.NfProfile
	var res *http.Response
	var err error

	// Check data (Use RESTful PUT)
	for {
		rep, res, err = smf_context.SMF_Self().
			NFManagementClient.
			NFInstanceIDDocumentApi.
			RegisterNFInstance(context.TODO(), smf_context.SMF_Self().NfInstanceID, profile)
			metrics.IncrementSvcNrfMsgStats(smf_context.SMF_Self().NfInstanceID, msgtypes.NnrfNFRegister, "Out", "", "")

		if err != nil || res == nil {
			logger.AppLog.Infof("SMF register to NRF Error[%s]", err.Error())
			metrics.IncrementSvcNrfMsgStats(smf_context.SMF_Self().NfInstanceID, msgtypes.NnrfNFRegister, "In", "Failure", err.Error())
			time.Sleep(2 * time.Second)
			continue
		}

		metrics.IncrementSvcNrfMsgStats(smf_context.SMF_Self().NfInstanceID, msgtypes.NnrfNFRegister, "In", http.StatusText(res.StatusCode), "")

		status := res.StatusCode
		if status == http.StatusOK {
			// NFUpdate
			break
		} else if status == http.StatusCreated {
			// NFRegister
			resourceUri := res.Header.Get("Location")
			// resouceNrfUri := resourceUri[strings.LastIndex(resourceUri, "/"):]
			smf_context.SMF_Self().NfInstanceID = resourceUri[strings.LastIndex(resourceUri, "/")+1:]
			break
		} else {
			logger.AppLog.Infof("handler returned wrong status code %d", status)
			// fmt.Errorf("NRF return wrong status code %d", status)
		}
	}

	logger.InitLog.Infof("SMF Registration to NRF %v", rep)
	return nil
}

func RetrySendNFRegistration(MaxRetry int) error {

	retryCount := 0
	for retryCount < MaxRetry {
		err := SendNFRegistration()
		if err == nil {
			return nil
		}
		logger.AppLog.Warnf("Send NFRegistration Failed by %v", err)
		retryCount++
	}

	return fmt.Errorf("[SMF] Retry NF Registration has meet maximum")
}

func SendNFDeregistration() error {

	// Check data (Use RESTful DELETE)
	res, localErr := smf_context.SMF_Self().
		NFManagementClient.
		NFInstanceIDDocumentApi.
		DeregisterNFInstance(context.TODO(), smf_context.SMF_Self().NfInstanceID)
		metrics.IncrementSvcNrfMsgStats(smf_context.SMF_Self().NfInstanceID, msgtypes.NnrfNFDeRegister, "Out", "", "")
	if localErr != nil {
		logger.AppLog.Warnln(localErr)
		metrics.IncrementSvcNrfMsgStats(smf_context.SMF_Self().NfInstanceID, msgtypes.NnrfNFDeRegister, "In", "Failure", localErr.Error())
		return localErr
	}
	if res != nil {
		metrics.IncrementSvcNrfMsgStats(smf_context.SMF_Self().NfInstanceID, msgtypes.NnrfNFRegister, "In", http.StatusText(res.StatusCode), "")
		if status := res.StatusCode; status != http.StatusNoContent {
			logger.AppLog.Warnln("handler returned wrong status code ", status)
			return openapi.ReportError("handler returned wrong status code %d", status)
		}
	}
	return nil
}

func SendNFDiscoveryUDM() (*models.ProblemDetails, error) {

	localVarOptionals := Nnrf_NFDiscovery.SearchNFInstancesParamOpts{}

	// Check data
	result, httpResp, localErr := smf_context.SMF_Self().
		NFDiscoveryClient.
		NFInstancesStoreApi.
		SearchNFInstances(context.TODO(), models.NfType_UDM, models.NfType_SMF, &localVarOptionals)
		metrics.IncrementSvcNrfMsgStats(smf_context.SMF_Self().NfInstanceID, msgtypes.NnrfNFDiscoveryUdm, "Out", "", "")

	if localErr == nil {
		metrics.IncrementSvcNrfMsgStats(smf_context.SMF_Self().NfInstanceID, msgtypes.NnrfNFDiscoveryUdm, "In", http.StatusText(httpResp.StatusCode), "")
		smf_context.SMF_Self().UDMProfile = result.NfInstances[0]

		for _, service := range *smf_context.SMF_Self().UDMProfile.NfServices {
			if service.ServiceName == models.ServiceName_NUDM_SDM {
				SDMConf := Nudm_SubscriberDataManagement.NewConfiguration()
				SDMConf.SetBasePath(service.ApiPrefix)
				smf_context.SMF_Self().SubscriberDataManagementClient = Nudm_SubscriberDataManagement.NewAPIClient(SDMConf)
			}
		}

		if smf_context.SMF_Self().SubscriberDataManagementClient == nil {
			logger.AppLog.Warnln("sdm client failed")
		}
	} else if httpResp != nil {
		logger.AppLog.Warnln("handler returned wrong status code ", httpResp.Status)
		if httpResp.Status != localErr.Error() {
			metrics.IncrementSvcNrfMsgStats(smf_context.SMF_Self().NfInstanceID, msgtypes.NnrfNFDiscoveryUdm, "In", http.StatusText(httpResp.StatusCode), httpResp.Status)
			return nil, localErr
		}
		problem := localErr.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		metrics.IncrementSvcNrfMsgStats(smf_context.SMF_Self().NfInstanceID, msgtypes.NnrfNFDiscoveryUdm, "In", http.StatusText(httpResp.StatusCode), localErr.Error())
		return &problem, nil
	} else {
		metrics.IncrementSvcNrfMsgStats(smf_context.SMF_Self().NfInstanceID, msgtypes.NnrfNFDiscoveryUdm, "In", "Failure", "NoResponse")
		return nil, openapi.ReportError("server no response")
	}
	return nil, nil
}

func SendNFDiscoveryPCF() (problemDetails *models.ProblemDetails, err error) {

	// Set targetNfType
	targetNfType := models.NfType_PCF
	// Set requestNfType
	requesterNfType := models.NfType_SMF
	localVarOptionals := Nnrf_NFDiscovery.SearchNFInstancesParamOpts{}

	// Check data
	result, httpResp, localErr := smf_context.SMF_Self().
		NFDiscoveryClient.
		NFInstancesStoreApi.
		SearchNFInstances(context.TODO(), targetNfType, requesterNfType, &localVarOptionals)
		metrics.IncrementSvcNrfMsgStats(smf_context.SMF_Self().NfInstanceID, msgtypes.NnrfNFDiscoveryPcf, "Out", "", "")

	if localErr == nil {
		metrics.IncrementSvcNrfMsgStats(smf_context.SMF_Self().NfInstanceID, msgtypes.NnrfNFDiscoveryPcf, "In", http.StatusText(httpResp.StatusCode), "")
		logger.AppLog.Traceln(result.NfInstances)
	} else if httpResp != nil {
		logger.AppLog.Warnln("handler returned wrong status code ", httpResp.Status)
		if httpResp.Status != localErr.Error() {
			err = localErr
			metrics.IncrementSvcNrfMsgStats(smf_context.SMF_Self().NfInstanceID, msgtypes.NnrfNFDiscoveryPcf, "In", http.StatusText(httpResp.StatusCode), httpResp.Status)
			return
		}
		metrics.IncrementSvcNrfMsgStats(smf_context.SMF_Self().NfInstanceID, msgtypes.NnrfNFDiscoveryPcf, "In", http.StatusText(httpResp.StatusCode), localErr.Error())
		problem := localErr.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		problemDetails = &problem
	} else {
		metrics.IncrementSvcNrfMsgStats(smf_context.SMF_Self().NfInstanceID, msgtypes.NnrfNFDiscoveryPcf, "In", "Failure", "NoResponse")
		err = openapi.ReportError("server no response")
	}

	return
}

func SendNFDiscoveryServingAMF(smContext *smf_context.SMContext) (*models.ProblemDetails, error) {
	targetNfType := models.NfType_AMF
	requesterNfType := models.NfType_SMF

	localVarOptionals := Nnrf_NFDiscovery.SearchNFInstancesParamOpts{}

	localVarOptionals.TargetNfInstanceId = optional.NewInterface(smContext.ServingNfId)

	// Check data
	result, httpResp, localErr := smf_context.SMF_Self().
		NFDiscoveryClient.
		NFInstancesStoreApi.
		SearchNFInstances(context.TODO(), targetNfType, requesterNfType, &localVarOptionals)
		metrics.IncrementSvcNrfMsgStats(smf_context.SMF_Self().NfInstanceID, msgtypes.NnrfNFDiscoveryAmf, "Out", "", "")

	if localErr == nil {
		if result.NfInstances == nil {
			if status := httpResp.StatusCode; status != http.StatusOK {
				logger.AppLog.Warnln("handler returned wrong status code", status)
			}
			logger.AppLog.Warnln("NfInstances is nil")
			metrics.IncrementSvcNrfMsgStats(smf_context.SMF_Self().NfInstanceID, msgtypes.NnrfNFDiscoveryAmf, "In", http.StatusText(httpResp.StatusCode), "NilInstance")
			return nil, openapi.ReportError("NfInstances is nil")
		}
		logger.AppLog.Info("SendNFDiscoveryServingAMF ok")
		smContext.AMFProfile = deepcopy.Copy(result.NfInstances[0]).(models.NfProfile)
		metrics.IncrementSvcNrfMsgStats(smf_context.SMF_Self().NfInstanceID, msgtypes.NnrfNFDiscoveryAmf, "In", http.StatusText(httpResp.StatusCode), "")
	} else if httpResp != nil {
		if httpResp.Status != localErr.Error() {
			metrics.IncrementSvcNrfMsgStats(smf_context.SMF_Self().NfInstanceID, msgtypes.NnrfNFDiscoveryAmf, "In", http.StatusText(httpResp.StatusCode), httpResp.Status)
			return nil, localErr
		}
		metrics.IncrementSvcNrfMsgStats(smf_context.SMF_Self().NfInstanceID, msgtypes.NnrfNFDiscoveryAmf, "In", http.StatusText(httpResp.StatusCode), localErr.Error())
		problem := localErr.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		return &problem, nil
	} else {
		metrics.IncrementSvcNrfMsgStats(smf_context.SMF_Self().NfInstanceID, msgtypes.NnrfNFDiscoveryAmf, "In", "Failure", "NoResponse")
		return nil, openapi.ReportError("server no response")
	}

	return nil, nil

}

func SendDeregisterNFInstance() (*models.ProblemDetails, error) {
	logger.AppLog.Infof("Send Deregister NFInstance")

	smfSelf := smf_context.SMF_Self()
	// Set client and set url

	var res *http.Response

	var err error
	res, err = smfSelf.
		NFManagementClient.
		NFInstanceIDDocumentApi.
		DeregisterNFInstance(context.Background(), smfSelf.NfInstanceID)
		metrics.IncrementSvcNrfMsgStats(smfSelf.NfInstanceID, msgtypes.NnrfNFInstanceDeRegister, "Out", "", "")
	if err == nil {
		metrics.IncrementSvcNrfMsgStats(smfSelf.NfInstanceID, msgtypes.NnrfNFInstanceDeRegister, "In", http.StatusText(res.StatusCode), "")
		return nil, err
	} else if res != nil {
		if res.Status != err.Error() {
			metrics.IncrementSvcNrfMsgStats(smfSelf.NfInstanceID, msgtypes.NnrfNFInstanceDeRegister, "In", http.StatusText(res.StatusCode), res.Status)
			return nil, err
		}
		metrics.IncrementSvcNrfMsgStats(smfSelf.NfInstanceID, msgtypes.NnrfNFInstanceDeRegister, "In", http.StatusText(res.StatusCode), err.Error())
		problem := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		return &problem, err
	} else {
		metrics.IncrementSvcNrfMsgStats(smfSelf.NfInstanceID, msgtypes.NnrfNFInstanceDeRegister, "In", "Failure", "NoResponse")
		return nil, openapi.ReportError("server no response")
	}
}
