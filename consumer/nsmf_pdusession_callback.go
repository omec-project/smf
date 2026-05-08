// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package consumer

import (
	"context"
	"net/http"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/Nsmf_PDUSession"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/smf/logger"
)

func SendSMContextStatusNotification(uri string) (*models.ProblemDetails, error) {
	if uri != "" {
		request := models.SmContextStatusNotification{}
		request.StatusInfo = models.StatusInfo{
			ResourceStatus: models.RESOURCESTATUS_RELEASED,
		}
		configuration := Nsmf_PDUSession.NewConfiguration()
		client := Nsmf_PDUSession.NewAPIClient(configuration)

		logger.CtxLog.Infoln("[SMF] Send SMContext Status Notification")
		apiSmContextStatusNotificationPostRequest := client.SMContextsCollectionCallbacksmContextStatusNotificationAPI.SmContextStatusNotificationPost(context.Background())
		apiSmContextStatusNotificationPostRequest = apiSmContextStatusNotificationPostRequest.SmContextStatusNotification(request)
		httpResp, localErr := client.SMContextsCollectionCallbacksmContextStatusNotificationAPI.SmContextStatusNotificationPostExecute(apiSmContextStatusNotificationPostRequest)

		if localErr == nil {
			if httpResp.StatusCode != http.StatusNoContent {
				return nil, openapi.ReportError("Send SMContextStatus Notification Failed")
			}

			logger.PduSessLog.Debugln("send SMContextStatus Notification Success")
		} else if httpResp != nil {
			defer func() {
				if resCloseErr := httpResp.Body.Close(); resCloseErr != nil {
					logger.ConsumerLog.Errorf("SMContextNotification response body cannot close: %+v", resCloseErr)
				}
			}()
			logger.PduSessLog.Warnf("Send SMContextStatus Notification Error[%s]", httpResp.Status)
			if httpResp.Status != localErr.Error() {
				return nil, localErr
			}
			problem := localErr.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
			return &problem, nil
		} else {
			logger.PduSessLog.Warnln("http response is nil in comsumer API SMContextNotification")
			return nil, openapi.ReportError("Send SMContextStatus Notification Failed[%s]", localErr.Error())
		}
	}
	return nil, nil
}
