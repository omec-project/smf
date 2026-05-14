// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package consumer

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/smf/logger"
)

func postSMContextStatusNotification(ctx context.Context, uri string, request models.SmContextStatusNotification) (*http.Response, error) {
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/problem+json")

	return http.DefaultClient.Do(httpRequest)
}

func SendSMContextStatusNotification(uri string) (*models.ProblemDetails, error) {
	if uri != "" {
		request := models.SmContextStatusNotification{}
		request.StatusInfo = models.StatusInfo{
			ResourceStatus: models.RESOURCESTATUS_RELEASED,
		}

		logger.CtxLog.Infoln("[SMF] Send SMContext Status Notification")
		httpResp, localErr := postSMContextStatusNotification(context.Background(), uri, request)
		if httpResp != nil && httpResp.Body != nil {
			defer func() {
				if resCloseErr := httpResp.Body.Close(); resCloseErr != nil {
					logger.ConsumerLog.Errorf("SMContextNotification response body cannot close: %+v", resCloseErr)
				}
			}()
		}

		if localErr == nil {
			if httpResp.StatusCode != http.StatusNoContent {
				return nil, openapi.ReportError("Send SMContextStatus Notification Failed")
			}

			logger.PduSessLog.Debugln("send SMContextStatus Notification Success")
		} else if httpResp != nil {
			logger.PduSessLog.Warnf("Send SMContextStatus Notification Error[%s]", httpResp.Status)
			return nil, localErr
		} else {
			logger.PduSessLog.Warnln("http response is nil in comsumer API SMContextNotification")
			return nil, openapi.ReportError("Send SMContextStatus Notification Failed[%s]", localErr.Error())
		}
	}
	return nil, nil
}
