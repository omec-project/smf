// SPDX-FileCopyrightText: 2022-present Intel Corporation
// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package callback

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/omec-project/openapi"
	"github.com/omec-project/openapi/models"
	"github.com/omec-project/smf/consumer"
	smfContext "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/smf/producer"
	"github.com/omec-project/util/httpwrapper"
)

func HTTPNfSubscriptionStatusNotify(c *gin.Context) {
	var nfSubscriptionStatusNotification models.NotificationData

	requestBody, err := c.GetRawData()
	if err != nil {
		logger.PduSessLog.Errorf("Get Request Body error: %+v", err)
		problemDetail := models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		c.JSON(http.StatusInternalServerError, problemDetail)
		return
	}

	err = openapi.Deserialize(&nfSubscriptionStatusNotification, requestBody, "application/json")
	if err != nil {
		problemDetail := "[Request Body] " + err.Error()
		rsp := models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: problemDetail,
		}
		logger.PduSessLog.Errorln(problemDetail)
		c.JSON(http.StatusBadRequest, rsp)
		return
	}

	req := httpwrapper.NewRequest(c.Request, nfSubscriptionStatusNotification)

	rsp := producer.HandleNfSubscriptionStatusNotify(req)

	responseBody, err := openapi.Serialize(rsp.Body, "application/json")
	if err != nil {
		logger.PduSessLog.Errorf("Error fetching response for HTTPNfSubscriptionStatusNotify : %+v\n", err)
		problemDetails := models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "SYSTEM_FAILURE",
			Detail: err.Error(),
		}
		c.JSON(http.StatusInternalServerError, problemDetails)
	} else {
		c.Data(rsp.Status, "application/json", responseBody)
		if nfSubscriptionStatusNotification.Event != models.NotificationEventType_DEREGISTERED {
			return
		}
		nfID := nfSubscriptionStatusNotification.NfProfile.NfInstanceId
		value, found := smfContext.SMF_Self().NfStatusSubscriptions.Load(nfID)
		if !found {
			logger.ConsumerLog.Warnf("no subscriptionId found for NF instance %s", nfID)
			return
		}
		subID := value.(string)
		problem, err := consumer.SendRemoveSubscription(subID)
		if err != nil {
			logger.ConsumerLog.Errorf("failed to remove NRF subscription %s: %+v", subID, err)
			return
		}
		if problem != nil {
			logger.ConsumerLog.Warnf("NRF responded with problem while removing %s: %+v", subID, problem)
			return
		}
		smfContext.SMF_Self().NfStatusSubscriptions.Delete(nfID)
	}
}
