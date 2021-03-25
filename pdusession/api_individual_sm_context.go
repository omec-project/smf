/*
 * Nsmf_PDUSession
 *
 * SMF PDU Session Service
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package pdusession

import (
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/free5gc/http_wrapper"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/smf/logger"
	"github.com/free5gc/smf/msgtypes/svcmsgtypes"
	"github.com/free5gc/smf/producer"

	smf_context "github.com/free5gc/smf/context"
	stats "github.com/free5gc/smf/metrics"
)

// HTTPReleaseSmContext - Release SM Context
func HTTPReleaseSmContext(c *gin.Context) {
	logger.PduSessLog.Info("Recieve Release SM Context Request")
	stats.IncrementN11MsgStats(smf_context.SMF_Self().NfInstanceID, svcmsgtypes.NsmfPDUSessionReleaseSmContext, "In", "", "")

	var request models.ReleaseSmContextRequest
	request.JsonData = new(models.SmContextReleaseData)

	s := strings.Split(c.GetHeader("Content-Type"), ";")
	var err error
	switch s[0] {
	case "application/json":
		err = c.ShouldBindJSON(request.JsonData)
	case "multipart/related":
		err = c.ShouldBindWith(&request, openapi.MultipartRelatedBinding{})
	}
	if err != nil {
		log.Print(err)
		problemDetail := "[Request Body] " + err.Error()
		rsp := models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: problemDetail,
		}
		logger.PduSessLog.Errorln(problemDetail)
		c.JSON(http.StatusBadRequest, rsp)
		stats.IncrementN11MsgStats(smf_context.SMF_Self().NfInstanceID, svcmsgtypes.NsmfPDUSessionReleaseSmContext, "Out", http.StatusText(http.StatusBadRequest), "Malformed")
		return
	}

	req := http_wrapper.NewRequest(c.Request, request)
	req.Params["smContextRef"] = c.Params.ByName("smContextRef")

	smContextRef := req.Params["smContextRef"]
	producer.HandlePDUSessionSMContextRelease(
		smContextRef, req.Body.(models.ReleaseSmContextRequest))

	stats.IncrementN11MsgStats(smf_context.SMF_Self().NfInstanceID, svcmsgtypes.NsmfPDUSessionReleaseSmContext, "Out", http.StatusText(http.StatusNoContent), "")
	c.Status(http.StatusNoContent)
}

// RetrieveSmContext - Retrieve SM Context
func RetrieveSmContext(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{})
}

// HTTPUpdateSmContext - Update SM Context
func HTTPUpdateSmContext(c *gin.Context) {
	logger.PduSessLog.Info("Recieve Update SM Context Request")
	stats.IncrementN11MsgStats(smf_context.SMF_Self().NfInstanceID, svcmsgtypes.NsmfPDUSessionUpdateSmContext, "In", "", "")

	var request models.UpdateSmContextRequest
	request.JsonData = new(models.SmContextUpdateData)

	s := strings.Split(c.GetHeader("Content-Type"), ";")
	var err error
	switch s[0] {
	case "application/json":
		err = c.ShouldBindJSON(request.JsonData)
	case "multipart/related":
		err = c.ShouldBindWith(&request, openapi.MultipartRelatedBinding{})
	}
	if err != nil {
		problemDetail := "[Request Body] " + err.Error()
		rsp := models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: problemDetail,
		}
		logger.PduSessLog.Errorln(problemDetail)
		c.JSON(http.StatusBadRequest, rsp)

		stats.IncrementN11MsgStats(smf_context.SMF_Self().NfInstanceID, svcmsgtypes.NsmfPDUSessionUpdateSmContext, "Out", http.StatusText(http.StatusBadRequest), "Malformed")
		log.Print(err)
		return
	}

	req := http_wrapper.NewRequest(c.Request, request)
	req.Params["smContextRef"] = c.Params.ByName("smContextRef")

	smContextRef := req.Params["smContextRef"]
	HTTPResponse := producer.HandlePDUSessionSMContextUpdate(
		smContextRef, req.Body.(models.UpdateSmContextRequest))

	stats.IncrementN11MsgStats(smf_context.SMF_Self().NfInstanceID, svcmsgtypes.NsmfPDUSessionUpdateSmContext, "Out", http.StatusText(HTTPResponse.Status), "")

	if HTTPResponse.Status < 300 {
		c.Render(HTTPResponse.Status, openapi.MultipartRelatedRender{Data: HTTPResponse.Body})
	} else {
		c.JSON(HTTPResponse.Status, HTTPResponse.Body)
	}
}
