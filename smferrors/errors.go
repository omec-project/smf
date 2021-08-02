package smferrors

import (
	"net/http"

	"github.com/free5gc/openapi/models"
)

var (
	N1SmError = models.ProblemDetails{
		Title:  "Invalid N1 Message",
		Status: http.StatusForbidden,
		Detail: "N1 Message Error",
		Cause:  "N1_SM_ERROR",
	}
	DnnDeniedError = models.ProblemDetails{
		Title:         "DNN Denied",
		Status:        http.StatusForbidden,
		Detail:        "The subscriber does not have the necessary subscription to access the DNN",
		Cause:         "DNN_DENIED",
		InvalidParams: nil,
	}
	DnnNotSupported = models.ProblemDetails{
		Title:         "DNN Not Supported",
		Status:        http.StatusForbidden,
		Detail:        "The DNN is not supported by the SMF.",
		Cause:         "DNN_NOT_SUPPORTED",
		InvalidParams: nil,
	}
	InsufficientResourceSliceDnn = models.ProblemDetails{
		Title:         "DNN Resource insufficient",
		Status:        http.StatusInternalServerError,
		Detail:        "The request cannot be provided due to insufficient resources for the specific slice and DNN.",
		Cause:         "INSUFFICIENT_RESOURCES_SLICE_DNN",
		InvalidParams: nil,
	}
	IpAllocError = models.ProblemDetails{
		Title:         "IP Allocation Error",
		Status:        http.StatusInternalServerError,
		Detail:        "The request cannot be provided due to insufficient resources for the IP allocation.",
		Cause:         "INSUFFICIENT_RESOURCES",
		InvalidParams: nil,
	}
	SubscriptionDataFetchError = models.ProblemDetails{
		Title:         "Subscription Data Fetch error",
		Status:        http.StatusInternalServerError,
		Detail:        "The request cannot be provided due to failure in fetching subscription data.",
		Cause:         "REQUEST_REJECTED",
		InvalidParams: nil,
	}
	SubscriptionDataLenError = models.ProblemDetails{
		Title:         "Subscription Data Fetch error",
		Status:        http.StatusInternalServerError,
		Detail:        "The request cannot be provided due to not receiving any subscription data.  ",
		Cause:         "REQUEST_REJECTED",
		InvalidParams: nil,
	}
	UDMDiscoveryFailure = models.ProblemDetails{
		Title:         "UDM Discovery Failure",
		Status:        http.StatusInternalServerError,
		Detail:        "The request cannot be provided due to failure in UDM discovery.",
		Cause:         "REQUEST_REJECTED",
		InvalidParams: nil,
	}
	UPFDataPathError = models.ProblemDetails{
		Title:         "UPF Data Path Failure",
		Status:        http.StatusInternalServerError,
		Detail:        "The request cannot be provided due to failure in fetching UPF data path.",
		Cause:         "REQUEST_REJECTED",
		InvalidParams: nil,
	}
	PCFDiscoveryFailure = models.ProblemDetails{
		Title:         "PCF Discovery Failure",
		Status:        http.StatusInternalServerError,
		Detail:        "The request cannot be provided due to failure in PCF discovery.",
		Cause:         "REQUEST_REJECTED",
		InvalidParams: nil,
	}
	PCFPolicyCreateFailure = models.ProblemDetails{
		Title:         "PCF Discovery Failure",
		Status:        http.StatusInternalServerError,
		Detail:        "The request cannot be provided due to failure in creating PCF policy.",
		Cause:         "REQUEST_REJECTED",
		InvalidParams: nil,
	}
	AMFDiscoveryFailure = models.ProblemDetails{
		Title:         "AMF Discovery Failure",
		Status:        http.StatusInternalServerError,
		Detail:        "The request cannot be provided due to failure in AMF discovery .",
		Cause:         "REQUEST_REJECTED",
		InvalidParams: nil,
	}
	ApplySMPolicyFailure = models.ProblemDetails{
		Title:         "Apply SM Policy Error",
		Status:        http.StatusInternalServerError,
		Detail:        "The request cannot be provided due to failure in applying SM policy.",
		Cause:         "REQUEST_REJECTED",
		InvalidParams: nil,
	}
)
