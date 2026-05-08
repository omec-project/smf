// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0

package smferrors

import (
	"net/http"

	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
)

var (
	N1SmError = models.ExtProblemDetails{
		Title:  openapi.PtrString("Invalid N1 Message"),
		Status: openapi.PtrInt32(http.StatusForbidden),
		Detail: openapi.PtrString("N1 Message Error"),
		Cause:  openapi.PtrString(string(models.CAUSE_REJECT_DUE_TO_N1_SM_ERROR)),
	}
	DnnDeniedError = models.ExtProblemDetails{
		Title:         openapi.PtrString("DNN Denied"),
		Status:        openapi.PtrInt32(http.StatusForbidden),
		Detail:        openapi.PtrString("The subscriber does not have the necessary subscription to access the DNN"),
		Cause:         openapi.PtrString(string(models.CAUSE_REL_DUE_TO_DNN_DENIED)),
		InvalidParams: nil,
	}
	DnnNotSupported = models.ExtProblemDetails{
		Title:         openapi.PtrString("DNN Not Supported"),
		Status:        openapi.PtrInt32(http.StatusForbidden),
		Detail:        openapi.PtrString("The DNN is not supported by the SMF."),
		Cause:         openapi.PtrString(string(models.CAUSE_REL_DUE_TO_DNN_NOT_SUPPORTED)),
		InvalidParams: nil,
	}
	InsufficientResourceSliceDnn = models.ExtProblemDetails{
		Title:         openapi.PtrString("DNN Resource insufficient"),
		Status:        openapi.PtrInt32(http.StatusInternalServerError),
		Detail:        openapi.PtrString("The request cannot be provided due to insufficient resources for the specific slice and DNN."),
		Cause:         openapi.PtrString(string(models.CAUSE_REL_DUE_TO_INSUFFICIENT_RESOURCES_SLICE_DNN)),
		InvalidParams: nil,
	}
	IpAllocError = models.ExtProblemDetails{
		Title:         openapi.PtrString("IP Allocation Error"),
		Status:        openapi.PtrInt32(http.StatusInternalServerError),
		Detail:        openapi.PtrString("The request cannot be provided due to insufficient resources for the IP allocation."),
		Cause:         openapi.PtrString(string(models.CAUSE_REL_DUE_TO_INSUFFICIENT_RESOURCES_SLICE)),
		InvalidParams: nil,
	}
	SubscriptionDataFetchError = models.ExtProblemDetails{
		Title:         openapi.PtrString("Subscription Data Fetch error"),
		Status:        openapi.PtrInt32(http.StatusInternalServerError),
		Detail:        openapi.PtrString("The request cannot be provided due to failure in fetching subscription data."),
		Cause:         openapi.PtrString("REQUEST_REJECTED"),
		InvalidParams: nil,
	}
	SubscriptionDataLenError = models.ExtProblemDetails{
		Title:         openapi.PtrString("Subscription Data Fetch error"),
		Status:        openapi.PtrInt32(http.StatusInternalServerError),
		Detail:        openapi.PtrString("The request cannot be provided due to not receiving any subscription data.  "),
		Cause:         openapi.PtrString("REQUEST_REJECTED"),
		InvalidParams: nil,
	}
	UDMDiscoveryFailure = models.ExtProblemDetails{
		Title:         openapi.PtrString("UDM Discovery Failure"),
		Status:        openapi.PtrInt32(http.StatusInternalServerError),
		Detail:        openapi.PtrString("The request cannot be provided due to failure in UDM discovery."),
		Cause:         openapi.PtrString("REQUEST_REJECTED"),
		InvalidParams: nil,
	}
	UPFDataPathError = models.ExtProblemDetails{
		Title:         openapi.PtrString("UPF Data Path Failure"),
		Status:        openapi.PtrInt32(http.StatusInternalServerError),
		Detail:        openapi.PtrString("The request cannot be provided due to failure in fetching UPF data path."),
		Cause:         openapi.PtrString("REQUEST_REJECTED"),
		InvalidParams: nil,
	}
	PCFDiscoveryFailure = models.ExtProblemDetails{
		Title:         openapi.PtrString("PCF Discovery Failure"),
		Status:        openapi.PtrInt32(http.StatusInternalServerError),
		Detail:        openapi.PtrString("The request cannot be provided due to failure in PCF discovery."),
		Cause:         openapi.PtrString("REQUEST_REJECTED"),
		InvalidParams: nil,
	}
	PCFPolicyCreateFailure = models.ExtProblemDetails{
		Title:         openapi.PtrString("PCF Policy Create Failure"),
		Status:        openapi.PtrInt32(http.StatusInternalServerError),
		Detail:        openapi.PtrString("The request cannot be provided due to failure in creating PCF policy."),
		Cause:         openapi.PtrString("REQUEST_REJECTED"),
		InvalidParams: nil,
	}
	AMFDiscoveryFailure = models.ExtProblemDetails{
		Title:         openapi.PtrString("AMF Discovery Failure"),
		Status:        openapi.PtrInt32(http.StatusInternalServerError),
		Detail:        openapi.PtrString("The request cannot be provided due to failure in AMF discovery ."),
		Cause:         openapi.PtrString("REQUEST_REJECTED"),
		InvalidParams: nil,
	}
	ApplySMPolicyFailure = models.ExtProblemDetails{
		Title:         openapi.PtrString("Apply SM Policy Error"),
		Status:        openapi.PtrInt32(http.StatusInternalServerError),
		Detail:        openapi.PtrString("The request cannot be provided due to failure in applying SM policy."),
		Cause:         openapi.PtrString("REQUEST_REJECTED"),
		InvalidParams: nil,
	}
	PduSessionTypeNotSupported = models.ExtProblemDetails{
		Title:         openapi.PtrString("PduSession Type Not Supported"),
		Status:        openapi.PtrInt32(http.StatusForbidden),
		Detail:        openapi.PtrString("Unstructured PDU Type is not Supported."),
		Cause:         openapi.PtrString("REQUEST_REJECTED"),
		InvalidParams: nil,
	}
)

var ErrorType = map[string]models.ExtProblemDetails{
	"DnnDeniedError":                DnnDeniedError,
	"DnnNotSupported":               DnnNotSupported,
	"InsufficientResourceSliceDnn":  InsufficientResourceSliceDnn,
	"IpAllocError":                  IpAllocError,
	"SubscriptionDataFetchError":    SubscriptionDataFetchError,
	"SubscriptionDataLenError":      SubscriptionDataLenError,
	"UDMDiscoveryFailure":           UDMDiscoveryFailure,
	"UPFDataPathError":              UPFDataPathError,
	"PCFDiscoveryFailure":           PCFDiscoveryFailure,
	"PCFPolicyCreateFailure":        PCFPolicyCreateFailure,
	"ApplySMPolicyFailure":          ApplySMPolicyFailure,
	"AMFDiscoveryFailure":           AMFDiscoveryFailure,
	"PDUSessionTypeIPv4OnlyAllowed": PduSessionTypeNotSupported,
}

var ErrorCause = map[string]uint8{
	"DnnDeniedError":                nasMessage.Cause5GMMDNNNotSupportedOrNotSubscribedInTheSlice,
	"DnnNotSupported":               nasMessage.Cause5GMMDNNNotSupportedOrNotSubscribedInTheSlice,
	"InsufficientResourceSliceDnn":  nasMessage.Cause5GSMInsufficientResourcesForSpecificSliceAndDNN,
	"IpAllocError":                  nasMessage.Cause5GSMInsufficientResources,
	"SubscriptionDataFetchError":    nasMessage.Cause5GSMRequestRejectedUnspecified,
	"SubscriptionDataLenError":      nasMessage.Cause5GSMRequestRejectedUnspecified,
	"UDMDiscoveryFailure":           nasMessage.Cause5GSMRequestRejectedUnspecified,
	"UPFDataPathError":              nasMessage.Cause5GSMRequestRejectedUnspecified,
	"PCFDiscoveryFailure":           nasMessage.Cause5GSMRequestRejectedUnspecified,
	"PCFPolicyCreateFailure":        nasMessage.Cause5GSMRequestRejectedUnspecified,
	"ApplySMPolicyFailure":          nasMessage.Cause5GSMRequestRejectedUnspecified,
	"AMFDiscoveryFailure":           nasMessage.Cause5GSMRequestRejectedUnspecified,
	"PDUSessionTypeIPv4OnlyAllowed": nasMessage.Cause5GSMPDUSessionTypeIPv4OnlyAllowed,
	"InvalidPDUSessionIdentity":     nasMessage.Cause5GSMInvalidPDUSessionIdentity,
}
