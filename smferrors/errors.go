// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0

package smferrors

import (
	"net/http"

	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/openapi/v2/utils"
)

const (
	errKeyDnnDeniedError  = "DnnDeniedError"
	errKeyDnnNotSupported = "DnnNotSupported"
)

var (
	N1SmError = NewExtProblemDetailsWithCause("Invalid N1 Message", http.StatusForbidden,
		"N1 Message Error", string(models.CAUSE_REJECT_DUE_TO_N1_SM_ERROR))
	DnnDeniedError = NewExtProblemDetailsWithCause("DNN Denied", http.StatusForbidden,
		"The subscriber does not have the necessary subscription to access the DNN",
		string(models.CAUSE_REL_DUE_TO_DNN_DENIED))
	DnnNotSupported = NewExtProblemDetailsWithCause("DNN Not Supported", http.StatusForbidden,
		"The DNN is not supported by the SMF.", string(models.CAUSE_REL_DUE_TO_DNN_NOT_SUPPORTED))
	InsufficientResourceSliceDnn = NewExtProblemDetailsWithCause("DNN Resource insufficient", http.StatusInternalServerError,
		"The request cannot be provided due to insufficient resources for the specific slice and DNN.",
		string(models.CAUSE_REL_DUE_TO_INSUFFICIENT_RESOURCES_SLICE_DNN))
	IpAllocError = NewExtProblemDetailsWithCause("IP Allocation Error", http.StatusInternalServerError,
		"The request cannot be provided due to insufficient resources for the IP allocation.",
		string(models.CAUSE_REL_DUE_TO_INSUFFICIENT_RESOURCES_SLICE))
	SubscriptionDataFetchError = NewExtProblemDetailsWithCause("Subscription Data Fetch error", http.StatusInternalServerError,
		"The request cannot be provided due to failure in fetching subscription data.", utils.CauseRequestRejected)
	SubscriptionDataLenError = NewExtProblemDetailsWithCause("Subscription Data Fetch error", http.StatusInternalServerError,
		"The request cannot be provided due to not receiving any subscription data.  ", utils.CauseRequestRejected)
	UDMDiscoveryFailure = NewExtProblemDetailsWithCause("UDM Discovery Failure", http.StatusInternalServerError,
		"The request cannot be provided due to failure in UDM discovery.", utils.CauseRequestRejected)
	UPFDataPathError = NewExtProblemDetailsWithCause("UPF Data Path Failure", http.StatusInternalServerError,
		"The request cannot be provided due to failure in fetching UPF data path.", utils.CauseRequestRejected)
	PCFDiscoveryFailure = NewExtProblemDetailsWithCause("PCF Discovery Failure", http.StatusInternalServerError,
		"The request cannot be provided due to failure in PCF discovery.", utils.CauseRequestRejected)
	PCFPolicyCreateFailure = NewExtProblemDetailsWithCause("PCF Policy Create Failure", http.StatusInternalServerError,
		"The request cannot be provided due to failure in creating PCF policy.", utils.CauseRequestRejected)
	AMFDiscoveryFailure = NewExtProblemDetailsWithCause("AMF Discovery Failure", http.StatusInternalServerError,
		"The request cannot be provided due to failure in AMF discovery.", utils.CauseRequestRejected)
	ApplySMPolicyFailure = NewExtProblemDetailsWithCause("Apply SM Policy Error", http.StatusInternalServerError,
		"The request cannot be provided due to failure in applying SM policy.", utils.CauseRequestRejected)
	SMContextNotFound          = NewExtProblemDetailsNotFound("Resource Not Found", "SMContext Ref is not found")
	PduSessionTypeNotSupported = NewExtProblemDetailsWithCause("PduSession Type Not Supported", http.StatusForbidden,
		"Unstructured PDU Type is not Supported.", utils.CauseRequestRejected)
)

var ErrorType = map[string]models.ExtProblemDetails{
	errKeyDnnDeniedError:            DnnDeniedError,
	errKeyDnnNotSupported:           DnnNotSupported,
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

// NewExtProblemDetails creates an ExtProblemDetails with basic fields
func NewExtProblemDetails(title string, status int, detail string) models.ExtProblemDetails {
	extProblemDetails := models.ExtProblemDetails{}
	extProblemDetails.SetTitle(title)
	extProblemDetails.SetStatus(int32(status))
	extProblemDetails.SetDetail(detail)
	return extProblemDetails
}

// NewExtProblemDetailsWithCause creates an ExtProblemDetails with cause
func NewExtProblemDetailsWithCause(title string, status int, detail string, cause string) models.ExtProblemDetails {
	extProblemDetails := models.ExtProblemDetails{}
	extProblemDetails.SetTitle(title)
	extProblemDetails.SetStatus(int32(status))
	extProblemDetails.SetDetail(detail)
	extProblemDetails.SetCause(cause)
	return extProblemDetails
}

// NewExtProblemDetailsSystemFailure creates a system failure ExtProblemDetails
func NewExtProblemDetailsSystemFailure() models.ExtProblemDetails {
	extProblemDetails := models.ExtProblemDetails{}
	extProblemDetails.SetStatus(int32(http.StatusInternalServerError))
	extProblemDetails.SetCause(utils.CauseSystemFailure)
	return extProblemDetails
}

// NewExtProblemDetailsNotFound creates a 404 ExtProblemDetails with a Type URI but no cause
func NewExtProblemDetailsNotFound(problemType, title string) models.ExtProblemDetails {
	extProblemDetails := models.ExtProblemDetails{}
	extProblemDetails.SetType(problemType)
	extProblemDetails.SetTitle(title)
	extProblemDetails.SetStatus(int32(http.StatusNotFound))
	return extProblemDetails
}

var ErrorCause = map[string]uint8{
	errKeyDnnDeniedError:            nasMessage.Cause5GSMMissingOrUnknownDNNInASlice,
	errKeyDnnNotSupported:           nasMessage.Cause5GSMMissingOrUnknownDNNInASlice,
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
	// Refusing a UE-requested PDU session modification. #32 is chosen over a generic rejection
	// because TS 24.501 subclause 6.4.2.4.3 item a makes the UE back off on its own for #32 and
	// #33 — with its configured SM Retry Timer, or 12 minutes by default — so the UE stops
	// retransmitting until T3581 and then retrying. A generic cause leaves it retrying.
	"ModificationNotSupported": nasMessage.Cause5GSMServiceOptionNotSupported,
}
