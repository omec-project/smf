// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package consumer

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/omec-project/openapi/v2/models"
	smfContext "github.com/omec-project/smf/context"
	"github.com/omec-project/smf/factory"
)

const (
	subErrTitle  = "Subscription rejected"
	subErrDetail = "the NRF does not accept subscriptions for this NF type"
	subErrCause  = "SUBSCRIPTION_NOT_ALLOWED"
)

// nrfRejecting stands up an NRF that answers every request with a 403 carrying a conformant
// ProblemDetails, which is the shape the generated client decodes into GenericOpenAPIError.RawModel
// and the shape the removed guard used to discard.
func nrfRejecting(t *testing.T) *httptest.Server {
	t.Helper()

	body, err := json.Marshal(models.ProblemDetails{
		Title:  ptr(subErrTitle),
		Detail: ptr(subErrDetail),
		Cause:  ptr(subErrCause),
		Status: ptrInt32(http.StatusForbidden),
	})
	if err != nil {
		t.Fatalf("marshalling the problem details: %v", err)
	}

	originalHTTPClientFactory := newNrfNFManagementHTTPClient
	svr := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/nnrf-nfm/v1/subscriptions") {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusForbidden)
		if _, writeErr := w.Write(body); writeErr != nil {
			t.Errorf("writing the response body: %v", writeErr)
		}
	}))
	svr.EnableHTTP2 = true
	svr.StartTLS()
	newNrfNFManagementHTTPClient = func() *http.Client { return svr.Client() }
	t.Cleanup(func() {
		newNrfNFManagementHTTPClient = originalHTTPClientFactory
		svr.Close()
	})

	if err := factory.InitConfigFactory("../config/smfcfg.yaml"); err != nil {
		t.Fatalf("could not read the example configuration file: %v", err)
	}
	smfContext.SMF_Self().NrfUri = svr.URL

	return svr
}

func ptr(s string) *string { return &s }

func ptrInt32(i int32) *int32 { return &i }

// assertProblemDetails is the whole point of the change: the NRF's stated reason reaches the
// caller instead of being replaced by a bare status.
func assertProblemDetails(t *testing.T, problem *models.ProblemDetails, err error) {
	t.Helper()

	if err != nil {
		t.Errorf("err = %v, want nil: a 403 whose body decoded is a problem the caller can read, "+
			"not a transport failure", err)
	}
	if problem == nil {
		t.Fatal("problemDetails = nil, want the ProblemDetails the NRF sent; the response body " +
			"decoded and was then discarded, which is the defect this test pins")
	}
	if got := problem.GetTitle(); got != subErrTitle {
		t.Errorf("Title = %q, want %q", got, subErrTitle)
	}
	if got := problem.GetDetail(); got != subErrDetail {
		t.Errorf("Detail = %q, want %q", got, subErrDetail)
	}
	if got := problem.GetCause(); got != subErrCause {
		t.Errorf("Cause = %q, want %q", got, subErrCause)
	}
	if got := problem.GetStatus(); got != http.StatusForbidden {
		t.Errorf("Status = %d, want %d", got, http.StatusForbidden)
	}
}

// The guard fired precisely when there was something to read. The generated client replaces its
// error string with FormatErrorMessage(status, model) as soon as a body decodes, so for a decoded
// ProblemDetails err.Error() never equals res.Status - and the comparison then threw the model away
// in favour of a bare status, on the one path where the NRF had explained itself.
func TestSendCreateSubscriptionReturnsTheProblemDetails(t *testing.T) {
	svr := nrfRejecting(t)

	_, problem, err := SendCreateSubscription(svr.URL, models.SubscriptionData{})

	assertProblemDetails(t, problem, err)
}

func TestSendRemoveSubscriptionReturnsTheProblemDetails(t *testing.T) {
	nrfRejecting(t)

	problem, err := SendRemoveSubscription("subscription-id")

	assertProblemDetails(t, problem, err)
}
