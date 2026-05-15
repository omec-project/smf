// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package pdusession

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/util/httpwrapper"
)

func TestRenderUpdateSmContextResponseUsesMultipartForErrorWithBinaryParts(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)

	n1File, err := os.CreateTemp(t.TempDir(), "n1")
	if err != nil {
		t.Fatalf("create temp n1 file: %v", err)
	}
	n2File, err := os.CreateTemp(t.TempDir(), "n2")
	if err != nil {
		t.Fatalf("create temp n2 file: %v", err)
	}

	response := &httpwrapper.Response{
		Status: http.StatusBadRequest,
		Body: models.UpdateSmContext400Response{
			JsonData: &models.SmContextUpdateError{
				Error:    models.ExtProblemDetails{Status: openapi.PtrInt32(http.StatusBadRequest)},
				N1SmMsg:  &models.RefToBinaryData{ContentId: "n1"},
				N2SmInfo: &models.RefToBinaryData{ContentId: "n2"},
			},
			BinaryDataN1SmMessage:     &n1File,
			BinaryDataN2SmInformation: &n2File,
		},
	}

	if !shouldRenderUpdateSmContextMultipart(response.Body) {
		t.Fatal("expected error response with binary parts to be marked for multipart rendering")
	}

	renderUpdateSmContextResponse(ctx, response)
	if _, err := os.Stat(n1File.Name()); !os.IsNotExist(err) {
		t.Fatalf("expected n1 temp file to be cleaned up, stat err=%v", err)
	}
	if _, err := os.Stat(n2File.Name()); !os.IsNotExist(err) {
		t.Fatalf("expected n2 temp file to be cleaned up, stat err=%v", err)
	}
}
