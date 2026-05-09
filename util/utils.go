// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"io"
	"net/http"
	"os"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/smf/logger"
)

// CloseResponseBody safely closes the response body and logs any errors.
func CloseResponseBody(res *http.Response) {
	if res != nil && res.Body != nil {
		if err := res.Body.Close(); err != nil {
			logger.ConsumerLog.Errorf("response body cannot close: %+v", err)
		}
	}
}

// HandleOpenAPIError processes OpenAPI errors and extracts ProblemDetails if available.
func HandleOpenAPIError(err error) (*models.ProblemDetails, error) {
	if apiError, ok := openapi.AsGenericOpenAPIError(err); ok {
		switch problem := apiError.Model().(type) {
		case models.ProblemDetails:
			return &problem, nil
		case *models.ProblemDetails:
			return problem, nil
		}
	}
	return nil, err
}

func CreatePayloadTempFile(payload []byte) (*os.File, error) {
	tmpFile, err := os.CreateTemp("", "prefix")
	if err != nil {
		return nil, err
	}
	cleanup := func() {
		name := tmpFile.Name()
		if closeErr := tmpFile.Close(); closeErr != nil {
			logger.ConsumerLog.Errorf("temp file close failed: %+v", closeErr)
		}
		if removeErr := os.Remove(name); removeErr != nil {
			logger.ConsumerLog.Errorf("temp file remove failed: %+v", removeErr)
		}
	}
	if _, err = tmpFile.Write(payload); err != nil {
		cleanup()
		return nil, err
	}
	if _, err = tmpFile.Seek(0, io.SeekStart); err != nil {
		cleanup()
		return nil, err
	}
	return tmpFile, nil
}
