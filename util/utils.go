// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"net/http"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/smf/logger"
)

// CloseResponseBody safely closes the response body and logs any errors.
func CloseResponseBody(res *http.Response) {
	if res != nil {
		if err := res.Body.Close(); err != nil {
			logger.ConsumerLog.Errorf("response body cannot close: %+v", err)
		}
	}
}

// HandleOpenAPIError processes OpenAPI errors and extracts ProblemDetails if available.
func HandleOpenAPIError(err error) (*models.ProblemDetails, error) {
	if apiError, ok := err.(openapi.GenericOpenAPIError); ok {
		problem := apiError.Model().(models.ProblemDetails)
		return &problem, nil
	}
	return nil, err
}
