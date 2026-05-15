// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"errors"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
)

func TestCloseResponseBodyAllowsNilBody(t *testing.T) {
	CloseResponseBody(&http.Response{})
}

func TestHandleOpenAPIErrorExtractsProblemDetailsSafely(t *testing.T) {
	problem := models.ProblemDetails{Detail: openapi.PtrString("problem")}
	extracted, err := HandleOpenAPIError(openapi.GenericOpenAPIError{RawModel: problem})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if extracted == nil || extracted.GetDetail() != "problem" {
		t.Fatalf("unexpected extracted problem %+v", extracted)
	}

	originalErr := errors.New("boom")
	extracted, err = HandleOpenAPIError(openapi.GenericOpenAPIError{RawModel: "not-problem"})
	if extracted != nil || err == nil {
		t.Fatalf("expected original error for non-problem model, got extracted=%+v err=%v", extracted, err)
	}

	extracted, err = HandleOpenAPIError(originalErr)
	if extracted != nil || !errors.Is(err, originalErr) {
		t.Fatalf("expected passthrough error, got extracted=%+v err=%v", extracted, err)
	}
}

func TestCreatePayloadTempFileReturnsReadableFile(t *testing.T) {
	tmpFile, err := CreatePayloadTempFile([]byte("payload"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() {
		name := tmpFile.Name()
		_ = tmpFile.Close()
		_ = os.Remove(name)
	}()

	content, err := io.ReadAll(tmpFile)
	if err != nil {
		t.Fatalf("failed reading temp file: %v", err)
	}
	if string(content) != "payload" {
		t.Fatalf("unexpected temp file content %q", string(content))
	}
}

func TestCleanupMultipartTempFilesRemovesNestedFilesOnce(t *testing.T) {
	tmpFile, err := CreatePayloadTempFile([]byte("payload"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	type nestedBody struct {
		Direct *os.File
		Slice  []*os.File
		Map    map[string]any
	}

	name := tmpFile.Name()
	body := nestedBody{
		Direct: tmpFile,
		Slice:  []*os.File{tmpFile},
		Map: map[string]any{
			"duplicate": tmpFile,
		},
	}

	CleanupMultipartTempFiles(body)

	if _, err := os.Stat(name); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected temp file %q to be removed, got err=%v", name, err)
	}
}
