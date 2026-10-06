// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"errors"
	"io"
	"os"
	"testing"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
)

const svcA = "svc-a"

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

func TestNFProfileServicesPrefersNfServiceList(t *testing.T) {
	profile := models.NewNFProfileWithDefaults()
	profile.SetNfServiceList(map[string]models.NFService{
		"svc-list": {ServiceInstanceId: "svc-list", ServiceName: models.SERVICENAME_NSMF_PDUSESSION},
	})
	profile.SetNfServices([]models.NFService{
		{ServiceInstanceId: "svc-slice", ServiceName: models.SERVICENAME_NUDM_SDM},
	})

	got := NFProfileServices(profile)
	if len(got) != 1 {
		t.Fatalf("expected only NfServiceList entries, got %+v", got)
	}
	if _, ok := got["svc-list"]; !ok {
		t.Fatalf("expected NfServiceList entry to be present, got %+v", got)
	}
}

func TestNFProfileServicesFallsBackToDeprecatedSlice(t *testing.T) {
	profile := models.NewNFProfileWithDefaults()
	profile.SetNfServices([]models.NFService{
		{ServiceInstanceId: svcA, ServiceName: models.SERVICENAME_NUDM_SDM},
		{ServiceName: models.SERVICENAME_NAMF_COMM}, // no ServiceInstanceId: keyed by index
	})

	got := NFProfileServices(profile)
	if len(got) != 2 {
		t.Fatalf("expected both deprecated slice entries, got %+v", got)
	}
	if svc, ok := got[svcA]; !ok || svc.GetServiceName() != models.SERVICENAME_NUDM_SDM {
		t.Fatalf("expected svc-a to be keyed by ServiceInstanceId, got %+v", got)
	}
	if svc, ok := got["1"]; !ok || svc.GetServiceName() != models.SERVICENAME_NAMF_COMM {
		t.Fatalf("expected entry with no ServiceInstanceId to be keyed by index, got %+v", got)
	}
}

func TestNFProfileServicesFallbackKeyDoesNotCollideWithServiceInstanceId(t *testing.T) {
	profile := models.NewNFProfileWithDefaults()
	profile.SetNfServices([]models.NFService{
		{ServiceName: models.SERVICENAME_NAMF_COMM},                        // no ServiceInstanceId, index 0: candidate key "0" collides with the real id below
		{ServiceInstanceId: "0", ServiceName: models.SERVICENAME_NUDM_SDM}, // real id "0" takes priority over the index-based fallback
	})

	got := NFProfileServices(profile)
	if len(got) != 2 {
		t.Fatalf("expected both entries to be preserved, got %+v", got)
	}
	if svc, ok := got["0"]; !ok || svc.GetServiceName() != models.SERVICENAME_NUDM_SDM {
		t.Fatalf("expected real ServiceInstanceId %q to take priority, got %+v", "0", got)
	}
	if svc, ok := got["0_"]; !ok || svc.GetServiceName() != models.SERVICENAME_NAMF_COMM {
		t.Fatalf("expected index-0 entry to fall back to a collision-free suffixed key, got %+v", got)
	}
}

func TestNFProfileDiscoveryServicesFallsBackToDeprecatedSlice(t *testing.T) {
	profile := models.NewNFProfileDiscoveryWithDefaults()
	profile.SetNfServices([]models.NFService{
		{ServiceInstanceId: svcA, ServiceName: models.SERVICENAME_NAMF_COMM},
	})

	got := NFProfileDiscoveryServices(profile)
	if svc, ok := got[svcA]; !ok || svc.GetServiceName() != models.SERVICENAME_NAMF_COMM {
		t.Fatalf("expected svc-a from the deprecated slice, got %+v", got)
	}
}

func TestSetNFProfileServicesPopulatesBothFields(t *testing.T) {
	profile := models.NewNFProfileWithDefaults()
	services := map[string]models.NFService{
		svcA: {ServiceInstanceId: svcA, ServiceName: models.SERVICENAME_NUDM_SDM},
	}

	SetNFProfileServices(profile, services)

	if got := profile.GetNfServiceList(); len(got) != 1 {
		t.Fatalf("expected NfServiceList to be populated, got %+v", got)
	}
	slice := profile.GetNfServices()
	if len(slice) != 1 || slice[0].GetServiceInstanceId() != svcA {
		t.Fatalf("expected deprecated NfServices slice to also be populated, got %+v", slice)
	}
}

func TestFindServiceByNamePicksLexicographicallySmallestKeyOnDuplicateNames(t *testing.T) {
	services := map[string]models.NFService{
		"svc-z": {ServiceInstanceId: "svc-z", ServiceName: models.SERVICENAME_NAMF_COMM, ApiPrefix: openapi.PtrString("z")},
		"svc-a": {ServiceInstanceId: "svc-a", ServiceName: models.SERVICENAME_NAMF_COMM, ApiPrefix: openapi.PtrString("a")},
		"svc-m": {ServiceInstanceId: "svc-m", ServiceName: models.SERVICENAME_NUDM_SDM, ApiPrefix: openapi.PtrString("m")},
	}

	// Run several times: map iteration order is randomized per-process, so a
	// non-deterministic implementation would be expected to disagree across runs.
	for i := 0; i < 10; i++ {
		svc, ok := FindServiceByName(services, models.SERVICENAME_NAMF_COMM)
		if !ok || svc.GetApiPrefix() != "a" {
			t.Fatalf("expected deterministic selection of svc-a, got %+v (ok=%v)", svc, ok)
		}
	}

	if _, ok := FindServiceByName(services, models.SERVICENAME_NPCF_SMPOLICYCONTROL); ok {
		t.Fatalf("expected no match for a service name absent from the map")
	}
}
