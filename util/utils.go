// Copyright (c) 2026 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"errors"
	"io"
	"os"
	"reflect"
	"strconv"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/smf/logger"
)

// NFProfileServices reads profile's NF services from NfServiceList, falling back to the
// deprecated NfServices slice only when the list is unset.
func NFProfileServices(profile *models.NFProfile) map[string]models.NFService {
	if list := profile.GetNfServiceList(); len(list) > 0 {
		return list
	}
	return nfServicesSliceToMap(profile.GetNfServices())
}

// NFProfileDiscoveryServices is NFProfileServices for a discovered (peer) NF profile.
func NFProfileDiscoveryServices(profile *models.NFProfileDiscovery) map[string]models.NFService {
	if list := profile.GetNfServiceList(); len(list) > 0 {
		return list
	}
	return nfServicesSliceToMap(profile.GetNfServices())
}

// nfServicesSliceToMap keys the deprecated NfServices slice by ServiceInstanceId, falling back
// to the index when it is empty, matching how NfServiceList itself is keyed.
func nfServicesSliceToMap(services []models.NFService) map[string]models.NFService {
	if len(services) == 0 {
		return nil
	}
	merged := make(map[string]models.NFService, len(services))
	for i, svc := range services {
		key := svc.GetServiceInstanceId()
		if key == "" {
			key = strconv.Itoa(i)
		}
		merged[key] = svc
	}
	return merged
}

// SetNFProfileServices writes services to both NfServiceList and the deprecated NfServices
// slice, so profile is understood by peers that still only read the old field.
// TODO: drop the NfServices write once NfServices is removed from the API.
func SetNFProfileServices(profile *models.NFProfile, services map[string]models.NFService) {
	profile.SetNfServiceList(services)
	slice := make([]models.NFService, 0, len(services))
	for _, svc := range services {
		slice = append(slice, svc)
	}
	profile.SetNfServices(slice)
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

func CleanupMultipartTempFiles(body any) {
	visited := make(map[string]struct{})
	cleanupMultipartTempFilesValue(reflect.ValueOf(body), visited)
}

func cleanupMultipartTempFilesValue(value reflect.Value, visited map[string]struct{}) {
	if !value.IsValid() {
		return
	}

	if value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return
		}
		if file, ok := value.Interface().(*os.File); ok {
			cleanupMultipartTempFile(file, visited)
			return
		}
		cleanupMultipartTempFilesValue(value.Elem(), visited)
		return
	}

	switch value.Kind() {
	case reflect.Struct:
		for idx := 0; idx < value.NumField(); idx++ {
			field := value.Type().Field(idx)
			if field.PkgPath != "" {
				continue
			}
			cleanupMultipartTempFilesValue(value.Field(idx), visited)
		}
	case reflect.Slice, reflect.Array:
		for idx := 0; idx < value.Len(); idx++ {
			cleanupMultipartTempFilesValue(value.Index(idx), visited)
		}
	case reflect.Map:
		iter := value.MapRange()
		for iter.Next() {
			cleanupMultipartTempFilesValue(iter.Value(), visited)
		}
	}
}

func cleanupMultipartTempFile(file *os.File, visited map[string]struct{}) {
	if file == nil {
		return
	}

	name := file.Name()
	if _, ok := visited[name]; ok {
		return
	}
	visited[name] = struct{}{}

	if err := file.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		logger.ConsumerLog.Errorf("temp file close failed: %+v", err)
	}
	if err := os.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		logger.ConsumerLog.Errorf("temp file remove failed: %+v", err)
	}
}
