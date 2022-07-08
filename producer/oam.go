// SPDX-FileCopyrightText: 2022-present Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"net/http"
	"strconv"

	"github.com/omec-project/http_wrapper"
	"github.com/omec-project/openapi/models"
	"github.com/omec-project/smf/context"
)

type PDUSessionInfo struct {
	Supi         string
	PDUSessionID string
	Dnn          string
	Sst          string
	Sd           string
	AnType       models.AccessType
	PDUAddress   string
	SessionRule  models.SessionRule
	UpCnxState   models.UpCnxState
	Tunnel       context.UPTunnel
}

func HandleOAMGetUEPDUSessionInfo(smContextRef string) *http_wrapper.Response {
	smContext := context.GetSMContext(smContextRef)
	if smContext == nil {
		httpResponse := &http_wrapper.Response{
			Header: nil,
			Status: http.StatusNotFound,
			Body:   nil,
		}

		return httpResponse
	}

	httpResponse := &http_wrapper.Response{
		Header: nil,
		Status: http.StatusOK,
		Body: PDUSessionInfo{
			Supi:         smContext.Supi,
			PDUSessionID: strconv.Itoa(int(smContext.PDUSessionID)),
			Dnn:          smContext.Dnn,
			Sst:          strconv.Itoa(int(smContext.Snssai.Sst)),
			Sd:           smContext.Snssai.Sd,
			AnType:       smContext.AnType,
			PDUAddress:   smContext.PDUAddress.Ip.String(),
			UpCnxState:   smContext.UpCnxState,
			// Tunnel: context.UPTunnel{
			// 	//UpfRoot:  smContext.Tunnel.UpfRoot,
			// 	ULCLRoot: smContext.Tunnel.UpfRoot,
			// },
		},
	}
	return httpResponse
}
