// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package oam

import (
	"github.com/gin-gonic/gin"
	"github.com/omec-project/smf/producer"
	"github.com/omec-project/util/httpwrapper"
)

func HTTPGetUEPDUSessionInfo(c *gin.Context) {
	req := httpwrapper.NewRequest(c.Request, nil)
	req.Params["smContextRef"] = c.Params.ByName("smContextRef")

	smContextRef := req.Params["smContextRef"]
	HTTPResponse := producer.HandleOAMGetUEPDUSessionInfo(smContextRef)

	c.JSON(HTTPResponse.Status, HTTPResponse.Body)
}
