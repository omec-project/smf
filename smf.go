// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

/*
 * Nsmf_PDUSession
 *
 * SMF PDU Session Service
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package main

import (
	"fmt"
	"os"

	"github.com/omec-project/smf/logger"
	"github.com/omec-project/smf/service"
	"github.com/urfave/cli"
)

var SMF = &service.SMF{}

func main() {
	app := cli.NewApp()
	app.Name = "smf"
	logger.AppLog.Infoln(app.Name)
	app.Usage = "Session Management Function"
	app.UsageText = "smf -cfg <smf_config_file.conf> -uerouting <uerouting_config_file.conf>"
	app.Action = action
	app.Flags = SMF.GetCliCmd()

	if err := app.Run(os.Args); err != nil {
		logger.AppLog.Fatalf("SMF run error: %v", err)
	}
}

func action(c *cli.Context) error {
	if err := SMF.Initialize(c); err != nil {
		logger.CfgLog.Errorf("%+v", err)
		return fmt.Errorf("failed to initialize")
	}

	SMF.Start()

	return nil
}
