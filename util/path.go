// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

//+build !debug

package util

import (
	"github.com/free5gc/path_util"
)

var (
	SmfLogPath           = path_util.Free5gcPath("free5gc/smfsslkey.log")
	SmfPemPath           = path_util.Free5gcPath("free5gc/support/TLS/smf.pem")
	SmfKeyPath           = path_util.Free5gcPath("free5gc/support/TLS/smf.key")
	DefaultSmfConfigPath = path_util.Free5gcPath("free5gc/config/smfcfg.yaml")
)
