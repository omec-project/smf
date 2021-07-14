# SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
#
# SPDX-License-Identifier: Apache-2.0
# SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
#
# smf

The repository contains changes for SMF NF.

1. To clone the repository
  "git clone --branch onf-release3.0.5 https://github.com/omec-project/smf.git --recursive"

2. To run SMF app in binary mode
  "./smf -smfcfg config/smfcfg.yaml -uerouting config/uerouting.yaml"

3. To make docker build
  "make docker-build -f Makefile_docker"
