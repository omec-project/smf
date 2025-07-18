<!--
SPDX-FileCopyrightText: 2025 Canonical Ltd
SPDX-FileCopyrightText: 2022-present Intel Corporation
SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
Copyright 2019 free5GC.org

SPDX-License-Identifier: Apache-2.0
-->
[![Go Report Card](https://goreportcard.com/badge/github.com/omec-project/smf)](https://goreportcard.com/report/github.com/omec-project/smf)

# SMF

SMF is a session management function in 5G architecture and acts as the anchor
point to communicate with UPF (User Plane Function). SD-Core SMF supports
interaction with multiple UPFs. SMF supports handling dynamic slice
configuration, removal and modification.

Compliance of the 5G Network functions can be found at [5G Compliance](https://docs.sd-core.opennetworking.org/main/overview/3gpp-compliance-5g.html)

## SMF Block diagram

![SMF Architecture](/docs/images/README-SMF.png)

## Dynamic Network configuration (via webconsole)

SMF polls the webconsole every 5 seconds to fetch the latest SNssaiInfo and UserPlaneInformation configuration.

### Setting Up Polling

Include the `webuiUri` of the webconsole in the configuration file
```
configuration:
  ...
  webuiUri: https://webui:5001 # or http://webui:5001
  ...
```
The scheme (http:// or https://) must be explicitly specified. If no parameter is specified,
SMF will use `http://webui:5001` by default.

### HTTPS Support

If the webconsole is served over HTTPS and uses a custom or self-signed certificate,
you must install the root CA certificate into the trust store of the SMF environment.

Check the official guide for installing root CA certificates on Ubuntu:
[Install a Root CA Certificate in the Trust Store](https://documentation.ubuntu.com/server/how-to/security/install-a-root-ca-certificate-in-the-trust-store/index.html)

## Supported Features
1. Supports PDU Session Establishment, Modification, Release
2. N2/X2 handover
3. End Marker Indication to UPF
4. PfcpSessionReport
5. N1N2MessageTransferFailureNotification handling Callback handling
6. Slice based UPF selection
7. UE address pool per Slice
8. PFCP heartbeat towards UPF
9. UE IP-Address allocation via UPF
10. QoS call flows in SMF to handle PCC rules in Create Session Policy Response and installing those rules in UPF & UE
11. High Availability and Cloud Native support (scale up/down number of instances and subscriber store in Database)
12. UPF-Adapter for PFCP registration of multiple SMF instances with the same node id to any UPF
13. Keep-alive support with respect to NRF
14. Transaction queueing for the same PDU session
15. SMF metrics available via metric-func to 5g Grafana dashboard
16. Static IP-address provision via configuration

## SMF supports wide range of error handling

This includes some of the handling as listed below:
1. UPF Connection Management:
- Implements automatic UPF reconnection mechanism when UPF restarts
- Maintains PFCP heartbeat monitoring towards UPF for connection health checks
2. PFCP Protocol Handling:
- Implements transaction timeout controls to prevent indefinite wait states
- Manages PFCP session lifecycle and termination
3. Service-Based Interface (SBI) Management:
- Handles SBI message timeouts with proper error recovery
- Implements retry mechanisms for failed operations
4. NRF Integration:
- Supports dynamic registration updates with NRF
- Implements automatic retry logic for NRF registration when service is unavailable
- Maintains NRF connection through heartbeat service
5. Configuration Management:
- Implements resilient configuration polling for Webconsole config server
- Includes automatic retry mechanism for configuration service availability

## How to use SMF

Refer to the [SD-Core documentation](https://docs.sd-core.opennetworking.org/main/index.html)

## Reach out to us through

1. #sdcore-dev channel in [Aether Community Slack](https://aether5g-project.slack.com)
2. Raise Github [issues](https://github.com/omec-project/smf/issues/new)

