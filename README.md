<!--
SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
Copyright 2019 free5GC.org

SPDX-License-Identifier: Apache-2.0

-->

# SMF

SMF is a session management function in 5G architecture and acts as the anchor point to communicate with UPF (User Plane Function).  SD-Core SMF supports interaction with multiple UPFs. SMF supports handling dynamic slice configuration, removal & modification.


## SMF Block diagram

![SMF Architecture](/docs/images/README-SMF.png)

SMF has configuration interface to handle slice configuration. Config service is realised using the project - Config Service.  SMF exports  metrics to prometheus. 

## Supported Features
1. Supports PDU Session Establishment, Modification, Release
2. N2/X2 handover
3. End Marker Indication to UPF
4. PfcpSessionReport
5. N1N2MessageTransferFailureNotification handling Callback handling 
6. Slice based UPF selection 
7. UE address pool per Slice
8. PFCP heartbeat towards UPF

## SMF supports wide range of error handling, 
this includes some of the handling as listed below
1. UPF Reconnect if UPF restarts
2. PFCP Heartbeat handling towards UPF
3. PFCP Transaction timeout and not to wait forever 
4. SBI message timeout handling and handling timeouts
5. Registration towards NRF with updated configuration. 
6. Retrying NRF registration if NRF is not available.

## Upcoming features in SMF

1. QoS  call flows in SMF to handle PCC rules in Create Session Policy Response 
   and installing those rules in UPF & UE
2. Handling notify message from PCF
3. UPF address allocation support
4. New Metric export architecture suitable for cloud native architecture


Compliance of the 5G Network functions can be found at [5G Compliance ](https://docs.sd-core.opennetworking.org/master/overview/3gpp-compliance-5g.html)

## How to use SMF

1. Use helm charts to install SMF OR
2. Use AIAB to try out 5G network functions in single node Kubernetes cluster. [Refer AIAB Guide](https://docs.sd-core.opennetworking.org/master/developer/aiab.html) 




## Reach out to us thorugh 

1. #sdcore-dev channel in [ONF Community Slack](https://onf-community.slack.com/)
2. Raise Github issues

