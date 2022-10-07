<!--
SPDX-FileCopyrightText: 2022-present Intel Corporation
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
9. UE IP-Address allocation via UPF
10. QoS  call flows in SMF to handle PCC rules in Create Session Policy Response 
   and installing those rules in UPF & UE
11. High Availibilty and Cloud Native support(scale up/down number of instances and subscriber store in Database)
12. UPF-Adapter for PFCP registration of multiple SMF instances with same node-id to any UPF.
13. Keep-alive support with respect to NRF.
14. Transaction queueing for the same PDU session.


## SMF supports wide range of error handling, 
This includes some of the handling as listed below
1. UPF Reconnect if UPF restarts
2. PFCP Heartbeat handling towards UPF
3. PFCP Transaction timeout and not to wait forever 
4. SBI message timeout handling and handling timeouts
5. Registration towards NRF with updated configuration. 
6. Retrying NRF registration if NRF is not available.

## Upcoming features in SMF

1. Policy Notify from PCF for QoS update
2. New Metric export architecture suitable for cloud native architecture
3. Support Cloud Native AMF, PCF and UPF



Compliance of the 5G Network functions can be found at [5G Compliance ](https://docs.sd-core.opennetworking.org/master/overview/3gpp-compliance-5g.html)

Design section for SMF is available at [SMF Design](https://docs.sd-core.opennetworking.org/master/design/design-smf.html)

## How to use SMF

1. Use helm charts to install SMF OR
2. Use AIAB to try out 5G network functions in single node Kubernetes cluster. [Refer AIAB Guide](https://docs.sd-core.opennetworking.org/master/developer/aiab.html) 




## Reach out to us thorugh 

1. #sdcore-dev channel in [ONF Community Slack](https://onf-community.slack.com/)
2. Raise Github issues

