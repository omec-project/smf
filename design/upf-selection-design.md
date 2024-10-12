// Copyright (c) 2024 https://www.cdac.in All rights reserved.
// SPDX-License-Identifier: Apache-2.0

# UPF Selection Design for Multiple DNNs

## 1. Introduction
- **Objective:** Modify the SMF to support UPF selection based on DNN and Slice ID. Each UPF will support only one DNN, and the SMF will maintain a list of UPFs to select from based on the DNN and Slice ID provided in the PDU session request. The system will ensure precise routing by associating each DNN with a specific UPF.

## 2. Discussion Points

### 2.1. DNN: `internet`
- **Status:** Successfully connected.

#### Example of current sdcore-5g-values.yaml configuration:

device-groups:
  - name: "5g-gnbsim-user-group1"
    imsis:
      - "001010000000001"
      - "001010000000002"
      - "001010000000003"
      - "001010000000005"
      - "001010000000008"
      - "001010000000009"
    ip-domain-name: "pool1"
    ip-domain-expanded:
      dnn: internet
      dns-primary: "10.176.0.11"        # Value sent to UE
      mtu: 1460                        # Value sent to UE when PDU Session Established
      ue-ip-pool: "172.250.1.0/24"     # IP address pool for subscribers
      ue-dnn-qos:
        dnn-mbr-downlink: 1000         # UE level downlink QoS (Maximum bit rate per UE)
        dnn-mbr-uplink: 1000           # UE level uplink QoS (Maximum bit rate per UE)
        bitrate-unit: Mbps             # Unit for above QoS rates
        traffic-class:                 # Default bearer QCI/ARP (not used in 5G)
          name: "platinum"
          qci: 9
          arp: 6
          pdb: 300
          pelr: 6
    site-info: "enterprise"
 network-slices:
            - name: "default"      # can be any unique slice name
              slice-id:            # must match with slice configured in gNB, UE
                sd: "000000"
                sst: 1
              site-device-group:
              - "5g-gnbsim-user-group1"   # All UEs in this device-group are assigned to this slice
              # Applicaiton filters control what each user can access.
              # Default, allow access to all applications
              application-filtering-rules:
              - rule-name: "ALLOW-ALL"
                priority: 250
                action: "permit"
                endpoint: "0.0.0.0/0"
              site-info:
                # Provide gNBs and UPF details and also PLMN for the site
                gNodeBs:
                - name: "gnb1"
                  tac: 1
                - name: "gnb2"
                  tac: 2
                plmn:
                  mcc: "001"
                  mnc: "01"
                site-name: "enterprise"
                upf:
                  upf-name: "upf"  # associated UPF for this slice. One UPF per Slice.
                  upf-port: 8805

**Current Behavior:** The SMF selects UPF based on a simple mapping of DNN to UPF. For the `internet` DNN, the current configuration successfully establishes a PDU session.

**Limitation:** This configuration does not handle scenarios where the same device must be part of multiple device groups with different DNNs but the same Slice ID. For example, the SMF fails to select the appropriate UPF for the `sdcore` DNN, resulting in a selection failure.

### 2.2. DNN: `sdcore`
- **Issue:** SMF selection failure occurred.

#### Here's an example of the intended sdcore-5g-values.yaml configuration for the `sdcore` DNN:

device-groups:
  - name: "5g-gnbsim-user-group1"
    imsis:
      - "001010000000001"
      - "001010000000002"
      - "001010000000003"
      - "001010000000005"
      - "001010000000008"
      - "001010000000009"
    ip-domain-name: "pool1"
    ip-domain-expanded:
      dnn: internet
      dns-primary: "10.176.0.11"        # Value sent to UE
      mtu: 1460                        # Value sent to UE when PDU Session Established
      ue-ip-pool: "172.250.1.0/24"     # IP address pool for subscribers
      ue-dnn-qos:
        dnn-mbr-downlink: 1000         # UE level downlink QoS (Maximum bit rate per UE)
        dnn-mbr-uplink: 1000           # UE level uplink QoS (Maximum bit rate per UE)
        bitrate-unit: Mbps             # Unit for above QoS rates
        traffic-class:                 # Default bearer QCI/ARP (not used in 5G)
          name: "platinum"
          qci: 9
          arp: 6
          pdb: 300
          pelr: 6
    site-info: "enterprise"
  - name: "5g-gnbsim-user-group2"
    imsis:
      - "001010000000001"
      - "001010000000002"
      - "001010000000003"
      - "001010000000005"
      - "001010000000008"
      - "001010000000009"
    ip-domain-name: "pool2"
    ip-domain-expanded:
      dnn: sdcore
      dns-primary: "10.176.0.11"        # Value sent to UE
      mtu: 1460                        # Value sent to UE when PDU Session Established
      ue-ip-pool: "172.252.2.0/24"     # IP address pool for subscribers
      ue-dnn-qos:
        dnn-mbr-downlink: 1000         # UE level downlink QoS (Maximum bit rate per UE)
        dnn-mbr-uplink: 1000           # UE level uplink QoS (Maximum bit rate per UE)
        bitrate-unit: Mbps             # Unit for above QoS rates
        traffic-class:                 # Default bearer QCI/ARP (not used in 5G)
          name: "platinum"
          qci: 9
          arp: 6
          pdb: 300
          pelr: 6
    site-info: "enterprise"
 network-slices:
            - name: "default"      # can be any unique slice name
              slice-id:            # must match with slice configured in gNB, UE
                sd: "000000"
                sst: 1
              site-device-group:
              - "5g-gnbsim-user-group1"   # All UEs in this device-group are assigned to this slice
              - "5g-gnbsim-user-group2"   # All UEs in this device-group are assigned to this slice
              
              # Applicaiton filters control what each user can access.
              # Default, allow access to all applications
              application-filtering-rules:
              - rule-name: "ALLOW-ALL"
                priority: 250
                action: "permit"
                endpoint: "0.0.0.0/0"
              site-info:
                # Provide gNBs and UPF details and also PLMN for the site
                gNodeBs:
                - name: "gnb1"
                  tac: 1
                - name: "gnb2"
                  tac: 2
                plmn:
                  mcc: "001"
                  mnc: "01"
                site-name: "enterprise"
                upfs:   # List of UPFs, each with a unique DNN
                - upf-name: "upf-1"  
                  upf-port: 8805
                - upf-name: "upf-2"  
                  upf-port: 8805
      
    **Intended Behavior:** The new design aims to enhance the SMF logic to support UPF selection based on both DNN and Slice ID. This improvement will enable the SMF to correctly handle multiple DNNs within the same Slice ID, ensuring accurate UPF selection and preventing issues like the current failure with the `sdcore` DNN.

## 3. Proposed Changes

### 3.1. SMF Changes

- **Objectives:**
  - Refactor the SMF to ensure that the UPF selection process accurately considers both the DNN and Slice ID parameters.

- **Action Steps:**
  - **Code Identification:** Locate the exact portion of the SMF codebase where the UPF selection logic is implemented.
  - **Logic Enhancement:** Modify the existing logic to incorporate DNN and Slice ID as key criteria in UPF selection.
  - **PFCP Session Updates:** Update the SMF's PFCP session handling logic to include DNN information, ensuring compatibility with the new selection criteria.

- **Expected Outcome:** By making these changes, the SMF will be able to accurately select the appropriate UPF based on the DNN and Slice ID, resolving issues like the one observed with the sdcore DNN.

### 3.2. UPF Changes
- **PFCP Association:**
  - PFCP association should now send a list of supported DNNs.
  - UPF should send back both DNNs during a new PFCP association.
  - Each DNN should have its own set of UE IPs, ensuring proper IP assignment based on the DNN selected during session establishment.
  - Currently, the system only supports single DNN. Future changes will include extending support to handle multiple DNNs with distinct UE IP pools.
  - Use DNN as an additional key when processing PFCP session additions to map the correct DNN and UE IPs.
  
## 4. Next Steps
- **Documentation:** Continue documenting design thoughts.
- **Implementation:** Start implementing the changes in SMF and UPF.

## 5. References
- **3GPP TS 29.244**: Refer to this specification for PFCP details.
