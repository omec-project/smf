# UPF Selection Design for Multiple DNNs

## 1. Introduction
- **Objective:** Modify the SMF to support UPF selection based on DNN and Slice ID.

## 2. Discussion Points

### 2.1. DNN: `internet`
- **Status:** Successfully connected.

### 2.2. DNN: `sdcore`
- **Issue:** SMF selection failure occurred.

## 3. Proposed Changes

### 3.1. SMF Changes
- **SMF UPF Selection Logic:**
  - Identify the code where SMF performs UPF selection.
  - Ensure SMF generates a list of UPFs based on DNN and Slice ID.
  - Modify the addition of PFCP session to include DNN information.

### 3.2. UPF Changes
- **PFCP Association:**
  - UPF should send back both DNNs during a new PFCP association.
  - Use DNN as an additional key when processing PFCP session additions.

## 4. Next Steps
- **Documentation:** Continue documenting design thoughts.
- **Implementation:** Start implementing the changes in SMF and UPF.

## 5. References
- **3GPP TS 29.244**: Refer to this specification for PFCP details.
