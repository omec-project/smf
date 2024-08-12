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

- **Objectives:**
  - Refactor the SMF to ensure that the UPF selection process accurately considers both the DNN and Slice ID parameters.
- **Action Steps:**
  - **Code Identification:** Locate the exact portion of the SMF codebase where the UPF selection logic is implemented.
  - **Logic Enhancement:** Modify the existing logic to incorporate DNN and Slice ID as key criteria in UPF selection.
  - **PFCP Session Updates:** Update the SMF's PFCP session handling logic to include DNN information, ensuring compatibility with the new selection criteria.
- **Expected Outcome:** By making these changes, the SMF will be able to accurately select the appropriate UPF based on the DNN and Slice ID, resolving issues like the one observed with the sdcore DNN.

### 3.2. UPF Changes
- **PFCP Association:**
  - UPF should send back both DNNs during a new PFCP association.
  - Use DNN as an additional key when processing PFCP session additions.

## 4. Next Steps
- **Documentation:** Continue documenting design thoughts.
- **Implementation:** Start implementing the changes in SMF and UPF.

## 5. References
- **3GPP TS 29.244**: Refer to this specification for PFCP details.
