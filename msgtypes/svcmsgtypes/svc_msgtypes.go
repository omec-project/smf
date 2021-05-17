package svcmsgtypes

// List of Msgs
const (

	//N11 Service
	MsgTypeNone                         string = "none"
	NsmfPDUSessionCreateSmContext       string = "CreateSmContext"
	NsmfPDUSessionUpdateSmContext       string = "UpdateSmContext"
	NsmfPDUSessionReleaseSmContext      string = "ReleaseSmContext"
	NsmfPDUSessionNotifySmContextStatus string = "NotifySmContextStatus"
	NsmfPDUSessionRetrieveSmContext     string = "RetrieveSmContext"
	NsmfPDUSessionCreate                string = "Create"  //Create a PDU session in the H-SMF
	NsmfPDUSessionUpdate                string = "Update"  //Update a PDU session in the H-SMF or V- SMF
	NsmfPDUSessionRelease               string = "Release" //Release a PDU session in the H-SMF

	//NNRF_NFManagement
	NnrfNFRegister           string = "NfRegister"
	NnrfNFDeRegister         string = "NfDeRegister"
	NnrfNFInstanceDeRegister string = "NnrfNFInstanceDeRegister"
	NnrfNFDiscoveryUdm       string = "NfDiscoveryUdm"
	NnrfNFDiscoveryPcf       string = "NfDiscoveryPcf"
	NnrfNFDiscoveryAmf       string = "NfDiscoveryAmf"

	//NUDM_
	NudmSmSubscriptionDataRetrieval string = "NudmSmSubscriptionDataRetrieval"

	//NPCF_
	NpcfSmPolicyAssociationCreate string = "NpcfSmPolicyAssociationCreate"
	//AMF_
)
