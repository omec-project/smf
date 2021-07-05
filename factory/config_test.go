package factory

import (
	"testing"

	protos "github.com/omec-project/config5g/proto/sdcoreConfig"
)

func TestUpdateSliceInfo(t *testing.T) {

	cfg := Configuration{}
	SmfConfig = Config{Configuration: &cfg}

	err := SmfConfig.updateSmfConfig(makeDummyConfig())
	if err != nil {
		t.Errorf("Test Update config failed: %v", err.Error())
	}
}

//For
func makeDummyConfig() *protos.NetworkSliceResponse {
	var rsp protos.NetworkSliceResponse

	rsp.NetworkSlice = make([]*protos.NetworkSlice, 0)

	ns := protos.NetworkSlice{}
	slice := protos.NSSAI{Sst: "1", Sd: "010203"}
	ns.Nssai = &slice

	upf := protos.UpfInfo{UpfName: "upf", UpfPort: 8805}
	site := protos.SiteInfo{SiteName: "siteOne", Upf: &upf, Gnb: make([]*protos.GNodeB, 0)}
	gNb := protos.GNodeB{Name: "gnb"}
	site.Gnb = append(site.Gnb, &gNb)
	ns.Site = &site

	ns.DeviceGroup = make([]*protos.DeviceGroup, 0)
	ipDomain := protos.IpDomain{DnnName: "internet", UePool: "60.60.0.0/16", DnsPrimary: "8.8.8.8"}
	devGrp := protos.DeviceGroup{IpDomainDetails: &ipDomain}
	ns.DeviceGroup = append(ns.DeviceGroup, &devGrp)

	rsp.NetworkSlice = append(rsp.NetworkSlice, &ns)
	return &rsp
}
