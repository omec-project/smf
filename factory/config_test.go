// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package factory

import (
	"fmt"
	"testing"

	protos "github.com/omec-project/config5g/proto/sdcoreConfig"
	"github.com/omec-project/openapi/models"
)

func TestUpdateSliceInfo(t *testing.T) {
	cfg1 := Configuration{}
	cfg2 := Configuration{}

	cfg1.parseRocConfig(makeDummyConfig("1", "010203"))
	cfg2.parseRocConfig(makeDummyConfig("2", "010203"))

	compareAndProcessConfigs(&cfg1, &cfg2)
}

func makeDummyConfig(sst, sd string) *protos.NetworkSliceResponse {
	var rsp protos.NetworkSliceResponse

	rsp.NetworkSlice = make([]*protos.NetworkSlice, 0)

	ns := protos.NetworkSlice{Name: "Enterprise-1"}
	slice := protos.NSSAI{Sst: sst, Sd: sd}
	ns.Nssai = &slice

	upf := protos.UpfInfo{UpfName: "upf", UpfPort: 8805}
	site := protos.SiteInfo{SiteName: "siteOne", Upf: &upf, Gnb: make([]*protos.GNodeB, 0)}
	gNb := protos.GNodeB{Name: "gnb"}
	site.Gnb = append(site.Gnb, &gNb)
	ns.Site = &site

	ns.DeviceGroup = make([]*protos.DeviceGroup, 0)
	ipDomain := protos.IpDomain{DnnName: "internet", UePool: "60.60.0.0/16", DnsPrimary: "8.8.8.8", Mtu: 1400}
	devGrp := protos.DeviceGroup{IpDomainDetails: &ipDomain}
	ns.DeviceGroup = append(ns.DeviceGroup, &devGrp)

	rsp.NetworkSlice = append(rsp.NetworkSlice, &ns)
	return &rsp
}

func TestCompareSliceConfig(t *testing.T) {
	sNssai1 := models.Snssai{Sst: 1, Sd: "010203"}
	sNssai2 := models.Snssai{Sst: 1, Sd: "010203"}

	dnnInfo1 := SnssaiDnnInfoItem{Dnn: "DNN1", UESubnet: "10.10.0.0/16", DNS: DNS{IPv4Addr: "1.1.1.1"}}
	dnnInfo2 := SnssaiDnnInfoItem{Dnn: "DNN2", UESubnet: "10.10.0.0/16", DNS: DNS{IPv4Addr: "1.1.1.1"}}
	dnnInfo3 := SnssaiDnnInfoItem{Dnn: "DNN1", UESubnet: "10.10.0.0/16", DNS: DNS{IPv4Addr: "1.1.1.1"}}
	dnnInfo4 := SnssaiDnnInfoItem{Dnn: "DNN2", UESubnet: "10.10.0.0/16", DNS: DNS{IPv4Addr: "1.1.1.1"}}

	sNssaiInfoItem1 := SnssaiInfoItem{SNssai: &sNssai1, DnnInfos: make([]SnssaiDnnInfoItem, 0)}
	sNssaiInfoItem1.DnnInfos = append(sNssaiInfoItem1.DnnInfos, dnnInfo1, dnnInfo2)
	slice1 := []SnssaiInfoItem{sNssaiInfoItem1}

	sNssaiInfoItem2 := SnssaiInfoItem{SNssai: &sNssai2, DnnInfos: make([]SnssaiDnnInfoItem, 0)}
	sNssaiInfoItem2.DnnInfos = append(sNssaiInfoItem2.DnnInfos, dnnInfo4, dnnInfo3)
	slice2 := []SnssaiInfoItem{sNssaiInfoItem2}

	if match, add, mod, del := compareNetworkSlices(slice1, slice2); match {
		fmt.Println("The Slices are Equal")
	} else {
		fmt.Println("The Slices are Unequal ")
		fmt.Println("slices added", add)
		fmt.Println("slices modified ", mod)
		fmt.Println("slices deleted ", del)
	}
}

func TestCompareUPNodesConfigs(t *testing.T) {
	u1 := UPNode{
		Type:                 "UPF",
		NodeID:               "u1.abc.def.com",
		SNssaiInfos:          make([]models.SnssaiUpfInfoItem, 0), //[]models.SnssaiUpfInfoItem `yaml:"sNssaiUpfInfos,omitempty"`
		InterfaceUpfInfoList: make([]InterfaceUpfInfoItem, 0),     //[]InterfaceUpfInfoItem,
	}
	slice1 := models.Snssai{Sst: 1, Sd: "010203"}
	slice2 := models.Snssai{Sst: 2, Sd: "020203"}
	sn1 := models.SnssaiUpfInfoItem{SNssai: &slice1, DnnUpfInfoList: make([]models.DnnUpfInfoItem, 0)}
	sn2 := models.SnssaiUpfInfoItem{SNssai: &slice2, DnnUpfInfoList: make([]models.DnnUpfInfoItem, 0)}
	dnn1 := models.DnnUpfInfoItem{Dnn: "DNN1"}
	dnn11 := models.DnnUpfInfoItem{Dnn: "DNN11"}
	dnn2 := models.DnnUpfInfoItem{Dnn: "DNN2"}
	dnn21 := models.DnnUpfInfoItem{Dnn: "DNN21"}

	sn1.DnnUpfInfoList = append(sn1.DnnUpfInfoList, dnn1, dnn11)
	sn2.DnnUpfInfoList = append(sn2.DnnUpfInfoList, dnn2, dnn21)
	u1.SNssaiInfos = []models.SnssaiUpfInfoItem{sn1, sn2}

	u2 := UPNode{
		Type:                 "UPF",
		NodeID:               "u2.abc.def.com",
		SNssaiInfos:          make([]models.SnssaiUpfInfoItem, 0), //[]models.SnssaiUpfInfoItem `yaml:"sNssaiUpfInfos,omitempty"`
		InterfaceUpfInfoList: make([]InterfaceUpfInfoItem, 0),     //[]InterfaceUpfInfoItem,
	}
	slice3 := models.Snssai{Sst: 1, Sd: "010203"}
	slice4 := models.Snssai{Sst: 2, Sd: "020203"}
	sn3 := models.SnssaiUpfInfoItem{SNssai: &slice3, DnnUpfInfoList: make([]models.DnnUpfInfoItem, 0)}
	sn4 := models.SnssaiUpfInfoItem{SNssai: &slice4, DnnUpfInfoList: make([]models.DnnUpfInfoItem, 0)}
	dnn3 := models.DnnUpfInfoItem{Dnn: "DNN1"}
	dnn31 := models.DnnUpfInfoItem{Dnn: "DNN11"}
	dnn4 := models.DnnUpfInfoItem{Dnn: "DNN2"}
	dnn41 := models.DnnUpfInfoItem{Dnn: "DNN21"}

	sn1.DnnUpfInfoList = append(sn1.DnnUpfInfoList, dnn3, dnn31)
	sn2.DnnUpfInfoList = append(sn2.DnnUpfInfoList, dnn4, dnn41)
	u2.SNssaiInfos = []models.SnssaiUpfInfoItem{sn3, sn4}

	up1, up2 := make(map[string]UPNode), make(map[string]UPNode)

	up1["u1"] = u1
	up2["u2"] = u2
	match, add, mod, del := compareUPNodesConfigs(up1, up2)

	if !match {
		fmt.Printf("UPF config mismatch, to be added [%+v]\n", add)
		fmt.Printf("UPF config mismatch, to be modified [%+v]\n", mod)
		fmt.Printf("UPF config mismatch, to be deleted [%+v]\n", del)
	} else {
		fmt.Println("UPF config match")
	}
}

func TestCompareGenericSlices(t *testing.T) {
	l1 := UPLink{A: "gnb", B: "upf1"}
	l2 := UPLink{A: "gnb", B: "upf2"}
	l3 := UPLink{A: "gnb", B: "upf3"}
	l4 := UPLink{A: "gnb", B: "upf2"}

	match, addLinks, delLinks := compareGenericSlices([]UPLink{l1, l2}, []UPLink{l3, l4}, compareUPLinks)
	if !match {
		fmt.Printf("Generic, The Links mismatch, add[%v] and del[%v]\n", addLinks.([]UPLink), delLinks)
	} else {
		fmt.Println("Generic, The Links match")
	}
}

func TestKafkaEnabledByDefault(t *testing.T) {
	err := InitConfigFactory("../config/smfcfg.yaml")
	if err != nil {
		t.Errorf("Could not load default configuration file: %v", err)
	}
	if *SmfConfig.Configuration.KafkaInfo.EnableKafka != true {
		t.Errorf("Expected Kafka to be enabled by default, was disabled")
	}
}
