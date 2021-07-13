// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0

package context

import (
	"net"

	"github.com/free5gc/smf/factory"
	"github.com/free5gc/smf/logger"
)

func SetupSMFContext(config *factory.Config) error {
	return nil
}

func (c *SMFContext) insertSmfNssaiInfo(snssaiInfoConfig *factory.SnssaiInfoItem) error {

	if smfContext.SnssaiInfos == nil {
		c.SnssaiInfos = make([]SnssaiSmfInfo, 0)
	}

	snssaiInfo := SnssaiSmfInfo{}
	snssaiInfo.Snssai = SNssai{
		Sst: snssaiInfoConfig.SNssai.Sst,
		Sd:  snssaiInfoConfig.SNssai.Sd,
	}

	snssaiInfo.DnnInfos = make(map[string]*SnssaiSmfDnnInfo)

	for _, dnnInfoConfig := range snssaiInfoConfig.DnnInfos {
		dnnInfo := SnssaiSmfDnnInfo{}
		dnnInfo.DNS.IPv4Addr = net.ParseIP(dnnInfoConfig.DNS.IPv4Addr).To4()
		dnnInfo.DNS.IPv6Addr = net.ParseIP(dnnInfoConfig.DNS.IPv6Addr).To4()
		if allocator, err := NewIPAllocator(dnnInfoConfig.UESubnet); err != nil {
			logger.InitLog.Errorf("create ip allocator[%s] failed: %s", dnnInfoConfig.UESubnet, err)
			continue
		} else {
			dnnInfo.UeIPAllocator = allocator
		}
		snssaiInfo.DnnInfos[dnnInfoConfig.Dnn] = &dnnInfo
	}
	c.SnssaiInfos = append(c.SnssaiInfos, snssaiInfo)

	//TODO: Update to other SMF structure also required
	//check init config code

	return nil
}

func (c *SMFContext) updateSmfNssaiInfo(newSlice *factory.SnssaiInfoItem) error {
	//identify slices to be updated

	c.deleteSmfNssaiInfo(newSlice)
	c.insertSmfNssaiInfo(newSlice)

	return nil
}

func (c *SMFContext) deleteSmfNssaiInfo(delSliceInfo *factory.SnssaiInfoItem) error {

	for index, slice := range c.SnssaiInfos {
		if slice.Snssai.Sd == delSliceInfo.SNssai.Sd && slice.Snssai.Sst == delSliceInfo.SNssai.Sst {
			//Remove the desired slice
			c.SnssaiInfos = append(c.SnssaiInfos[:index], c.SnssaiInfos[index+1:]...)
		}
	}
	return nil
}
