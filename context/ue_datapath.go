// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"fmt"
	"math"

	"github.com/omec-project/smf/factory"
	"github.com/omec-project/smf/logger"
	"github.com/omec-project/util/idgenerator"
)

type UEPreConfigPaths struct {
	DataPathPool    DataPathPool
	PathIDGenerator *idgenerator.IDGenerator
}

func NewUEDataPathNode(name string) (node *DataPathNode, err error) {
	if smfContext.UserPlaneInformation == nil {
		return nil, fmt.Errorf("smfContext.UserPlaneInformation is nil")
	}
	upNodes := smfContext.UserPlaneInformation.UPNodes

	if _, exist := upNodes[name]; !exist {
		err = fmt.Errorf("upNode %s isn't exist in smfcfg.yaml, but in UERouting.yaml", name)
		return nil, err
	}

	node = &DataPathNode{
		UPF:            upNodes[name].UPF,
		UpLinkTunnel:   &GTPTunnel{},
		DownLinkTunnel: &GTPTunnel{},
	}
	return
}

func NewUEPreConfigPaths(supi string, paths []factory.Path) (*UEPreConfigPaths, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("no paths provided for SUPI: %s", supi)
	}

	logger.PduSessLog.Infof("Initializing UEPreConfigPaths for SUPI: %s", supi)

	// create a new path ID generator
	pathIDGenerator := idgenerator.NewGenerator(1, math.MaxInt32)

	dataPathPool := NewDataPathPool()

	for idx, pathCfg := range paths {
		dataPath := NewDataPath()

		if idx == 0 {
			dataPath.IsDefaultPath = true
		}
		// allocate a unique path ID
		pathID, err := pathIDGenerator.Allocate()
		if err != nil {
			return nil, fmt.Errorf("failed to allocate path ID for SUPI %s: %w", supi, err)
		}
		dataPath.Destination.DestinationIP = pathCfg.DestinationIP
		dataPath.Destination.DestinationPort = pathCfg.DestinationPort
		var parentNode *DataPathNode
		for upfIdx, nodeName := range pathCfg.UPF {
			newUeNode, err := NewUEDataPathNode(nodeName)
			if err != nil {
				return nil, fmt.Errorf("failed to create DataPathNode %s for SUPI %s: %w", nodeName, supi, err)
			}

			if upfIdx == 0 {
				dataPath.FirstDPNode = newUeNode
			}
			if parentNode != nil {
				newUeNode.AddPrev(parentNode)
				parentNode.AddNext(newUeNode)
			}
			parentNode = newUeNode
		}

		logger.CtxLog.Debugf("added preconfig data path (pathID=%d) for SUPI %s: %s", pathID, supi, dataPath.String())
		dataPathPool[pathID] = dataPath
	}

	return &UEPreConfigPaths{
		DataPathPool:    dataPathPool,
		PathIDGenerator: pathIDGenerator,
	}, nil
}
