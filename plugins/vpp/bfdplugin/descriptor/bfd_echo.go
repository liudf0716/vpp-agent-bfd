//  Copyright (c) 2021 .
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at:
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package descriptor

import (
	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	"go.ligato.io/cn-infra/v2/logging"

	"go.ligato.io/vpp-agent/v3/plugins/vpp/bfdplugin/descriptor/adapter"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/bfdplugin/vppcalls"
	vpp_ifdescriptor "go.ligato.io/vpp-agent/v3/plugins/vpp/ifplugin/descriptor"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/ifplugin/ifaceidx"
	bfd "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/bfd"
)

const (
	// BfdEchoDescriptorName is descriptor name
	BfdEchoDescriptorName = "vpp-bfd-echo"
)

type BfdEchoDescriptor struct {
	log        logging.Logger
	bfdHandler vppcalls.BFDVppAPI
	ifIndex    ifaceidx.IfaceMetadataIndex
}

// NewBFDDescriptor is constructor for BFD descriptor
func NewBfdEchoDescriptor(bfdHandler vppcalls.BFDVppAPI, ifIndex ifaceidx.IfaceMetadataIndex,
	logger logging.PluginLogger) *BfdEchoDescriptor {
	return &BfdEchoDescriptor{
		log:        logger.NewLogger("bfdEcho-descriptor"),
		bfdHandler: bfdHandler,
		ifIndex:    ifIndex,
	}
}

// GetDescriptor returns descriptor suitable for registration (via adapter) with
// the KVScheduler.
func (d *BfdEchoDescriptor) GetDescriptor() *adapter.BfdEchoDescriptor {
	return &adapter.BfdEchoDescriptor{
		Name:                 BfdEchoDescriptorName,
		NBKeyPrefix:          bfd.ModelEchoFunction.KeyPrefix(),
		ValueTypeName:        bfd.ModelEchoFunction.ProtoName(),
		KeySelector:          bfd.ModelEchoFunction.IsKeyValid,
		KeyLabel:             bfd.ModelEchoFunction.StripKeyPrefix,
		ValueComparator:      d.EquivalentBfdEcho,
		Validate:             d.Validate,
		Create:               d.Create,
		Delete:               d.Delete,
		Retrieve:             d.Retrieve,
		RetrieveDependencies: []string{vpp_ifdescriptor.InterfaceDescriptorName},
	}
}

func (d *BfdEchoDescriptor) EquivalentBfdEcho(key string, oldBfdEcho, newBfdEcho *bfd.EchoFunction) bool {
	return proto.Equal(oldBfdEcho, newBfdEcho)
}

func (d *BfdEchoDescriptor) Validate(key string, bfdEcho *bfd.EchoFunction) (err error) {
	// Verify interface presence
	_, found := d.ifIndex.LookupByName(bfdEcho.EchoSourceInterface)
	if !found {
		return errors.Errorf("failed to find interface %s", bfdEcho.EchoSourceInterface)
	}

	return nil
}

func (d *BfdEchoDescriptor) Create(key string, bfd *bfd.EchoFunction) (interface{}, error) {
	fromIfaceMeta, _ := d.ifIndex.LookupByName(bfd.EchoSourceInterface)
	err := d.bfdHandler.AddBfdUDPEchoFunction(bfd, fromIfaceMeta.SwIfIndex)
	return nil, err
}

func (d *BfdEchoDescriptor) Delete(key string, bfd *bfd.EchoFunction, metadata interface{}) error {
	return d.bfdHandler.DeleteBfdUDPEchoFunction()
}

// Retrieve returns list of configured BFDs with metadata
func (d *BfdEchoDescriptor) Retrieve(corrlate []adapter.BfdEchoKVWithMetadata) (bfds []adapter.BfdEchoKVWithMetadata, err error) {
	return
}
