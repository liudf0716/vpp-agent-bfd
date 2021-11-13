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
	"context"
	"sync"

	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	"go.ligato.io/cn-infra/v2/logging"

	"go.ligato.io/vpp-agent/v3/plugins/kvscheduler/api"
	kvs "go.ligato.io/vpp-agent/v3/plugins/kvscheduler/api"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/bfdplugin/descriptor/adapter"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/bfdplugin/vppcalls"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/ifplugin/ifaceidx"
	bfd "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/bfd"
)

const (
	// BFDDescriptorName is descriptor name
	BFDDescriptorName = "vpp-bfd"
)

type BFDDescriptor struct {
	log         logging.Logger
	bfdHandler  vppcalls.BFDVppAPI
	kvscheduler kvs.KVScheduler
	ifIndex     ifaceidx.IfaceMetadataIndex

	// BFD notification watching
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewBFDDescriptor is constructor for BFD descriptor
func NewBFDDescriptor(bfdHandler vppcalls.BFDVppAPI, kvscheduler kvs.KVScheduler, ifIndex ifaceidx.IfaceMetadataIndex,
	logger logging.PluginLogger) *BFDDescriptor {
	return &BFDDescriptor{
		log:         logger.NewLogger("bfd-descriptor"),
		bfdHandler:  bfdHandler,
		kvscheduler: kvscheduler,
		ifIndex:     ifIndex,
	}
}

// WatchBFDNotifications starts watching for BFD notifications.
func (d *BFDDescriptor) WatchBFDNotifications(ctx context.Context) {
	var childCtx context.Context
	childCtx, d.cancel = context.WithCancel(ctx)

	d.wg.Add(1)
	go d.watchBFDNotifications(childCtx)
}

// Close stops watching of BFD notifications.
func (d *BFDDescriptor) Close() error {
	d.cancel()
	d.wg.Wait()
	return nil
}

// GetDescriptor returns descriptor suitable for registration (via adapter) with
// the KVScheduler.
func (d *BFDDescriptor) GetDescriptor() *adapter.BFDDescriptor {
	return &adapter.BFDDescriptor{
		Name:            BFDDescriptorName,
		NBKeyPrefix:     bfd.ModelBFD.KeyPrefix(),
		ValueTypeName:   bfd.ModelBFD.ProtoName(),
		KeySelector:     bfd.ModelBFD.IsKeyValid,
		KeyLabel:        bfd.ModelBFD.StripKeyPrefix,
		ValueComparator: d.EquivalentBFDs,
		WithMetadata:    true,
		Create:          d.Create,
		Delete:          d.Delete,
		DerivedValues:   d.DerivedValues,
	}
}

func (d *BFDDescriptor) EquivalentBFDs(key string, oldBFD, newBFD *bfd.SingleHopBFD_Session) bool {
	return proto.Equal(oldBFD, newBFD)
}

func (d *BFDDescriptor) Create(key string, bfdInput *bfd.SingleHopBFD_Session) (interface{}, error) {
	// Verify interface presence
	fromIfaceMeta, found := d.ifIndex.LookupByName(bfdInput.Interface)
	if !found {
		return nil, errors.Errorf("failed to find interface %s", bfdInput.Interface)
	}

	ifIdx := fromIfaceMeta.SwIfIndex

	// Call vpp api
	err := d.bfdHandler.AddBfdUDPSession(bfdInput, ifIdx)
	if err != nil {
		return nil, errors.Errorf("failed to configure BFD UDP session for interface %s: %v", bfdInput.Interface, err)
	}

	d.log.Infof("BFD session for interface %s configured ", bfdInput.Interface)

	return nil, nil
}

func (d *BFDDescriptor) Delete(key string, bfdInput *bfd.SingleHopBFD_Session, metadata interface{}) error {
	// Verify interface presence
	fromIfaceMeta, found := d.ifIndex.LookupByName(bfdInput.Interface)
	if !found {
		return errors.Errorf("failed to find interface %s", bfdInput.Interface)
	}

	ifIdx := fromIfaceMeta.SwIfIndex

	err := d.bfdHandler.DeleteBfdUDPSession(ifIdx, bfdInput.SourceAddress, bfdInput.DestinationAddress)
	if err != nil {
		return errors.Errorf("failed to remove BFD UDP session %s: %v", bfdInput.Interface, err)
	}

	d.log.Info("BFD session for interface %s removed", bfdInput.Interface)

	return nil
}

func (d *BFDDescriptor) DerivedValues(key string, value *bfd.SingleHopBFD_Session) (derived []api.KeyValuePair) {
	return derived
}

// watchBFDNotifications watches and processes BFD notifiction
func (d *BFDDescriptor) watchBFDNotifications(ctx context.Context) {
	defer d.wg.Done()
	d.log.Debug("Started watcher on BFD notifications")

	bfdChan := make(chan *vppcalls.BfdUdpSessionDetails, 10)
	if err := d.bfdHandler.WatchBFDEvents(ctx, bfdChan); err != nil {
		d.log.Errorf("watching bfd event failed: %v", err)
		return
	}

	for {
		select {
		case details := <-bfdChan:
			// Get interface logical name
			ifName, _, found := d.ifIndex.LookupBySwIfIndex(details.SwIfIndex)
			if !found {
				d.log.Warnf("Interface sw_if_index=%d with bfd was not found in the mapping", details.SwIfIndex)
				continue
			}

			d.log.Debugf("BFD event assigned src %v dst %v  to interface %q ",
				details.LocalAddr, details.PeerAddr, ifName)

			// notify about the new lease
			session := &bfd.SessionDetails{
				Interface:          ifName,
				SourceAddress:      details.LocalAddr,
				DestinationAddress: details.PeerAddr,
				State:              bfd.SessionDetails_BfdState(details.BfdState),
			}
			if err := d.kvscheduler.PushSBNotification(kvs.KVWithMetadata{
				Key:      bfd.BFDEventKey(ifName),
				Value:    session,
				Metadata: session,
			}); err != nil {
				d.log.Error(err)
			}
		case <-ctx.Done():
			return
		}
	}
}
