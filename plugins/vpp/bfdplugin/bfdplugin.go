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

//go:generate descriptor-adapter --descriptor-name BFD --value-type *vpp_bfd.SingleHopBFD_Session  --import "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/bfd" --output-dir "descriptor"

package bfdplugin

import (
	"context"
	"sync"

	"github.com/go-errors/errors"
	"go.ligato.io/cn-infra/v2/health/statuscheck"
	"go.ligato.io/cn-infra/v2/infra"
	"go.ligato.io/cn-infra/v2/utils/safeclose"

	"go.ligato.io/vpp-agent/v3/plugins/govppmux"
	kvs "go.ligato.io/vpp-agent/v3/plugins/kvscheduler/api"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/bfdplugin/descriptor"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/bfdplugin/descriptor/adapter"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/bfdplugin/vppcalls"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/ifplugin"

	_ "go.ligato.io/vpp-agent/v3/plugins/vpp/bfdplugin/vppcalls/vpp2009"
)

// BFDPlugin is a plugin that bidirectional forwarding detection.
type BFDPlugin struct {
	Deps

	bfdHandler    vppcalls.BFDVppAPI
	bfdDescriptor *descriptor.BFDDescriptor

	bfdIDSeq uint32

	// go routine management
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Deps represents dependencies for the plugin.
type Deps struct {
	infra.PluginDeps
	Scheduler   kvs.KVScheduler
	VPP         govppmux.API
	IfPlugin    ifplugin.API
	StatusCheck statuscheck.PluginStatusWriter // optional
}

// Init initializes BFD plugin.
func (p *BFDPlugin) Init() error {
	if !p.VPP.IsPluginLoaded("bfd") {
		p.Log.Warnf("VPP plugin BFD was disabled by VPP")
		return nil
	}

	p.ctx, p.cancel = context.WithCancel(context.Background())

	// init handlers
	p.bfdHandler = vppcalls.CompatibleBFDVppHandler(p.VPP, p.IfPlugin.GetInterfaceIndex(), p.Log)
	if p.bfdHandler == nil {
		return errors.New("bfdHandler is not available")
	}

	// init & register descriptor
	p.bfdDescriptor = descriptor.NewBFDDescriptor(p.bfdHandler, p.Scheduler, p.IfPlugin.GetInterfaceIndex(), p.Log)
	bfdDescriptor := adapter.NewBFDDescriptor(p.bfdDescriptor.GetDescriptor())
	if err := p.Deps.Scheduler.RegisterKVDescriptor(bfdDescriptor); err != nil {
		return err
	}

	p.bfdDescriptor.WatchBFDNotifications(p.ctx)

	return nil
}

// AfterInit registers plugin with StatusCheck.
func (p *BFDPlugin) AfterInit() error {
	if p.StatusCheck != nil {
		p.StatusCheck.Register(p.PluginName, nil)
	}
	return nil
}

// close stops all go routines.
func (p *BFDPlugin) Close() error {
	// stop publishing of state data
	p.cancel()
	p.wg.Wait()

	// close all resources
	return safeclose.Close(p.bfdDescriptor)
}
