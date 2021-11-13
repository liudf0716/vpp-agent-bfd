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

package vpp2009

import (
	govppapi "git.fd.io/govpp.git/api"
	"go.ligato.io/cn-infra/v2/logging"
	"go.ligato.io/vpp-agent/v3/plugins/vpp"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/bfdplugin/vppcalls"
	vpp2009 "go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2009"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2009/bfd"
	bfds "go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2009/bfd"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/ifplugin/ifaceidx"
)

func init() {
	msgs := bfd.AllMessages()
	vppcalls.AddBFDHandlerVersion(vpp2009.Version, msgs, NewBFDVppHandler)
}

type BFDVppHandler struct {
	callsChannel govppapi.Channel
	bfds         bfds.RPCService
	log          logging.Logger
	ifIndexes    ifaceidx.IfaceMetadataIndex
}

func NewBFDVppHandler(c vpp.Client, ifIndexes ifaceidx.IfaceMetadataIndex, log logging.Logger) vppcalls.BFDVppAPI {
	ch, err := c.NewAPIChannel()
	if err != nil {
		return nil
	}
	return &BFDVppHandler{
		callsChannel: ch,
		bfds:         bfds.NewServiceClient(c),
		log:          log,
		ifIndexes:    ifIndexes,
	}
}
