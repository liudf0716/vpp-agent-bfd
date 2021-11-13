// Copyright (c) 2021.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vpp2009

import (
	"fmt"

	vpp_bfd "go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2009/bfd"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2009/interface_types"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2009/ip_types"
	bfd "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/bfd"
)

// AddBfdUDPSession implements BFD handler.
func (h *BFDVppHandler) AddBfdUDPSession(bfdSess *bfd.SingleHopBFD_Session, ifIdx uint32) error {
	req := &vpp_bfd.BfdUDPAdd{
		SwIfIndex:     interface_types.InterfaceIndex(ifIdx),
		DesiredMinTx:  bfdSess.DesiredMinTxInterval,
		RequiredMinRx: bfdSess.RequiredMinRxInterval,
		DetectMult:    uint8(bfdSess.DetectMultiplier),
	}

	var err error
	req.LocalAddr, err = ip_types.ParseAddress(bfdSess.SourceAddress)
	if err != nil {
		return fmt.Errorf("different IP versions or missing IP address. Local: %v, Peer: %v",
			bfdSess.SourceAddress, bfdSess.DestinationAddress)
	}
	req.PeerAddr, err = ip_types.ParseAddress(bfdSess.DestinationAddress)
	if err != nil {
		return fmt.Errorf("different IP versions or missing IP address. Local: %v, Peer: %v",
			bfdSess.SourceAddress, bfdSess.DestinationAddress)
	}

	// No Authentication
	req.IsAuthenticated = false

	reply := &vpp_bfd.BfdUDPAddReply{}

	if err = h.callsChannel.SendRequest(req).ReceiveReply(reply); err != nil {
		return err
	} else if reply.Retval != 0 {
		return fmt.Errorf("%s returned %d", reply.GetMessageName(), reply.Retval)
	}

	return nil
}

// DeleteBfdUDPSession implements BFD handler.
func (h *BFDVppHandler) DeleteBfdUDPSession(ifIndex uint32, sourceAddress string, destAddress string) error {
	req := &vpp_bfd.BfdUDPDel{
		SwIfIndex: interface_types.InterfaceIndex(ifIndex),
	}
	var err error
	req.LocalAddr, err = ip_types.ParseAddress(sourceAddress)
	if err != nil {
		return fmt.Errorf("different IP versions or missing IP address. Local: %v, Peer: %v",
			sourceAddress, destAddress)
	}
	req.PeerAddr, err = ip_types.ParseAddress(destAddress)
	if err != nil {
		return fmt.Errorf("different IP versions or missing IP address. Local: %v, Peer: %v",
			sourceAddress, destAddress)
	}
	reply := &vpp_bfd.BfdUDPDelReply{}

	if err := h.callsChannel.SendRequest(req).ReceiveReply(reply); err != nil {
		return err
	} else if reply.Retval != 0 {
		return fmt.Errorf("%s returned %d", reply.GetMessageName(), reply.Retval)
	}

	return nil
}
