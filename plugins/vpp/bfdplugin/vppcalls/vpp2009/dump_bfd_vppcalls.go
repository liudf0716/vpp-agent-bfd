// Copyright (c) 2021 .
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
	"go.ligato.io/vpp-agent/v3/plugins/vpp/bfdplugin/vppcalls"
	vpp_bfd "go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2009/bfd"
	bfd "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/bfd"
)

// DumpBfdSessions implements BFD handler.
func (h *BFDVppHandler) DumpBfdSessions() (*vppcalls.BfdSessionDetails, error) {
	var sessions []*bfd.Session
	meta := &vppcalls.BfdSessionMeta{
		SessionIfToIdx: make(map[uint32]string),
	}

	req := &vpp_bfd.BfdUDPSessionDump{}
	sessionsRequest := h.callsChannel.SendMultiRequest(req)

	for {
		sessionDetails := &vpp_bfd.BfdUDPSessionDetails{}
		stop, err := sessionsRequest.ReceiveReply(sessionDetails)
		if stop {
			break
		}
		if err != nil {
			return nil, err
		}

		ifName, _, exists := h.ifIndexes.LookupBySwIfIndex(uint32(sessionDetails.SwIfIndex))
		if !exists {
			h.log.Warnf("BFD session dump: interface name not found for index %d", sessionDetails.SwIfIndex)
		}

		// Put session info
		sessions = append(sessions, &bfd.Session{
			Interface:             ifName,
			DestinationAddress:    sessionDetails.LocalAddr.String(),
			SourceAddress:         sessionDetails.PeerAddr.String(),
			DesiredMinTxInterval:  sessionDetails.DesiredMinTx,
			RequiredMinRxInterval: sessionDetails.RequiredMinRx,
			DetectMultiplier:      uint32(sessionDetails.DetectMult),
			KeyId:                 uint32(sessionDetails.BfdKeyID),
			AdvertisedKeyId:       uint32(sessionDetails.ConfKeyID),
		})
		// Put bfd interface info
		meta.SessionIfToIdx[uint32(sessionDetails.SwIfIndex)] = ifName
	}

	return &vppcalls.BfdSessionDetails{
		Session: sessions,
		Meta:    meta,
	}, nil
}

// DumpBfdAuthKeys implements BFD handler.
func (h *BFDVppHandler) DumpBfdAuthKeys() (*vppcalls.BfdAuthKeyDetails, error) {
	var authKeys []*bfd.SingleHopBFD_Key
	meta := &vppcalls.BfdAuthKeyMeta{
		KeyIDToUseCount: make(map[uint32]uint32),
	}

	req := &vpp_bfd.BfdAuthKeysDump{}
	keysRequest := h.callsChannel.SendMultiRequest(req)

	for {
		keyDetails := &vpp_bfd.BfdAuthKeysDetails{}
		stop, err := keysRequest.ReceiveReply(keyDetails)
		if stop {
			break
		}
		if err != nil {
			return nil, err
		}

		// Put auth key info
		authKeys = append(authKeys, &bfd.SingleHopBFD_Key{
			AuthKeyIndex: keyDetails.ConfKeyID,
			Id:           keyDetails.ConfKeyID,
			AuthenticationType: func(authType uint8) bfd.SingleHopBFD_Key_AuthenticationType {
				if authType == 4 {
					return bfd.SingleHopBFD_Key_KEYED_SHA1
				}
				return bfd.SingleHopBFD_Key_METICULOUS_KEYED_SHA1
			}(keyDetails.AuthType),
		})
		// Put bfd key use count info
		meta.KeyIDToUseCount[keyDetails.ConfKeyID] = keyDetails.UseCount
	}

	return &vppcalls.BfdAuthKeyDetails{
		AuthKeys: authKeys,
		Meta:     meta,
	}, nil
}
