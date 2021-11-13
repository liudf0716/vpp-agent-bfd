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

package vppcalls

import (
	"context"

	govppapi "git.fd.io/govpp.git/api"

	"go.ligato.io/cn-infra/v2/logging"
	"go.ligato.io/vpp-agent/v3/plugins/vpp"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/ifplugin/ifaceidx"
	bfd "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/bfd"
)

// BfdDetails is the wrapper structure for the BFD northbound API structure.
type BfdDetails struct {
	Bfd  *bfd.SingleHopBFD `json:"bfd"`
	Meta *BfdMeta          `json:"bfd_meta"`
}

// BfdMeta is combination of proto-modelled BFD data and VPP provided metadata
type BfdMeta struct {
	*BfdSessionMeta `json:"bfd_session_meta"`
	*BfdAuthKeyMeta `json:"bfd_authkey_meta"`
}

// BfdSessionDetails is the wrapper structure for the BFD session northbound API structure.
type BfdSessionDetails struct {
	Session []*bfd.SingleHopBFD_Session
	Meta    *BfdSessionMeta
}

// BfdSessionMeta is combination of proto-modelled BFD session data and session interface to index map
type BfdSessionMeta struct {
	SessionIfToIdx map[uint32]string
}

// BfdAuthKeyDetails is the wrapper structure for the BFD authentication key northbound API structure.
type BfdAuthKeyDetails struct {
	AuthKeys []*bfd.SingleHopBFD_Key
	Meta     *BfdAuthKeyMeta
}

// BfdAuthKeyMeta is combination of proto-modelled BFD session data and key-to-usage map
type BfdAuthKeyMeta struct {
	KeyIDToUseCount map[uint32]uint32
}

// BFDEvent represents bfd event from vpp
type BfdUdpSessionDetails struct {
	SwIfIndex       uint32
	LocalAddr       string
	PeerAddr        string
	BfdState        uint8
	IsAuthenticated bool
	BfdKeyID        uint8
	ConfKeyID       uint32
	RequiredMinRx   uint32
	DesiredMinTx    uint32
	DetectMult      uint8
}

type BFDVppAPI interface {
	BFDVppRead

	// AddBFD create bfd udp session
	AddBfdUDPSession(bfdSess *bfd.SingleHopBFD_Session, ifIdx uint32) error
	// DeleateBfd delete bfd udp session
	DeleteBfdUDPSession(ifIndex uint32, sourceAddress string, destAddress string) error
}

type BFDVppRead interface {
	// DumpBfdSingleHop dump bfd single hop
	DumpBfdSingleHop() (*BfdDetails, error)
	// WatchBFDEvent starts watching for bfd events.
	WatchBFDEvents(ctx context.Context, eventsCh chan<- *BfdUdpSessionDetails) error
}

var Handler = vpp.RegisterHandler(vpp.HandlerDesc{
	Name:       "bfd",
	HandlerAPI: (*BFDVppAPI)(nil),
})

type NewHandlerFunc func(c vpp.Client, ifIndexes ifaceidx.IfaceMetadataIndex, log logging.Logger) BFDVppAPI

func AddBFDHandlerVersion(version vpp.Version, msgs []govppapi.Message, h NewHandlerFunc) {
	Handler.AddVersion(vpp.HandlerVersion{
		Version: version,
		Check: func(c vpp.Client) error {
			ch, err := c.NewAPIChannel()
			if err != nil {
				return err
			}
			return ch.CheckCompatiblity(msgs...)
		},
		NewHandler: func(c vpp.Client, a ...interface{}) vpp.HandlerAPI {
			return h(c, a[0].(ifaceidx.IfaceMetadataIndex), a[1].(logging.Logger))
		},
	})
}

func CompatibleBFDVppHandler(c vpp.Client, ifIndexes ifaceidx.IfaceMetadataIndex, log logging.Logger) BFDVppAPI {
	if v := Handler.FindCompatibleVersion(c); v != nil {
		return v.NewHandler(c, ifIndexes, log).(BFDVppAPI)
	}
	return nil
}
