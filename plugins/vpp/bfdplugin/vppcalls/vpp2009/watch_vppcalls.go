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
	"context"
	"net"
	"os"
	"time"

	govppapi "git.fd.io/govpp.git/api"
	"github.com/pkg/errors"

	"go.ligato.io/vpp-agent/v3/plugins/vpp/bfdplugin/vppcalls"
	vpp_bfd "go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2009/bfd"
)

var (
	// EventDeliverTimeout defines maximum time to deliver event upstream.
	EventDeliverTimeout = time.Second
	// NotifChanBufferSize defines size of notification channel buffer.
	NotifChanBufferSize = 10
)

func (h *BFDVppHandler) WatchBFDEvents(ctx context.Context, eventsCh chan<- *vppcalls.BfdUdpSessionDetails) error {
	notifChan := make(chan govppapi.Message, NotifChanBufferSize)

	// subscribe to BfdUDPSessionDetails notifications
	sub, err := h.callsChannel.SubscribeNotification(notifChan, &vpp_bfd.BfdUDPSessionDetails{})
	if err != nil {
		return errors.Errorf("subscribing to VPP notification (bfd_udp_session_details) failed: %v", err)
	}
	unsub := func() {
		if err := sub.Unsubscribe(); err != nil {
			h.log.Warnf("unsubscribing VPP notification (bfd_udp_session_details) failed: %v", err)
		}
	}

	go func() {
		h.log.Debugf("start watching bfd events")
		defer h.log.Debugf("done watching bfd events (%v)", ctx.Err())

		for {
			select {
			case e, open := <-notifChan:
				if !open {
					h.log.Debugf("bfd events channel was closed")
					unsub()
					return
				}

				bfdUdpSessionDetails, ok := e.(*vpp_bfd.BfdUDPSessionDetails)
				if !ok {
					h.log.Debugf("unexpected notification type: %#v", bfdUdpSessionDetails)
					continue
				}

				// try to send event
				select {
				case eventsCh <- toBfdUdpSessionDetails(bfdUdpSessionDetails):
					// sent ok
				case <-ctx.Done():
					unsub()
					return
				default:
					// channel full send event in goroutine for later processing
					go func() {
						select {
						case eventsCh <- toBfdUdpSessionDetails(bfdUdpSessionDetails):
							// sent ok
						case <-time.After(EventDeliverTimeout):
							h.log.Warnf("unable to deliver interface event, dropping it: %+v", bfdUdpSessionDetails)
						}
					}()
				}
			case <-ctx.Done():
				unsub()
				return
			}
		}
	}()

	// enable bfd events from VPP
	if _, err := h.bfds.WantBfdEvents(ctx, &vpp_bfd.WantBfdEvents{
		PID:           uint32(os.Getpid()),
		EnableDisable: true,
	}); err != nil {
		if errors.Is(err, govppapi.VPPApiError(govppapi.INVALID_REGISTRATION)) {
			h.log.Warnf("already subscribed to bfd events: %v", err)
			return nil
		}
		return errors.Errorf("failed to watch bfd events: %v", err)
	}

	return nil
}

func toBfdUdpSessionDetails(bfdDetails *vpp_bfd.BfdUDPSessionDetails) *vppcalls.BfdUdpSessionDetails {
	srcAddrArr := bfdDetails.LocalAddr.Un.GetIP4()
	srcAddr := net.IP(srcAddrArr[:])
	dstAddrArr := bfdDetails.PeerAddr.Un.GetIP4()
	dstAddr := net.IP(dstAddrArr[:])

	bfdUdpSessionDetails := &vppcalls.BfdUdpSessionDetails{
		SwIfIndex:       uint32(bfdDetails.SwIfIndex),
		LocalAddr:       srcAddr.String(),
		PeerAddr:        dstAddr.String(),
		BfdState:        uint8(bfdDetails.State),
		IsAuthenticated: bfdDetails.IsAuthenticated,
		BfdKeyID:        bfdDetails.BfdKeyID,
		ConfKeyID:       bfdDetails.ConfKeyID,
		RequiredMinRx:   bfdDetails.RequiredMinRx,
		DesiredMinTx:    bfdDetails.DesiredMinTx,
		DetectMult:      bfdDetails.DetectMult,
	}

	return bfdUdpSessionDetails
}
