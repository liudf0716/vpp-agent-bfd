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

package vpp_bfd

import (
	"go.ligato.io/vpp-agent/v3/pkg/models"
)

// ModuleName is the name of the module used for models.
const ModuleName = "vpp.bfds"

var (
	ModelBFDSession = models.Register(&SingleHopBFD{}, models.Spec{
		Module:  ModuleName,
		Version: "v2",
		Type:    "session",
	}, models.WithNameTemplate("{{.BfdInterface}}/{{.SourceAddress}}/{{.DestinationAddress}}"))

	ModelEchoFunction = models.Register(&EchoFunction{}, models.Spec{
		Module:  ModuleName,
		Version: "v2",
		Type:    "echo",
	}, models.WithNameTemplate("{{.EchoSourceInterface}}"))
)

const (
	// BFDEventKeyPrefix
	BFDEventKeyPrefix = "vpp/interface/bfd-event/"
)

func BFDEventKey(ifName string) string {
	return BFDEventKeyPrefix + ifName
}

func BFDEventPubKey(ifName, dst string) string {
	return BFDEventKeyPrefix + ifName + "/" + dst
}
