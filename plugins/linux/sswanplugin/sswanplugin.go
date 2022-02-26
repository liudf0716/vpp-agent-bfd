// Copyright (c) 2018 Cisco and/or its affiliates.
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

//go:generate descriptor-adapter --descriptor-name Sswan --value-type *linux_sswan.Sswan --import "go.ligato.io/vpp-agent/v3/proto/ligato/linux/sswan" --output-dir "descriptor"

package sswanplugin

import (
        "fmt"
        "io"
        "os"
        "os/exec"

        "github.com/ligato/cn-infra/infra"
        kvs "github.com/ligato/vpp-agent/plugins/kvscheduler/api"
        "github.com/ligato/vpp-agent/plugins/linux/sswanplugin/descriptor"
)

const (
        IpsecConfigFile      = "/usr/local/etc/ipsec.conf"
        StrongswanConfigFile = "/usr/local/etc/strongswan.conf"
        IpsecSecretsFile     = "/usr/local/etc/ipsec.secrets"
        CharonConfigFile     = "/usr/local/etc/strongswan.d/charon.conf"
)

type SswanPlugin struct {
  Deps
  
  disabled  bool
  
  sswanHandler  linuxcalls.SswanAPI
  sswanDescriptor *descriptor.SswanDescriptor
}

type Deps struct {
  infra.PluginDeps
  KVScheduler kvs.KVScheduler
}

func (p *SswanPlugin) Init() error {
  return nil
}

func (p *SswanPlugin) Close() error {
  return nil
}
