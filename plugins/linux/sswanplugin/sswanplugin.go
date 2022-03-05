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
	// by default, at most 10 go routines will split the configured namespaces
	// to execute the Retrieve operation in parallel.
	defaultGoRoutinesCnt = 10
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

// Config holds the sswanplugin configuration.
type Config struct {
	Disabled      bool `json:"disabled"`
	GoRoutinesCnt int  `json:"go-routines-count"`
}

func (p *SswanPlugin) Init() error {
    // parse configuration file
	config, err := p.retrieveConfig()
	if err != nil {
		return err
	}
	p.Log.Debugf("Linux strongswan plugin config: %+v", config)
	if config.Disabled {
		p.disabled = true
		p.Log.Infof("Disabling Linux Strongswan plugin")
		return nil
	}
    
    sswanDescriptor := descriptor.NewSswanDescriptor(p.KVScheduler, p.Log, config.GoRoutinesCnt)
    err = p.Deps.KVScheduler.RegisterKVDescriptor(sswanDescriptor)
    if err != nil {
            p.Log.Infof("sswan plugin register descriptor failed: %+v", err)
            return err
    }
    return nil
}

func (p *SswanPlugin) Close() error {
  return nil
}

func (p *SswanPlugin) retrieveConfig() (*Config, error) {
        config := &Config{
                // default configuration
                GoRoutinesCnt: defaultGoRoutinesCnt,
        }
        found, err := p.Cfg.LoadValue(config)
        if !found {
                p.Log.Debug("Linux SswanPlugin config not found")
                return config, nil
        }
        if err != nil {
                return nil, err
        }
        return config, err
}
