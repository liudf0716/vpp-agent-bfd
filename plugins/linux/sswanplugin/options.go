package sswanplugin

import (
        "github.com/ligato/cn-infra/config"
        "github.com/ligato/cn-infra/logging"
        "github.com/ligato/vpp-agent/plugins/kvscheduler"
)

// DefaultPlugin is a default instance of IfPlugin.
var DefaultPlugin = *NewPlugin()

// NewPlugin creates a new Plugin with the provides Options
func NewPlugin(opts ...Option) *StrongswanPlugin {
        p := &SswanPlugin{}

        p.PluginName = "linux-sswanplugin"
        p.KVScheduler = &kvscheduler.DefaultPlugin


        for _, o := range opts {
                o(p)
        }

        if p.Log == nil {
                p.Log = logging.ForPlugin(p.String())
        }
        if p.Cfg == nil {
                p.Cfg = config.ForPlugin(p.String(),
                        config.WithCustomizedFlag(config.FlagName(p.String()), "linux-sswanplugin.conf"),
                )
        }

        return p
}

type Option func(*SswanPlugin)

func UseDeps(f func(*Deps)) Option {
        return func(p *SswanPlugin) {
                f(&p.Deps)
        }
}
