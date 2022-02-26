package descriptor

import (
  "strings"
  
  "github.com/ligato/cn-infra/logging"
  kvs "github.com/ligato/vpp-agent/plugins/kvscheduler/api"
)

const (
  SswanDescriptorName = "sswan-descriptor"
)

type SswanDescriptor struct {
  log           logging.Logger
  scheduler     kvs.KVScheduler
  sswanHandler  linuxcalls.SswanAPI
}

func NewSswanDescriptor(
        scheduler kvs.KVScheduler, sswanHandler linuxcalls.SswanAPI, 
        log logging.PluginLogger) *kvs.KVDescriptor {

        descrCtx := &SswanDescriptor{
                scheduler:        scheduler,
                sswanHandler:     sswanHandler,
                log:              log.NewLogger("sswan-descriptor"),
        }

        typedDescr := &adapter.SswanDescriptor{
                Name:                 SswanDescriptorName,
                NBKeyPrefix:          linux_iptables.ModelRuleChain.KeyPrefix(),
                ValueTypeName:        linux_iptables.ModelRuleChain.ProtoName(),
                KeySelector:          linux_iptables.ModelRuleChain.IsKeyValid,
                KeyLabel:             linux_iptables.ModelRuleChain.StripKeyPrefix,
                ValueComparator:      descrCtx.EquivalentSswans,
                Validate:             descrCtx.Validate,
                Create:               descrCtx.Create,
                Delete:               descrCtx.Delete,
                Retrieve:             descrCtx.Retrieve,
                Dependencies:         descrCtx.Dependencies,
        }
        return adapter.NewSswanDescriptor(typedDescr)
}

func (d *SswanDescriptor) EquivalentSswans() bool {
  return true
}

func (d *SswanDescriptor) Validate() (err error) {
  return nil
}

func (d *SswanDescriptor) Create() () {
}

func (d *SswanDescriptor) Delete() error {
}

func (d *SswanDescriptor) Retrieve() () {
}

func (d *SswanDescriptor)Dependencies() () {
}

