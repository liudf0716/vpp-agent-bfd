package linux_sswan

import (
	"go.ligato.io/vpp-agent/v3/pkg/models"
)

// ModuleName is the module name used for models.
const ModuleName = "linux.sswan"

var (
	ModelSswan = models.Register(&Sswan{}, models.Spec{
		Module:  ModuleName,
		Version: "v2",
		Type:    "sswan",
	}, models.WithNameTemplate("{{.Name}}"))
)
