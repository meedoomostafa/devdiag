package configschema

import (
	"fmt"
	"strings"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	cueerrors "cuelang.org/go/cue/errors"
	cueyaml "cuelang.org/go/encoding/yaml"
	"gopkg.in/yaml.v3"
)

type Config struct {
	SchemaVersion string `json:"schema_version,omitempty" yaml:"schema_version"`
	CI            struct {
		Env struct {
			IgnoreMissingLocal []string `json:"ignore_missing_local,omitempty" yaml:"ignore_missing_local"`
			IgnoreMissingCI    []string `json:"ignore_missing_ci,omitempty" yaml:"ignore_missing_ci"`
		} `json:"env,omitempty" yaml:"env"`
	} `json:"ci,omitempty" yaml:"ci"`
	Policy struct {
		FailSeverity string `json:"fail_severity,omitempty" yaml:"fail_severity"`
	} `json:"policy,omitempty" yaml:"policy"`
}

type Result struct {
	Valid  bool     `json:"valid"`
	Errors []string `json:"errors,omitempty"`
	Config Config   `json:"config,omitempty"`
}

const configCueSchema = `
#Config: {
	schema_version?: string
	ci?: {
		env?: {
			ignore_missing_local?: [...string]
			ignore_missing_ci?: [...string]
		}
	}
	policy?: {
		fail_severity?: "off" | "info" | "low" | "medium" | "high" | "critical"
	}
}
`

func ValidateYAML(data []byte) Result {
	result := Result{Valid: true}
	file, err := cueyaml.Extract("devdiag.yaml", data)
	if err != nil {
		return Result{Valid: false, Errors: []string{fmt.Sprintf("parse config: %v", err)}}
	}
	ctx := cuecontext.New()
	schema := ctx.CompileString(configCueSchema)
	if err := schema.Err(); err != nil {
		return Result{Valid: false, Errors: []string{fmt.Sprintf("compile config schema: %v", err)}}
	}
	value := ctx.BuildFile(file)
	if err := value.Err(); err != nil {
		return Result{Valid: false, Errors: []string{fmt.Sprintf("parse config: %v", err)}}
	}
	configValue := schema.LookupPath(cue.ParsePath("#Config")).Unify(value)
	if err := configValue.Validate(cue.Concrete(true), cue.Final()); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, splitCUEError(err)...)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("decode config: %v", err))
	}
	result.Config = cfg
	return result
}

func splitCUEError(err error) []string {
	if err == nil {
		return nil
	}
	var out []string
	details := cueerrors.Details(err, nil)
	if strings.TrimSpace(details) == "" {
		details = err.Error()
	}
	for _, line := range strings.Split(details, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	if len(out) == 0 {
		out = append(out, err.Error())
	}
	return out
}
