package ci

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/meedoomostafa/devdiag/internal/schema"
	"gopkg.in/yaml.v3"
)

// Collector scans CI workflow files and extracts structured evidence.
type Collector struct {
	Root string
}

func (c *Collector) Name() string {
	return "ci"
}

func (c *Collector) Collect(ctx context.Context) (schema.CollectorResult, error) {
	root := c.Root
	if root == "" {
		root = "."
	}

	evidence := []schema.Evidence{}
	notes := []string{}

	workflowDir := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(workflowDir)
	if err != nil {
		return schema.CollectorResult{
			Name:   c.Name(),
			Status: schema.CollectorOK,
		}, nil
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}

		path := filepath.Join(workflowDir, name)
		pw, err := parseWorkflow(path, name)
		if err != nil {
			notes = append(notes, fmt.Sprintf("failed to parse %s: %v", name, err))
			continue
		}

		evidence = append(evidence, pw.toEvidence()...)
		notes = append(notes, pw.notes...)
	}

	status := schema.CollectorOK
	if len(notes) > 0 {
		status = schema.CollectorPartial
	}

	return schema.CollectorResult{
		Name:     c.Name(),
		Status:   status,
		Evidence: evidence,
		Notes:    notes,
	}, nil
}

// parsedWorkflow holds structured data from a single GitHub Actions workflow.
type parsedWorkflow struct {
	filename    string
	runCommands []commandEvidence
	usesActions []usesEvidence
	envVars     []envEvidence
	services    []serviceEvidence
	containers  []containerEvidence
	defaults    []defaultsEvidence
	notes       []string
}

type commandEvidence struct {
	Job  string
	Step int
	Cmd  string
}

type usesEvidence struct {
	Job    string
	Step   int
	Action string
}

type envEvidence struct {
	Scope string
	Job   string
	Step  int
	Key   string
	Value string
}

type serviceEvidence struct {
	Job   string
	Name  string
	Image string
	Ports []string
}

type containerEvidence struct {
	Job   string
	Image string
}

type defaultsEvidence struct {
	Scope            string
	Job              string
	WorkingDirectory string
	Shell            string
}

func parseWorkflow(path, filename string) (*parsedWorkflow, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}

	start := &root
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		start = root.Content[0]
	}

	pw := &parsedWorkflow{filename: filename}
	if start.Kind == yaml.MappingNode {
		pw.parseWorkflowMapping(start)
	}
	return pw, nil
}

func (pw *parsedWorkflow) parseWorkflowMapping(node *yaml.Node) {
	for i := 0; i < len(node.Content); i += 2 {
		key := node.Content[i].Value
		val := node.Content[i+1]
		switch key {
		case "env":
			pw.parseEnv("workflow", "", -1, val)
		case "jobs":
			pw.parseJobs(val)
		case "defaults":
			pw.parseDefaults("workflow", "", val)
		case "strategy":
			pw.detectMatrix(val)
		}
	}
}

func (pw *parsedWorkflow) parseJobs(node *yaml.Node) {
	if node.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i < len(node.Content); i += 2 {
		jobName := node.Content[i].Value
		jobNode := node.Content[i+1]
		if jobNode.Kind == yaml.MappingNode {
			pw.parseJob(jobName, jobNode)
		}
	}
}

func (pw *parsedWorkflow) parseJob(jobName string, node *yaml.Node) {
	for i := 0; i < len(node.Content); i += 2 {
		key := node.Content[i].Value
		val := node.Content[i+1]
		switch key {
		case "env":
			pw.parseEnv("job", jobName, -1, val)
		case "services":
			pw.parseServices(jobName, val)
		case "container":
			pw.parseContainer(jobName, val)
		case "steps":
			pw.parseSteps(jobName, val)
		case "defaults":
			pw.parseDefaults("job", jobName, val)
		case "strategy":
			pw.detectMatrix(val)
		}
	}
}

func (pw *parsedWorkflow) parseSteps(jobName string, node *yaml.Node) {
	if node.Kind != yaml.SequenceNode {
		return
	}
	for stepIdx, stepNode := range node.Content {
		if stepNode.Kind != yaml.MappingNode {
			continue
		}
		for i := 0; i < len(stepNode.Content); i += 2 {
			key := stepNode.Content[i].Value
			val := stepNode.Content[i+1]
			switch key {
			case "run":
				if val.Kind == yaml.ScalarNode && val.Value != "" {
					pw.runCommands = append(pw.runCommands, commandEvidence{
						Job: jobName, Step: stepIdx, Cmd: strings.TrimSpace(val.Value),
					})
				}
			case "uses":
				if val.Kind == yaml.ScalarNode && val.Value != "" {
					pw.usesActions = append(pw.usesActions, usesEvidence{
						Job: jobName, Step: stepIdx, Action: val.Value,
					})
					action := val.Value
					if strings.HasPrefix(action, "actions/setup-") {
						pw.extractSetupVersion(jobName, stepIdx, action, stepNode)
					}
				}
			case "env":
				pw.parseEnv("step", jobName, stepIdx, val)
			}
		}
	}
}

func (pw *parsedWorkflow) extractSetupVersion(jobName string, stepIdx int, action string, stepNode *yaml.Node) {
	var withNode *yaml.Node
	for i := 0; i < len(stepNode.Content); i += 2 {
		if stepNode.Content[i].Value == "with" && stepNode.Content[i+1].Kind == yaml.MappingNode {
			withNode = stepNode.Content[i+1]
			break
		}
	}
	if withNode == nil {
		return
	}
	for i := 0; i < len(withNode.Content); i += 2 {
		key := withNode.Content[i].Value
		val := withNode.Content[i+1].Value
		if key == "node-version" || key == "python-version" || key == "go-version" || key == "ruby-version" {
			parts := strings.Split(action, "/")
			if len(parts) == 2 {
				actionName := parts[1]
				if idx := strings.Index(actionName, "@"); idx != -1 {
					actionName = actionName[:idx]
				}
				pw.envVars = append(pw.envVars, envEvidence{
					Scope: "setup_action",
					Job:   jobName,
					Step:  stepIdx,
					Key:   actionName + "_" + key,
					Value: val,
				})
			}
		}
	}
}

func (pw *parsedWorkflow) parseEnv(scope, jobName string, stepIdx int, node *yaml.Node) {
	if node.Kind == yaml.ScalarNode {
		pw.envVars = append(pw.envVars, envEvidence{
			Scope: scope, Job: jobName, Step: stepIdx, Key: "value", Value: node.Value,
		})
		return
	}
	if node.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i < len(node.Content); i += 2 {
		key := node.Content[i].Value
		val := node.Content[i+1].Value
		pw.envVars = append(pw.envVars, envEvidence{
			Scope: scope, Job: jobName, Step: stepIdx, Key: key, Value: val,
		})
	}
}

func (pw *parsedWorkflow) parseServices(jobName string, node *yaml.Node) {
	if node.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i < len(node.Content); i += 2 {
		svcName := node.Content[i].Value
		svcNode := node.Content[i+1]
		if svcNode.Kind != yaml.MappingNode {
			continue
		}
		svc := serviceEvidence{Job: jobName, Name: svcName}
		for j := 0; j < len(svcNode.Content); j += 2 {
			k := svcNode.Content[j].Value
			v := svcNode.Content[j+1]
			switch k {
			case "image":
				if v.Kind == yaml.ScalarNode {
					svc.Image = v.Value
				}
			case "ports":
				if v.Kind == yaml.SequenceNode {
					for _, portNode := range v.Content {
						if portNode.Kind == yaml.ScalarNode {
							svc.Ports = append(svc.Ports, portNode.Value)
						}
					}
				} else if v.Kind == yaml.ScalarNode {
					svc.Ports = append(svc.Ports, v.Value)
				}
			}
		}
		pw.services = append(pw.services, svc)
	}
}

func (pw *parsedWorkflow) parseContainer(jobName string, node *yaml.Node) {
	var img string
	if node.Kind == yaml.ScalarNode {
		img = node.Value
	} else if node.Kind == yaml.MappingNode {
		for i := 0; i < len(node.Content); i += 2 {
			if node.Content[i].Value == "image" {
				img = node.Content[i+1].Value
			}
		}
	}
	if img != "" {
		pw.containers = append(pw.containers, containerEvidence{Job: jobName, Image: img})
	}
}

func (pw *parsedWorkflow) parseDefaults(scope, jobName string, node *yaml.Node) {
	if node.Kind != yaml.MappingNode {
		return
	}
	def := defaultsEvidence{Scope: scope, Job: jobName}
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == "run" && node.Content[i+1].Kind == yaml.MappingNode {
			runNode := node.Content[i+1]
			for j := 0; j < len(runNode.Content); j += 2 {
				k := runNode.Content[j].Value
				v := runNode.Content[j+1].Value
				switch k {
				case "working-directory":
					def.WorkingDirectory = v
				case "shell":
					def.Shell = v
				}
			}
		}
	}
	if def.WorkingDirectory != "" || def.Shell != "" {
		pw.defaults = append(pw.defaults, def)
	}
}

func (pw *parsedWorkflow) detectMatrix(node *yaml.Node) {
	if node.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == "matrix" {
			pw.notes = append(pw.notes, "matrix strategy detected; matrix expansion is not evaluated in M8")
			return
		}
	}
}

func (pw *parsedWorkflow) toEvidence() []schema.Evidence {
	var ev []schema.Evidence

	for _, cmd := range pw.runCommands {
		ev = append(ev, schema.Evidence{
			Source: fmt.Sprintf("ci_run__%s__%d", sanitizeSource(cmd.Job), cmd.Step),
			Value:  cmd.Cmd,
		})
	}

	for _, u := range pw.usesActions {
		ev = append(ev, schema.Evidence{
			Source: fmt.Sprintf("ci_uses__%s__%d", sanitizeSource(u.Job), u.Step),
			Value:  u.Action,
		})
	}

	for _, env := range pw.envVars {
		switch env.Scope {
		case "workflow":
			ev = append(ev, schema.Evidence{
				Source: "ci_env__workflow__" + sanitizeSource(env.Key),
				Value:  env.Value,
			})
		case "job":
			ev = append(ev, schema.Evidence{
				Source: fmt.Sprintf("ci_env__job__%s__%s", sanitizeSource(env.Job), sanitizeSource(env.Key)),
				Value:  env.Value,
			})
		case "step":
			ev = append(ev, schema.Evidence{
				Source: fmt.Sprintf("ci_env__step__%s__%d__%s", sanitizeSource(env.Job), env.Step, sanitizeSource(env.Key)),
				Value:  env.Value,
			})
		case "setup_action":
			action, versionKey := splitSetupKey(env.Key)
			ev = append(ev, schema.Evidence{
				Source: fmt.Sprintf("ci_setup__%s__%d__%s__%s", sanitizeSource(env.Job), env.Step, sanitizeSource(action), sanitizeSource(versionKey)),
				Value:  env.Value,
			})
		}
	}

	for _, svc := range pw.services {
		job := sanitizeSource(svc.Job)
		name := sanitizeSource(svc.Name)
		if svc.Image != "" {
			ev = append(ev, schema.Evidence{
				Source: fmt.Sprintf("ci_service__%s__%s__image", job, name),
				Value:  svc.Image,
			})
		}
		for _, p := range svc.Ports {
			hostPort := extractHostPort(p)
			if hostPort != "" {
				ev = append(ev, schema.Evidence{
					Source: fmt.Sprintf("ci_service__%s__%s__host_port", job, name),
					Value:  hostPort,
				})
			}
		}
	}

	for _, ctr := range pw.containers {
		ev = append(ev, schema.Evidence{
			Source: fmt.Sprintf("ci_container__%s__image", sanitizeSource(ctr.Job)),
			Value:  ctr.Image,
		})
	}

	for _, def := range pw.defaults {
		if def.Scope == "workflow" {
			if def.WorkingDirectory != "" {
				ev = append(ev, schema.Evidence{Source: "ci_defaults__workflow__working_directory", Value: def.WorkingDirectory})
			}
			if def.Shell != "" {
				ev = append(ev, schema.Evidence{Source: "ci_defaults__workflow__shell", Value: def.Shell})
			}
			continue
		}
		job := sanitizeSource(def.Job)
		if def.WorkingDirectory != "" {
			ev = append(ev, schema.Evidence{Source: fmt.Sprintf("ci_defaults__job__%s__working_directory", job), Value: def.WorkingDirectory})
		}
		if def.Shell != "" {
			ev = append(ev, schema.Evidence{Source: fmt.Sprintf("ci_defaults__job__%s__shell", job), Value: def.Shell})
		}
	}

	return ev
}

func splitSetupKey(key string) (action, versionKey string) {
	idx := strings.LastIndex(key, "_")
	if idx == -1 {
		return key, "version"
	}
	return key[:idx], key[idx+1:]
}

func sanitizeSource(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func extractHostPort(portStr string) string {
	portStr = strings.TrimSpace(portStr)
	if portStr == "" {
		return ""
	}
	// Handles: "5432:5432", "5432:5432/tcp", "127.0.0.1:5432:5432"
	parts := strings.Split(portStr, ":")
	if len(parts) == 2 {
		hostPart := strings.TrimSpace(parts[0])
		if strings.Contains(hostPart, ".") || strings.Contains(hostPart, "/") {
			// IP prefix or protocol suffix in first part
			hostPart = strings.TrimSpace(parts[1])
		}
		if idx := strings.Index(hostPart, "/"); idx != -1 {
			hostPart = hostPart[:idx]
		}
		return hostPart
	}
	if len(parts) == 3 {
		// 127.0.0.1:5432:5432
		hostPart := strings.TrimSpace(parts[1])
		if idx := strings.Index(hostPart, "/"); idx != -1 {
			hostPart = hostPart[:idx]
		}
		return hostPart
	}
	return ""
}
