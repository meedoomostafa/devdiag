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
	if err == nil {
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
	}

	if gitlabEvidence, err := parseGitLabCI(filepath.Join(root, ".gitlab-ci.yml")); err == nil {
		evidence = append(evidence, gitlabEvidence...)
	} else if !os.IsNotExist(err) {
		notes = append(notes, fmt.Sprintf("failed to parse .gitlab-ci.yml: %v", err))
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
	matrix      []matrixRuntimeEvidence
	metadata    []schema.Evidence
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
	Job     string
	Name    string
	Image   string
	Ports   []string
	Options string
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

type matrixRuntimeEvidence struct {
	Job        string
	Runtime    string
	VersionKey string
	Value      string
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
			pw.parseStrategy("workflow", val)
		case "on":
			pw.parseTriggers(val)
		case "permissions":
			pw.parsePermissions("workflow", "", val)
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
			pw.parseStrategy(jobName, val)
		case "runs-on":
			pw.metadata = append(pw.metadata, schema.Evidence{Source: fmt.Sprintf("ci_runs_on__%s", sanitizeSource(jobName)), Value: scalarOrSequenceValue(val)})
		case "needs":
			pw.metadata = append(pw.metadata, schema.Evidence{Source: fmt.Sprintf("ci_needs__%s", sanitizeSource(jobName)), Value: scalarOrSequenceValue(val)})
		case "if":
			if val.Kind == yaml.ScalarNode {
				pw.metadata = append(pw.metadata, schema.Evidence{Source: fmt.Sprintf("ci_if__job__%s", sanitizeSource(jobName)), Value: val.Value})
			}
		case "permissions":
			pw.parsePermissions("job", jobName, val)
		case "uses":
			if val.Kind == yaml.ScalarNode {
				pw.metadata = append(pw.metadata, schema.Evidence{Source: fmt.Sprintf("ci_reusable_workflow__%s", sanitizeSource(jobName)), Value: val.Value})
			}
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
					pw.extractActionMetadata(jobName, stepIdx, action, stepNode)
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
		if key == "node-version" || key == "python-version" || key == "go-version" || key == "ruby-version" || key == "dotnet-version" {
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

func (pw *parsedWorkflow) extractActionMetadata(jobName string, stepIdx int, action string, stepNode *yaml.Node) {
	if strings.HasPrefix(action, "./") || strings.HasPrefix(action, ".github/") {
		pw.metadata = append(pw.metadata, schema.Evidence{
			Source: fmt.Sprintf("ci_composite_action__%s__%d", sanitizeSource(jobName), stepIdx),
			Value:  action,
		})
	}
	if action != "actions/cache@v4" && !strings.HasPrefix(action, "actions/cache@") {
		return
	}
	withNode := mappingChild(stepNode, "with")
	if withNode == nil {
		return
	}
	for i := 0; i < len(withNode.Content); i += 2 {
		if withNode.Content[i].Value == "key" && withNode.Content[i+1].Kind == yaml.ScalarNode {
			pw.metadata = append(pw.metadata, schema.Evidence{
				Source: fmt.Sprintf("ci_cache__%s__%d__key", sanitizeSource(jobName), stepIdx),
				Value:  withNode.Content[i+1].Value,
			})
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

func (pw *parsedWorkflow) parseTriggers(node *yaml.Node) {
	if node.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == "workflow_call" {
			pw.metadata = append(pw.metadata, schema.Evidence{Source: "ci_workflow_call__present", Value: "true"})
		}
	}
}

func (pw *parsedWorkflow) parsePermissions(scope, jobName string, node *yaml.Node) {
	if node.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i < len(node.Content); i += 2 {
		key := sanitizeSource(node.Content[i].Value)
		val := node.Content[i+1]
		value := scalarOrSequenceValue(val)
		if value == "" {
			continue
		}
		if scope == "workflow" {
			pw.metadata = append(pw.metadata, schema.Evidence{Source: "ci_permissions__workflow__" + key, Value: value})
			continue
		}
		pw.metadata = append(pw.metadata, schema.Evidence{Source: fmt.Sprintf("ci_permissions__job__%s__%s", sanitizeSource(jobName), key), Value: value})
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
			case "options":
				if v.Kind == yaml.ScalarNode {
					svc.Options = v.Value
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

func (pw *parsedWorkflow) parseStrategy(jobName string, node *yaml.Node) {
	if node.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == "matrix" {
			pw.parseMatrix(jobName, node.Content[i+1])
			return
		}
	}
}

func (pw *parsedWorkflow) parseMatrix(jobName string, node *yaml.Node) {
	if node.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i < len(node.Content); i += 2 {
		runtimeName, versionKey, ok := matrixRuntimeKey(node.Content[i].Value)
		if !ok {
			continue
		}
		for _, value := range scalarValues(node.Content[i+1]) {
			pw.matrix = append(pw.matrix, matrixRuntimeEvidence{
				Job:        jobName,
				Runtime:    runtimeName,
				VersionKey: versionKey,
				Value:      value,
			})
		}
	}
}

func matrixRuntimeKey(key string) (runtimeName, versionKey string, ok bool) {
	switch key {
	case "node", "node-version":
		return "setup-node", "node-version", true
	case "python", "python-version":
		return "setup-python", "python-version", true
	case "go", "go-version":
		return "setup-go", "go-version", true
	case "ruby", "ruby-version":
		return "setup-ruby", "ruby-version", true
	case "dotnet", "dotnet-version":
		return "setup-dotnet", "dotnet-version", true
	default:
		return "", "", false
	}
}

func scalarValues(node *yaml.Node) []string {
	switch node.Kind {
	case yaml.ScalarNode:
		if strings.TrimSpace(node.Value) == "" {
			return nil
		}
		return []string{strings.TrimSpace(node.Value)}
	case yaml.SequenceNode:
		values := make([]string, 0, len(node.Content))
		for _, item := range node.Content {
			if item.Kind != yaml.ScalarNode || strings.TrimSpace(item.Value) == "" {
				continue
			}
			values = append(values, strings.TrimSpace(item.Value))
		}
		return values
	default:
		return nil
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
			if strings.Contains(svc.Image, "docker:dind") {
				ev = append(ev, schema.Evidence{
					Source: fmt.Sprintf("ci_dind__%s", job),
					Value:  svc.Image,
				})
			}
		}
		if svc.Options != "" {
			ev = append(ev, schema.Evidence{
				Source: fmt.Sprintf("ci_service__%s__%s__options", job, name),
				Value:  svc.Options,
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

	for idx, item := range pw.matrix {
		ev = append(ev, schema.Evidence{
			Source: fmt.Sprintf("ci_setup__%s__matrix_%d__%s__%s", sanitizeSource(item.Job), idx, sanitizeSource(item.Runtime), sanitizeSource(item.VersionKey)),
			Value:  item.Value,
		})
	}

	ev = append(ev, pw.metadata...)

	return ev
}

func parseGitLabCI(path string) ([]schema.Evidence, error) {
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
	if start.Kind != yaml.MappingNode {
		return nil, nil
	}

	ev := []schema.Evidence{{Source: "ci_platform", Value: "gitlab"}}
	for i := 0; i < len(start.Content); i += 2 {
		key := start.Content[i].Value
		val := start.Content[i+1]
		switch key {
		case "image":
			image := scalarOrMappingImage(val)
			if image != "" {
				ev = append(ev,
					schema.Evidence{Source: "ci_container__workflow__image", Value: image},
				)
				ev = append(ev, runtimeEvidenceFromImage("workflow", "image", image)...)
			}
		case "variables":
			ev = append(ev, envEvidenceFromGitLabVariables("workflow", val)...)
		case "cache":
			if cacheKey := gitLabCacheKey(val); cacheKey != "" {
				ev = append(ev, schema.Evidence{Source: "ci_cache__workflow__key", Value: cacheKey})
			}
		default:
			if isGitLabReservedKey(key) || val.Kind != yaml.MappingNode {
				continue
			}
			ev = append(ev, gitLabJobEvidence(key, val)...)
		}
	}
	return ev, nil
}

func gitLabJobEvidence(jobName string, node *yaml.Node) []schema.Evidence {
	var ev []schema.Evidence
	for i := 0; i < len(node.Content); i += 2 {
		key := node.Content[i].Value
		val := node.Content[i+1]
		switch key {
		case "image":
			image := scalarOrMappingImage(val)
			if image != "" {
				ev = append(ev, schema.Evidence{Source: fmt.Sprintf("ci_container__%s__image", sanitizeSource(jobName)), Value: image})
				ev = append(ev, runtimeEvidenceFromImage(jobName, "image", image)...)
			}
		case "variables":
			ev = append(ev, envEvidenceFromGitLabVariables(jobName, val)...)
		case "services":
			ev = append(ev, gitLabServiceEvidence(jobName, val)...)
		case "script":
			for idx, cmd := range scalarValues(val) {
				ev = append(ev, schema.Evidence{Source: fmt.Sprintf("ci_run__%s__%d", sanitizeSource(jobName), idx), Value: cmd})
			}
		case "cache":
			if cacheKey := gitLabCacheKey(val); cacheKey != "" {
				ev = append(ev, schema.Evidence{Source: fmt.Sprintf("ci_cache__%s__key", sanitizeSource(jobName)), Value: cacheKey})
			}
		}
	}
	return ev
}

func envEvidenceFromGitLabVariables(scope string, node *yaml.Node) []schema.Evidence {
	if node.Kind != yaml.MappingNode {
		return nil
	}
	ev := make([]schema.Evidence, 0, len(node.Content)/2)
	for i := 0; i < len(node.Content); i += 2 {
		key := sanitizeSource(node.Content[i].Value)
		value := scalarOrSequenceValue(node.Content[i+1])
		if scope == "workflow" {
			ev = append(ev, schema.Evidence{Source: "ci_env__workflow__" + key, Value: value})
			continue
		}
		ev = append(ev, schema.Evidence{Source: fmt.Sprintf("ci_env__job__%s__%s", sanitizeSource(scope), key), Value: value})
	}
	return ev
}

func gitLabServiceEvidence(jobName string, node *yaml.Node) []schema.Evidence {
	var ev []schema.Evidence
	for idx, serviceNode := range scalarValues(node) {
		image := serviceNode
		name := imageName(image)
		if name == "" {
			name = fmt.Sprintf("service_%d", idx)
		}
		ev = append(ev, schema.Evidence{Source: fmt.Sprintf("ci_service__%s__%s__image", sanitizeSource(jobName), sanitizeSource(name)), Value: image})
	}
	return ev
}

func gitLabCacheKey(node *yaml.Node) string {
	if node.Kind == yaml.ScalarNode {
		return node.Value
	}
	if node.Kind != yaml.MappingNode {
		return ""
	}
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == "key" {
			return scalarOrSequenceValue(node.Content[i+1])
		}
	}
	return ""
}

func runtimeEvidenceFromImage(jobName, step string, image string) []schema.Evidence {
	name, version := runtimeFromImage(image)
	if name == "" || version == "" {
		return nil
	}
	return []schema.Evidence{{
		Source: fmt.Sprintf("ci_setup__%s__%s__%s__%s", sanitizeSource(jobName), sanitizeSource(step), sanitizeSource(name), "node_version"),
		Value:  version,
	}}
}

func runtimeFromImage(image string) (runtimeName, version string) {
	ref := strings.TrimSpace(image)
	if idx := strings.LastIndex(ref, "/"); idx != -1 {
		ref = ref[idx+1:]
	}
	parts := strings.SplitN(ref, ":", 2)
	if len(parts) != 2 {
		return "", ""
	}
	switch parts[0] {
	case "node":
		return "setup_node", parts[1]
	default:
		return "", ""
	}
}

func imageName(image string) string {
	ref := strings.TrimSpace(image)
	if idx := strings.LastIndex(ref, "/"); idx != -1 {
		ref = ref[idx+1:]
	}
	if idx := strings.Index(ref, ":"); idx != -1 {
		ref = ref[:idx]
	}
	return ref
}

func isGitLabReservedKey(key string) bool {
	switch key {
	case "stages", "variables", "image", "services", "cache", "include", "workflow", "default", "before_script", "after_script":
		return true
	default:
		return strings.HasPrefix(key, ".")
	}
}

func mappingChild(node *yaml.Node, key string) *yaml.Node {
	if node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func scalarOrMappingImage(node *yaml.Node) string {
	if node.Kind == yaml.ScalarNode {
		return strings.TrimSpace(node.Value)
	}
	if child := mappingChild(node, "name"); child != nil && child.Kind == yaml.ScalarNode {
		return strings.TrimSpace(child.Value)
	}
	return ""
}

func scalarOrSequenceValue(node *yaml.Node) string {
	switch node.Kind {
	case yaml.ScalarNode:
		return strings.TrimSpace(node.Value)
	case yaml.SequenceNode:
		return strings.Join(scalarValues(node), ", ")
	default:
		return ""
	}
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
	return escapeSourceSegment(b.String())
}

func escapeSourceSegment(s string) string {
	return strings.ReplaceAll(s, "__", "%5F%5F")
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
