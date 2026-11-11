package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	// groupProvider is the executor identifier model groups are registered and executed under.
	groupProvider = "model-groups"

	groupModeQuality = "quality"
	groupModeCost    = "cost"
)

// executorFormats lists every client protocol; group requests pass through in the client's own format.
var executorFormats = []string{"openai", "openai-response", "claude", "gemini", "codex", "antigravity", "interactions"}

type lifecycleRequest struct {
	ConfigYAML    []byte `json:"config_yaml"`
	SchemaVersion uint32 `json:"schema_version"`
}

type registration struct {
	SchemaVersion uint32                   `json:"schema_version"`
	Metadata      pluginMetadata           `json:"metadata"`
	Capabilities  registrationCapabilities `json:"capabilities"`
}

type pluginMetadata struct {
	Name             string        `json:"Name"`
	Version          string        `json:"Version"`
	Author           string        `json:"Author"`
	GitHubRepository string        `json:"GitHubRepository"`
	Logo             string        `json:"Logo"`
	ConfigFields     []configField `json:"ConfigFields"`
}

type configField struct {
	Name        string `json:"Name"`
	Type        string `json:"Type"`
	Default     any    `json:"Default,omitempty"`
	Description string `json:"Description"`
}

type registrationCapabilities struct {
	Scheduler             bool     `json:"scheduler"`
	ModelRegistrar        bool     `json:"model_registrar"`
	ModelRouter           bool     `json:"model_router"`
	ManagementAPI         bool     `json:"management_api"`
	Executor              bool     `json:"executor"`
	ExecutorModelScope    string   `json:"executor_model_scope"`
	ExecutorInputFormats  []string `json:"executor_input_formats"`
	ExecutorOutputFormats []string `json:"executor_output_formats"`
	RequestInterceptor    bool     `json:"request_interceptor"`
	StreamInterceptor     bool     `json:"response_stream_interceptor"`
	RequestLifecycle      bool     `json:"request_lifecycle_plugin"`
}

type pluginConfig struct {
	// MinRemaining is the fraction every applicable quota window must keep for a credential to be used.
	MinRemaining float64 `yaml:"min_remaining" json:"min_remaining"`
	// IdleMinutes is how long a session may go without a prompt before it can move to another credential.
	IdleMinutes int `yaml:"idle_minutes" json:"idle_minutes"`
	// StreamPrefetchBytes is how many bytes of visible text executeGroupStream buffers before
	// committing to a candidate model, so prompt-level, thinking-phase, and streaming safeguard or
	// text refusals can switch to the next model in the group before any chunk is sent.
	StreamPrefetchBytes int           `yaml:"stream_prefetch_bytes" json:"stream_prefetch_bytes"`
	ManagementKey       string        `yaml:"management_key" json:"-"`
	Groups              []modelGroup  `yaml:"groups" json:"groups"`
	Features            featureConfig `yaml:"features" json:"features"`
	// LegacyManagement reads existing management.key configs on upgrade.
	LegacyManagement struct {
		Key string `yaml:"key" json:"key"`
	} `yaml:"management,omitempty" json:"-"`
}

// featureConfig controls safeguard and client-wire adaptations.
type featureConfig struct {
	FallbackOnRefusal             bool   `yaml:"fallback_on_refusal" json:"fallback_on_refusal"`
	ClientFallbackNotices         bool   `yaml:"client_fallback_notices" json:"client_fallback_notices"`
	VerboseNotices                bool   `yaml:"verbose_notices" json:"verbose_notices"`
	NoticePrefix                  string `yaml:"notice_prefix" json:"notice_prefix"`
	RewriteCyberSystemPrompt      bool   `yaml:"rewrite_cyber_system_prompt" json:"rewrite_cyber_system_prompt"`
	StripRefusalTaintHeaders      bool   `yaml:"strip_refusal_taint_headers" json:"strip_refusal_taint_headers"`
	DisableUpstreamServerFallback bool   `yaml:"disable_upstream_server_fallback" json:"disable_upstream_server_fallback"`
	BypassAutoModeClassifier      bool   `yaml:"bypass_auto_mode_classifier" json:"bypass_auto_mode_classifier"`
	NeutralizeClassifierStopNudge bool   `yaml:"neutralize_classifier_stop_nudges" json:"neutralize_classifier_stop_nudges"`
	StripRestrictiveReminders     bool   `yaml:"strip_restrictive_system_reminders" json:"strip_restrictive_system_reminders"`
}

func (f featureConfig) effectiveNoticePrefix() string {
	if f.NoticePrefix != "" {
		return f.NoticePrefix
	}
	return defaultNoticePrefix
}

type modelGroup struct {
	ID     string       `yaml:"id" json:"id"`
	Name   string       `yaml:"name" json:"name"`
	Mode   string       `yaml:"mode" json:"mode"`
	Models []groupModel `yaml:"models" json:"models"`
}

type groupModel struct {
	ID      string  `yaml:"id" json:"id"`
	Quality float64 `yaml:"quality" json:"quality"`
	Cost    float64 `yaml:"cost" json:"cost"`
}

func (g *modelGroup) UnmarshalJSON(raw []byte) error {
	type plain modelGroup
	var decoded plain
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return fmt.Errorf("group needs {id, name, mode, models: [{id, quality, cost}]}: %w", err)
	}
	*g = modelGroup(decoded)
	return nil
}

func (g *modelGroup) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("group must be a mapping with id, name, mode, models")
	}
	for i := 0; i < len(node.Content); i += 2 {
		switch node.Content[i].Value {
		case "id", "name", "mode", "models":
		default:
			return fmt.Errorf("unknown group field %q; use mode: quality or cost and rated model entries", node.Content[i].Value)
		}
	}
	type plain modelGroup
	var decoded plain
	if err := node.Decode(&decoded); err != nil {
		return err
	}
	*g = modelGroup(decoded)
	return nil
}

func (m *groupModel) UnmarshalJSON(raw []byte) error {
	var decoded struct {
		ID string `json:"id"`
		Quality *float64 `json:"quality"`
		Cost *float64 `json:"cost"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	if decoded.Quality == nil || decoded.Cost == nil {
		return fmt.Errorf("model %q needs explicit quality and cost ratings (0–100)", decoded.ID)
	}
	*m = groupModel{ID: decoded.ID, Quality: *decoded.Quality, Cost: *decoded.Cost}
	return nil
}

func (m *groupModel) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("model must be {id, quality, cost}; string model lists are no longer supported")
	}
	for i := 0; i < len(node.Content); i += 2 {
		switch node.Content[i].Value {
		case "id", "quality", "cost":
		default:
			return fmt.Errorf("unknown model field %q", node.Content[i].Value)
		}
	}
	var decoded struct {
		ID string `yaml:"id"`
		Quality *float64 `yaml:"quality"`
		Cost *float64 `yaml:"cost"`
	}
	if err := node.Decode(&decoded); err != nil {
		return err
	}
	if decoded.Quality == nil || decoded.Cost == nil {
		return fmt.Errorf("model %q needs explicit quality and cost ratings (0–100)", decoded.ID)
	}
	*m = groupModel{ID: decoded.ID, Quality: *decoded.Quality, Cost: *decoded.Cost}
	return nil
}

var activeConfig atomic.Value

func init() {
	activeConfig.Store(defaultPluginConfig())
	loadPersistedSessions(time.Now())
}

func defaultPluginConfig() pluginConfig {
	return pluginConfig{
		MinRemaining:        0.02,
		IdleMinutes:         5,
		StreamPrefetchBytes: 128,
		Features: featureConfig{
			FallbackOnRefusal:             true,
			ClientFallbackNotices:         true,
			NoticePrefix:                  defaultNoticePrefix,
			RewriteCyberSystemPrompt:      true,
			StripRefusalTaintHeaders:      true,
			DisableUpstreamServerFallback: true,
			BypassAutoModeClassifier:      true,
			NeutralizeClassifierStopNudge: true,
			StripRestrictiveReminders:     true,
		},
	}
}

func currentConfig() pluginConfig {
	return activeConfig.Load().(pluginConfig)
}

func configurePlugin(raw []byte) error {
	var req lifecycleRequest
	if len(raw) > 0 {
		if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
			return errUnmarshal
		}
	}
	cfg := defaultPluginConfig()
	if len(req.ConfigYAML) > 0 {
		if errUnmarshal := yaml.Unmarshal(req.ConfigYAML, &cfg); errUnmarshal != nil {
			return errUnmarshal
		}
	}
	if cfg.ManagementKey == "" && cfg.LegacyManagement.Key != "" {
		cfg.ManagementKey = cfg.LegacyManagement.Key
	}
	if errValidate := validateConfig(cfg); errValidate != nil {
		return errValidate
	}
	activeConfig.Store(cfg)
	return nil
}

func validateConfig(cfg pluginConfig) error {
	if cfg.MinRemaining < 0 || cfg.MinRemaining >= 1 {
		return fmt.Errorf("min_remaining must be in [0, 1), got %v", cfg.MinRemaining)
	}
	if cfg.IdleMinutes < 0 {
		return fmt.Errorf("idle_minutes must be non-negative, got %d", cfg.IdleMinutes)
	}
	if cfg.StreamPrefetchBytes < 1 {
		return fmt.Errorf("stream_prefetch_bytes must be at least 1, got %d", cfg.StreamPrefetchBytes)
	}
	ids := make(map[string]bool, len(cfg.Groups))
	for index, group := range cfg.Groups {
		if group.ID == "" {
			return fmt.Errorf("groups[%d] needs an id", index)
		}
		if ids[group.ID] {
			return fmt.Errorf("group id %s is used twice", group.ID)
		}
		ids[group.ID] = true
		if group.Name == "" {
			return fmt.Errorf("group %s needs a name", group.ID)
		}
		if len(group.Models) == 0 {
			return fmt.Errorf("group %s needs at least one model", group.ID)
		}
		if group.Mode != groupModeQuality && group.Mode != groupModeCost {
			return fmt.Errorf("group %s needs mode quality or cost, got %q", group.ID, group.Mode)
		}
		models := make(map[string]bool, len(group.Models))
		for _, model := range group.Models {
			if model.ID == "" || models[model.ID] {
				return fmt.Errorf("group %s has an empty or duplicate model id %q", group.ID, model.ID)
			}
			models[model.ID] = true
			if math.IsNaN(model.Quality) || math.IsInf(model.Quality, 0) || model.Quality < 0 || model.Quality > 100 ||
				math.IsNaN(model.Cost) || math.IsInf(model.Cost, 0) || model.Cost < 0 || model.Cost > 100 {
				return fmt.Errorf("group %s model %s: quality and cost must be finite ratings in [0, 100]", group.ID, model.ID)
			}
		}
	}
	for _, group := range cfg.Groups {
		for _, model := range group.Models {
			if ids[model.ID] {
				return fmt.Errorf("group %s lists group %s as a target; groups cannot nest", group.ID, model.ID)
			}
		}
	}
	return nil
}

func (cfg pluginConfig) group(id string) (modelGroup, bool) {
	for _, group := range cfg.Groups {
		if group.ID == id {
			return group, true
		}
	}
	return modelGroup{}, false
}

func pluginRegistration() registration {
	return registration{
		SchemaVersion: schemaVersion,
		Metadata: pluginMetadata{
			Name:             pluginName,
			Version:          pluginVersion,
			Author:           pluginAuthor,
			GitHubRepository: pluginRepo,
			Logo:             pluginLogo,
			ConfigFields: []configField{
				{Name: "management_key", Type: "string", Description: "Required: CPA management key used to read provider quota and save settings from the UI."},
				{Name: "min_remaining", Type: "number", Default: 0.02, Description: "Quota fraction (0-1) every window of a credential must keep for it to be used."},
				{Name: "idle_minutes", Type: "integer", Default: 5, Description: "Minutes without a prompt after which a credential binding may re-rank (0 disables credential affinity). Group model bindings last until compaction, reset, or failure."},
				{Name: "stream_prefetch_bytes", Type: "integer", Default: 128, Description: "Bytes of visible text a smart group stream buffers and checks for refusals before forwarding to the client."},
				{Name: "groups", Type: "array", Description: "Smart Groups ({id, name, mode: quality|cost, models: [{id, quality, cost}]}). Ratings are 0–100; higher quality is better, higher cost is more expensive. Weighted selection among models within 3 score points of the best; conversations stay pinned until compaction, reset, or failure."},
				{Name: "features", Type: "object", Description: "Safeguard and client-wire adaptation toggles and custom notice_prefix."},
			},
		},
		Capabilities: registrationCapabilities{
			Scheduler:             true,
			ModelRegistrar:        true,
			ModelRouter:           true,
			ManagementAPI:         true,
			Executor:              true,
			ExecutorModelScope:    "static",
			ExecutorInputFormats:  executorFormats,
			ExecutorOutputFormats: executorFormats,
			RequestInterceptor:    true,
			StreamInterceptor:     true,
			RequestLifecycle:      true,
		},
	}
}
