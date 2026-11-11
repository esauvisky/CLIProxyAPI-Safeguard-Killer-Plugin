package main

import "time"

// hostAuth is one credential from the host.auth.list callback (pluginapi.HostAuthFileEntry).
type hostAuth struct {
	ID             string    `json:"id"`
	AuthIndex      string    `json:"auth_index"`
	Name           string    `json:"name"`
	Provider       string    `json:"provider"`
	Label          string    `json:"label"`
	Email          string    `json:"email"`
	Status         string    `json:"status"`
	Disabled       bool      `json:"disabled"`
	Unavailable    bool      `json:"unavailable"`
	NextRetryAfter time.Time `json:"next_retry_after"`
}

// quotaWindow is one rate-limit window of a credential, normalized across providers.
type quotaWindow struct {
	// Name labels the window for display, e.g. "7d", "5h", "weekly", "Claude and GPT models: weekly".
	Name string `json:"name"`
	// Remaining is the unused fraction of the window, 0..1.
	Remaining float64 `json:"remaining"`
	// ResetAt is when the window refills; zero when the provider does not report it.
	ResetAt time.Time `json:"reset_at"`
	// Period is the window length (5h, 7d, 30d, ...); zero when unknown.
	Period time.Duration `json:"period"`
	// Models lists the model IDs the window applies to; empty means every model of the credential.
	Models []string `json:"models,omitempty"`
}

// credentialQuota is the latest quota snapshot of one credential.
type credentialQuota struct {
	AuthID    string        `json:"auth_id"`
	AuthIndex string        `json:"auth_index"`
	Provider  string        `json:"provider"`
	Source    string        `json:"source"`
	Plan      string        `json:"plan,omitempty"`
	Windows   []quotaWindow `json:"windows"`
	FetchedAt time.Time     `json:"fetched_at"`
	// Error is the last fetch failure; a credential with an error is not ranked.
	Error string `json:"error,omitempty"`
}

// rankEntry is one credential's evaluation for a spread decision.
type rankEntry struct {
	AuthID    string  `json:"auth_id"`
	Provider  string  `json:"provider"`
	Window    string  `json:"window,omitempty"`
	Remaining float64 `json:"remaining"`
	// HoursToReset is the time until the bottleneck window resets.
	HoursToReset float64 `json:"hours_to_reset"`
	// Rate is the lowest remaining / hours_to_reset among applicable windows.
	Rate float64 `json:"rate"`
	// Weight is the account's configured priority multiplier (default 1).
	Weight float64 `json:"weight"`
	// Load counts active credential session bindings, not in-flight requests.
	Load int `json:"load"`
	// Score is Rate * Weight / (1+Load).
	Score float64 `json:"score"`
	// Excluded explains why the credential was not eligible; empty when eligible.
	Excluded string `json:"excluded,omitempty"`
}

// decision is one routing or scheduling choice, kept in a ring buffer for the UI.
type decision struct {
	Time time.Time `json:"time"`
	// Kind is "balance" (credential pick for a model) or "group" (model group fallback).
	Kind    string `json:"kind"`
	Model   string `json:"model"`
	Session string `json:"session,omitempty"`
	// AuthID is the chosen credential for "balance" and the serving model for "group".
	AuthID string `json:"auth_id,omitempty"`
	// Version is the plugin version that recorded this decision.
	Version     string         `json:"version,omitempty"`
	Reason      string         `json:"reason"`
	Ranking     []rankEntry    `json:"ranking,omitempty"`
	Attempts    []groupAttempt `json:"attempts,omitempty"`
	Mode        string         `json:"mode,omitempty"`
	ModelScores []modelScore   `json:"model_scores,omitempty"`
}

// modelSessionState tracks how a model in a Smart Group failed within a specific session.
type modelSessionState struct {
	FailureKind   string    `json:"failure_kind"`
	Reason        string    `json:"reason,omitempty"`
	RefusalCount  int       `json:"refusal_count,omitempty"`
	FailedAtTurn  int       `json:"failed_at_turn,omitempty"`
	FailedAtBytes int       `json:"failed_at_bytes,omitempty"`
	FailedAt      time.Time `json:"failed_at"`
}

// sessionBinding pins a client session to a credential or Smart Group model.
type sessionBinding struct {
	Session  string    `json:"session"`
	AuthID   string    `json:"auth_id"`
	Provider string    `json:"provider"`
	Model    string    `json:"model"`
	BoundAt  time.Time `json:"bound_at"`
	LastSeen time.Time `json:"last_seen"`
	// IdleExpiresAt is LastSeen + idle_minutes; after it the next prompt re-picks.
	IdleExpiresAt         time.Time                     `json:"idle_expires_at"`
	Turns                 int                           `json:"turns,omitempty"`
	LastPayloadBytes      int                           `json:"last_payload_bytes,omitempty"`
	LastMessageCount      int                           `json:"last_message_count,omitempty"`
	LastInputTokens       int                           `json:"last_input_tokens,omitempty"`
	LastCacheReadTokens   int                           `json:"last_cache_read_tokens,omitempty"`
	LastCacheCreateTokens int                           `json:"last_cache_create_tokens,omitempty"`
	CacheWarm             bool                          `json:"cache_warm,omitempty"`
	LastTipTurn           int                           `json:"last_tip_turn,omitempty"`
	ModelStates           map[string]*modelSessionState `json:"model_states,omitempty"`
}

// uiState is the JSON served to the management page.
type uiState struct {
	Version     string           `json:"version"`
	Now         time.Time        `json:"now"`
	Config      pluginConfig     `json:"config"`
	Credentials []uiCredential   `json:"credentials"`
	Sessions    []sessionBinding `json:"sessions"`
	Decisions   []decision       `json:"decisions"`
	// Models lists every model ID served by a credential, for the group editor.
	Models []string `json:"models"`
	// Error is set when the host credential list could not be read.
	Error string `json:"error,omitempty"`
	// ManagementError explains why quota collection is not running (no key, rejected key, IP ban).
	ManagementError string `json:"management_error,omitempty"`
	// Metrics aggregates routing decisions for the metrics chart row.
	Metrics routingMetrics `json:"metrics"`
}

// uiCredential joins a credential with its models and quota.
type uiCredential struct {
	Auth  hostAuth        `json:"auth"`
	Quota credentialQuota `json:"quota"`
	// HasQuota reports whether Quota holds a fetched snapshot.
	HasQuota bool     `json:"has_quota"`
	Models   []string `json:"models"`
}
