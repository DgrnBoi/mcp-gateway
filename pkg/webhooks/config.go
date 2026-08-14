package webhooks

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/antigravity/mcp-gateway/pkg/identity"
	"github.com/antigravity/mcp-gateway/pkg/server"
)

// Config is the gateway's operational configuration. It is deliberately
// separate from policy.yaml: policy.yaml is the GitOps enforcement artifact
// reviewers sign off on; config.yaml carries endpoints and notification
// settings, which change without forcing a policy review cycle.
type Config struct {
	Webhooks WebhooksConfig          `yaml:"webhooks"`
	Token    TokenConfig             `yaml:"token"`
	TLS      identity.TLSConfig      `yaml:"tls"`
	RateLimit server.RateLimitConfig `yaml:"ratelimit"`
}

// TokenConfig is the YAML surface for Ticket 14 (JWT binding). At least
// one of PEM or JWKSURL must be set for token validation to be active;
// an empty section leaves the gateway in Stage 2 header-hash mode
// (backward compatible). PEM carries the public key text inline so the
// whole identity surface stays in one GitOps-friendly file.
type TokenConfig struct {
	PEM      string `yaml:"pem,omitempty"`
	JWKSURL  string `yaml:"jwks_url,omitempty"`
	Audience string `yaml:"audience,omitempty"`
}

// WebhooksConfig is the only supported top-level section. Unknown keys at
// the webhook level or inside a provider block are hard errors.
type WebhooksConfig struct {
	Slack     ProviderConfig `yaml:"slack"`
	PagerDuty ProviderConfig `yaml:"pagerduty"`
}

// ProviderConfig is shared by all webhook providers. An enabled provider
// with an empty endpoint is a hard error: silent failures that fill the
// dead-letter queue from a typo'd URL are worse than a startup failure.
type ProviderConfig struct {
	Enabled bool `yaml:"enabled"`
	// Slack uses URL; PagerDuty uses RoutingKey; GitHub PRs use GitHubToken.
	// Only the key relevant to the provider needs to be set.
	URL         string `yaml:"url,omitempty"`
	RoutingKey  string `yaml:"routing_key,omitempty"`
	GitHubToken string `yaml:"github_token,omitempty"`
}

// Load reads and validates a config.yaml. Unknown webhook keys and
// enabled-with-empty-endpoint providers are hard errors.
func Load(path string) (Config, error) {
	cfg := DefaultConfig()

	// Decode once to preserve unknown fields for validation, then unmarshal.
	src, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("reading config: %w", err)
	}
	if err := yaml.Unmarshal(src, &cfg); err != nil {
		return cfg, fmt.Errorf("parsing config: %w", err)
	}
	if err := cfg.validate(src); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// DefaultConfig returns the production defaults: rate limiting on at
// 10 RPS, all other Stage 3 features opt-in (backward compatible with
// Stage 2 configs).
func DefaultConfig() Config {
	return Config{
		RateLimit: server.DefaultRateLimitConfig(),
	}
}

// validate hard-fails on enabled providers missing their endpoint and on
// unknown top-level or provider keys.
func (c *Config) validate(src []byte) error {
	// Ticket 14: JWKS fetches key material over the network — that
	// transport must itself be protected, so JWKS without TLS is a
	// hard configuration error, not a silent downgrade.
	if c.Token.JWKSURL != "" && c.Token.PEM == "" && !c.TLS.Enabled {
		return fmt.Errorf("token.jwks_url is set without tls enabled — JWKS key material must travel over TLS")
	}
	if c.Webhooks.Slack.Enabled && c.Webhooks.Slack.URL == "" {
		return fmt.Errorf("webhooks.slack is enabled but url is empty")
	}
	if c.Webhooks.PagerDuty.Enabled && c.Webhooks.PagerDuty.RoutingKey == "" {
		return fmt.Errorf("webhooks.pagerduty is enabled but routing_key is empty")
	}

	var raw map[string]any
	if err := yaml.Unmarshal(src, &raw); err != nil {
		return fmt.Errorf("parsing config for unknown-key check: %w", err)
	}
	// Top-level sections: exactly 'webhooks' plus the opt-in Stage 3
	// blocks (token, tls, ratelimit).
	for k := range raw {
		switch k {
		case "webhooks", "token", "tls", "ratelimit":
			// known
		default:
			return fmt.Errorf("unknown top-level config key: %q (supported: webhooks, token, tls, ratelimit)", k)
		}
	}
	if _, ok := raw["webhooks"]; !ok {
		return fmt.Errorf("missing required 'webhooks' section")
	}

	wh, ok := raw["webhooks"].(map[string]any)
	if !ok {
		return fmt.Errorf("'webhooks' is not a mapping")
	}
	known := map[string]bool{"slack": true, "pagerduty": true}
	for k := range wh {
		if !known[k] {
			return fmt.Errorf("unknown webhook provider: %q (supported: slack, pagerduty)", k)
		}
	}
	return nil
}
