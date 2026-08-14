package webhooks

import (
	"os"
	"path/filepath"
	"testing"
)

// writeFile persists a config document in the test dir and returns its path.
func writeFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoad_ValidMinimalConfig(t *testing.T) {
	cfg, err := Load(writeFile(t, "webhooks: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Webhooks.Slack.Enabled || cfg.Webhooks.PagerDuty.Enabled {
		t.Error("opt-in providers must default to disabled")
	}
	if cfg.Token.PEM != "" || cfg.Token.JWKSURL != "" {
		t.Error("token section must default to empty (Stage 2 compatibility)")
	}
}

func TestLoad_SlackWithEndpoint(t *testing.T) {
	cfg, err := Load(writeFile(t, `
webhooks:
  slack:
    enabled: true
    url: https://hooks.slack.example/services/T00/B00/xxxx
  pagerduty:
    enabled: false
token:
  audience: mcpgw
`))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Webhooks.Slack.Enabled || cfg.Webhooks.Slack.URL == "" {
		t.Error("slack provider must carry its endpoint")
	}
	if cfg.Token.Audience != "mcpgw" {
		t.Errorf("audience: %q", cfg.Token.Audience)
	}
}

func TestLoad_EnabledWithoutEndpointRejected(t *testing.T) {
	errs := map[string]string{
		"slack without url": `
webhooks:
  slack: {enabled: true}
  pagerduty: {enabled: false}
`,
		"pagerduty without routing_key": `
webhooks:
  slack: {enabled: false}
  pagerduty: {enabled: true}
`,
	}
	for name, body := range errs {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeFile(t, body)); err == nil {
				t.Error("enabled provider without endpoint must fail validation")
			}
		})
	}
}

func TestLoad_UnknownKeysRejected(t *testing.T) {
	cases := map[string]string{
		"top-level typo": "webhooks: {}\nwebhookss: {}\n",
		"unknown provider": `
webhooks:
  slack: {enabled: false}
  pagerduty: {enabled: false}
  teams: {enabled: true, url: "https://x"}
`,
		"missing webhooks": "token: {audience: x}\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeFile(t, body)); err == nil {
				t.Errorf("%s must be rejected", name)
			}
		})
	}
}

func TestLoad_JWKSRequiresTLS(t *testing.T) {
	if _, err := Load(writeFile(t, `
webhooks: {}
token:
  jwks_url: https://auth.example/.well-known/jwks.json
`)); err == nil {
		t.Error("JWKS without TLS must be a hard configuration error")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	if _, err := Load("/no-such-file/config.yaml"); err == nil {
		t.Error("missing config file must error")
	}
}

func TestDefaultConfig_RateLimitingOnByDefault(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.RateLimit.RequestsPerSecond <= 0 {
		t.Error("default config must enable rate limiting")
	}
}
