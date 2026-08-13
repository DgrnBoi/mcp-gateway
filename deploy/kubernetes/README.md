# Kubernetes Deployment Reference

Reference manifests for running the MCP Security Gateway in Kubernetes.
These are deliberately simple, dependency-free YAML — the Helm chart in
`../helm/mcp-gateway/` generates equivalent (but parameterized) output.

## Files

| File | Purpose |
|------|---------|
| `deployment.yaml` | Rolling-update Deployment, non-root, probes |
| `service.yaml` | Exposes ONLY the proxy port (9090); console stays internal |
| `configmap.yaml` | `policy.yaml` + `config.yaml`; hot-reload via mtime bump |
| `config.yaml` (root) | Gateway CLI args and webhook/JWT/mTLS/rate-limit config |

## Health check contract

The readiness probe hits `GET /healthz` on the proxy port. The gateway
responds `200 {"status":"ok"}` on `/healthz` for all requests, including
unauthenticated ones — this endpoint deliberately performs **no policy
evaluation** and carries no client identity, because readiness must not
fail an otherwise healthy pod due to identity configuration.

If you pin an older gateway image without `/healthz`, replace the probe
path with `/` on the console port.

## Console access (defense in depth)

The console (9091) is not exposed by the `mcp-gateway` Service. Reach it
via `kubectl port-forward` for triage, or front it with an internal ingress
that terminates your own SSO — the console has no authentication of its
own until Stage 5 (Ticket 20: Console RBAC).

## Sidecar pattern (how apps consume the gateway)

The supported v1 pattern is explicit pod-level injection: add the gateway
container to your application pod and point your MCP client at
`http://127.0.0.1:9090` instead of the upstream. The application's own
MCP server container is addressed as `http://127.0.0.1:8090` from inside
the pod (the `mcp-gateway-upstream` Service covers cross-pod cases).

Automatic injection via `MutatingWebhookConfiguration` is out of scope
for v1 — it requires managing webhook TLS certificates and extra RBAC —
and is the planned v2 chart.
