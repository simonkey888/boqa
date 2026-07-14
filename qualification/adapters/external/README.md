# External benchmark adapters

These adapters are provisioning and scoring boundaries, not downloaders or
scanners. They never auto-run a public corpus. Every executable scenario must be
local-only, web-only, immutable (source commit plus image and configuration
digests), non-privileged, socket-free and compatible with the P2 isolation
policy.

Docker was unavailable during this pipeline, therefore:

- OWASP Benchmark scenarios integrated/executed: **0**.
- NodeGoat scenarios executed: **0**.
- Juice Shop scenarios executed: **0**.
- Vulhub pinned/executed scenarios: **0**.
- Vulfocus: **BLOCKED_UNSAFE_DOCKER_CONTROL** when a Docker socket, privileged
  container or host network is requested. An external control plane is required.

No external lab result is included in P2 qualification metrics.
