# BOQA P2 controlled-hunting qualification

This directory is an isolated, deterministic evaluation system. The agent gets
only a canonical synthetic target, authorized URL, scope, optional synthetic
credentials and a request/navigation budget. Private manifests and oracle code
are consumed only after the agent finishes.

The first-party runner is an in-process protocol with no socket, DNS, browser or
host filesystem capability. Docker policies are generated and validated for
future external-lab runners: internal network, loopback-only exposure,
read-only root filesystem, all capabilities dropped, no-new-privileges,
CPU/memory/PID limits, no host network, no Docker socket and mandatory cleanup.

Docker is optional. When it is unavailable, public benchmark adapters remain
implemented but unexecuted and the result must say `EXTERNAL_LABS_NOT_RUN`.

Ground truth is never a BOQA input and is never uploaded as a CI artifact.
