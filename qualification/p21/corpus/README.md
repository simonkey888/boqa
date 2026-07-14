# P2.1 pinned external blind corpus

The corpus is frozen before baseline execution. Agent inputs contain only an
opaque canonical target, an authorized URL, scope, optional scenario-local
credentials, a bounded request/navigation budget and an optional per-run random
handle. They do not contain scenario IDs, seeds or track names. Private route mappings and upstream oracle labels are loaded
by the controller only after the BOQA process exits.

The paired classification set contains 24 OWASP Benchmark instances: two
independent vulnerable/safe pairs in each of six web families. Four NodeGoat
instances are detection-only and four Juice Shop instances are stateful coverage
cases. Detection-only and stateful cases never enter precision or false-positive
rate calculations.

Vulnerable and safe members of a pair deliberately expose the same opaque target
ID, hostname, path, port, scope and budget. A run handle is freshly generated and
has no stable relation to a scenario, pair, seed, framework, track or variant.
The isolated gateway maps that public
identity to the private upstream case for a single fresh run.
