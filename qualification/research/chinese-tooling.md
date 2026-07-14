# P2.D Chinese research differential track

Inspection was limited to public repository metadata and license files. No PoC,
payload library, scanner, target-discovery component or executable code was
downloaded, copied, linked or run.

| Repository | Observed license | P2 disposition |
| --- | --- | --- |
| `vulhub/vulhub` | MIT (`LICENSE`, blob `5706865806404c056e27e9d76aef286e4ae64d7e`) | Local pinned lab concepts only; no scenario executed |
| `fofapro/vulfocus` | Apache-2.0 (`LICENSE`, blob `9466347c908218a3f0c3f59a341adf8e935b0015`) | External controller only; Docker-socket designs blocked |
| `yaklang/yaklang` | AGPL-3.0 (`LICENSE.md`, blob `e066202aa1f8607c2ba4721d6d5fb8f7200c5b16`) | No code copy or linking; architecture ideas only |
| `yaklang/yakit` | AGPL-3.0 (`LICENSE.md`, blob `cba6f6a15a4cc3ba212e9e9059f7243e2d171090`) | No code copy or linking; optional external process concept only |

Public sources inspected:

- <https://github.com/vulhub/vulhub>
- <https://github.com/fofapro/vulfocus>
- <https://github.com/yaklang/yaklang>
- <https://github.com/yaklang/yakit>

## Ideas retained without implementation copying

- normalize requests before comparison;
- canonicalize method, path and bounded header classes;
- account for crawler coverage independently from findings;
- represent signatures as abstract evidence requirements rather than payloads;
- compare differential responses and fixture coverage;
- keep fixture generation deterministic and oracle-independent.

## Ideas explicitly excluded

- PoC and exploit libraries;
- unrestricted or mass scanning;
- public target discovery;
- target expansion by a reference tool;
- importing reference findings into BOQA;
- treating a reference tool as ground truth;
- linked or copied AGPL components in BOQA.

## Optional differential comparator

`qualification/adapters/reference-comparator.js` accepts already-completed BOQA
and reference-tool result sets plus an independent oracle. It reports BOQA-only,
reference-only and overlapping case IDs; precision, recall, time and requests
for each tool; and rejected out-of-scope rows. The reference result cannot alter
BOQA input, scope or findings and is never used as truth.

No reference tool was executed in this pipeline.
