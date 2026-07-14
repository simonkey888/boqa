# P2.H controlled-hunting economic proxy

This proxy uses only the executed first-party synthetic holdout. It does not
assign monetary value, predict bounty income or extrapolate external-lab
performance.

## Measured evidence

| Measure | Value | Interpretation |
| --- | ---: | --- |
| Scored holdout evaluations | 80 | two independent rounds of 40 |
| Reproducibility repeats | 40 | fresh-state repeat for each TP report |
| Complete suite | 38/38 test files | P1 and P2 regressions included |
| Complete-suite wall time | 28.6 seconds | observed in this workspace |
| Machine hours | 0.007944 | wall time converted to hours |
| Human review hours | 0 | no independent human triage was performed |
| TP / FP / FN | 40 / 0 / 0 | synthetic first-party oracle only |
| Automated-ready reports | 40 | rubric score at least 10/12 |
| Requests | 184 | counted by isolated runtimes |
| Requests per TP | 4.6 | all scored requests divided by TP |

The harness records bounded logical times of 5 ms to finding and 8 ms to report
for deterministic tests. Those injected-clock values are not treated as real
performance measurements. The economic JSON instead uses observed suite wall
time, divided conservatively by the 80 scored evaluations.

## Machine-only monthly arithmetic

Using 28.6 seconds / 80 scenarios = 0.3575 seconds per scored synthetic
scenario, 30 days per month gives:

| Daily machine window | Synthetic scenarios/month |
| --- | ---: |
| 2 hours/day | 604,195 |
| 4 hours/day | 1,208,391 |
| 8 hours/day | 2,416,783 |

These numbers demonstrate that the in-process harness is cheap; they do **not**
estimate external Docker-lab throughput. Provisioning, browser work, model
latency, retries and human review are absent and will dominate a P3 pilot.

## Unknowns deliberately left null

- internally duplicated findings rate: scenarios have independent oracles and
  cross-scenario deduplication was not evaluated;
- human rewrite-required rate: no report was independently reviewed;
- human hours per ready report: human review hours were zero;
- external-lab machine cost: Docker was unavailable and external labs were not
  run.

The proxy therefore supports only this conclusion: BOQA's controlled first-party
evaluation path is technically fast and produced complete automated reports,
but commercial viability cannot be inferred until a later authorized pilot
measures real isolated-lab latency and human triage effort.
