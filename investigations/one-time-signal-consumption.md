# Investigation: One-time signal consumption

## Facts (verified)

- The repaired actor binding allowed the exact dirty-tree fast-forward under actor `round-five-nested-promotion-integrator-fixed-ward`.
- After that guarded operation, the actor state still contained `dirty-tree-switch` with `one_time_use: true`.
- `EvaluateVerbose` previously collected signal references only after a rule evaluated `true`.
- Override signals normally make deny rules evaluate `false`, so the old collector could not mark the successful override for consumption.
- The existing dirty-tree override test proved allowance but never called `ConsumeSignals` or asserted removal.

## Theories

1. Persistence failed to save the consumed state. Prediction: `EvaluateVerbose` reports `dirty-tree-switch` as checked, but the saved state retains it.
2. The rule never reports a successful override as checked. Prediction: the operation is allowed and `EvaluateVerbose` returns no checked signal.
3. The signal was consumed and recreated by a later command. Prediction: history contains a second `ward allow` after the merge.

## Tests Run

| Test | Hypothesis | Result | Rules Out | Supports |
|---|---|---|---|---|
| Inspect live actor state and history | 1-3 | Signal remained; history had only set, allow, and merge hook events | Recreation | 1 or 2 |
| Extend dirty-tree override test through `ConsumeSignals` | 1-2 | Red: `dirty-tree-switch` survived | Persistence-only explanation | 2 |
| Compare rule outcome with and without referenced one-time signals | 2 | Removing the signal changes the dirty-switch rule from false to true | Other theories | 2 |

## Current Best Theory

Confirmed theory 2. "Only matched rules" is the wrong consumption criterion for
an override that works by making a deny rule false. The correct criterion is
counterfactual: consume referenced one-time signals only when removing them
changes that rule's boolean outcome.

## Fix

For each rule that references present one-time signals, evaluate the rule once
with those one-time signals removed. Mark them for consumption only if the
boolean outcome changes. This preserves signals across unrelated commands,
handles positive signal rules, consumes jointly decisive one-time signals, and
does not consume an irrelevant one-time signal masked by a persistent signal.

## Verification Status

- Dirty-tree override consumption regression: pass.
- Unrelated-command non-consumption regression: pass.
- Positive, jointly decisive, and persistent-masking cases: pass.
- `go vet ./...`: pass.
- `go test ./... -count=1`: pass in 53.333 seconds. An earlier 60-second
  process timeout expired at 58.524 seconds without a test failure; the bounded
  rerun used 75 seconds.
- `go test -race ./... -count=1`: pass in 63.136 seconds.
- Installed binary reports exact VCS revision
  `491f54c9882a27aa59cd2edd02d8c3c289bd1008`; Codex hooks were refreshed.
- Live proof on the dirty `mushy-peas` integration checkout: the first
  `git merge --ff-only HEAD` was allowed, actor state then contained
  `"signals": {}`, and a second identical command without another grant was
  denied by `no-dirty-tree-switch`.
