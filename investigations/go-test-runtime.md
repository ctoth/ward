# Investigation: go test runtime

## Facts (verified)

- `go test -count=1` passes in 65.532 seconds on Windows.
- `go test -json -count=1 -timeout 75s` passes in 62.668 seconds.
- No Go test contains an explicit sleep, timer, eventual assertion, or test timeout.
- Pure parser and state tests complete in effectively zero seconds.
- Git-backed tests individually take up to 6.51 seconds.
- `initTestRepo` launches three Git processes for every temporary repository.
- `ComputeRepoStatus` launches five Git processes per snapshot.
- The production hook computes repository status before `EvaluateVerbose`, which computes it twice more through `enrichCommandRepoContext` and `repoActivation`.
- Rules that reference facts launch Bash once per evaluation through `computeFact`.

## Theories

1. Repeated external-process startup dominates runtime. It predicts that consolidating repository snapshots and eliminating duplicate snapshots will produce a large reduction without changing assertions.
2. Temporary filesystem creation dominates runtime. It predicts that tests with many `t.TempDir` calls but no subprocesses will also be slow; current per-test timing contradicts this.
3. Test compilation dominates runtime. It predicts a large gap before the first test starts; JSON timing instead shows the delay accumulating within subprocess-backed tests.

## Tests Run

| Test | Hypothesis | Result | Rules Out | Supports |
|---|---|---|---|---|
| Search tests for timers and sleeps | Real-time waiting dominates | No matches | Explicit waiting | — |
| Uncached full-suite JSON timing | A small test family dominates | Pure tests are near-zero; subprocess-backed tests accumulate the runtime | Compilation and ordinary temp-directory I/O as primary causes | Repeated process startup |
| Trace repository and fact call paths | Duplicate external commands dominate | Up to 15 Git launches per hook evaluation, plus Bash-backed facts | A single unavoidable integration call | Repeated process startup |
| Consolidate and reuse repository snapshots | Git process fan-out dominates the first runtime segment | Full suite passes in 28.373 seconds, down from 65.532 seconds | Git as the only remaining bottleneck | Repeated process startup; Bash facts remain |

## Current Best Theory

Repeated Git and Bash process startup is the root cause. Consolidating repository status into one porcelain-v2 invocation and reusing one snapshot removed 37.159 seconds. A 10-second timeout after that change stopped inside `computeFact` waiting for Bash, confirming shell-backed facts are now the dominant remaining cost.

## Open Questions

- How to preserve exact fact-command semantics while avoiding a fresh Bash process for every policy evaluation.

## Next Action

Commit the measured Git snapshot improvement, then isolate and remove redundant Bash fact evaluation without replacing command-backed facts with weaker test doubles.
