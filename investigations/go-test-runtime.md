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
- Each temporary test repository inherited global `core.fsmonitor`, spawning a detached `git fsmonitor--daemon` that outlived `t.TempDir`; more than one hundred such Git processes were present.

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
| Disable fsmonitor in ephemeral test repos | Temporary repos leak filesystem monitors and add startup cost | Full suite passes in 25.437 seconds and a focused real-Git run creates zero daemons | Ordinary temp filesystem I/O as the cause | Inherited fsmonitor config was a real secondary cause |

## Current Best Theory

Repeated external-process startup is the root cause. Consolidating repository status into one porcelain-v2 invocation and reusing one snapshot removed 37.159 seconds. Disabling inherited fsmonitor in temporary repositories removed another 2.936 seconds and stopped the daemon leak. Shell-backed constant test facts remain the dominant avoidable cost.

## Open Questions

- How to preserve exact fact-command semantics while avoiding a fresh Bash process for every policy evaluation.
- How much runtime remains in real-Git higher-level policy tests versus the dedicated repository integration test.

## Next Action

Commit the measured fsmonitor fix, then inject the exact constant fixture fact values into policy tests while retaining dedicated real command-backed fact coverage.
