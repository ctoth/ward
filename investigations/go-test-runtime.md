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
| Inject exact constant fact fixtures | Repeated Bash startup dominates policy unit tests | Full suite passes in 19.112 seconds while a dedicated test still executes both real fixture commands | Fact computation itself as the cost | Redundant Bash startup for constant test values |
| Inject exact repository snapshots into policy tests | Live Git discovery is redundant when a policy test already defines repository state | Dirty-tree policy tests pass in 0.159 seconds; full suite passes in 14.890 seconds | CEL evaluation or filesystem fixtures as the cost | Redundant live repository discovery |
| Skip unobservable repository discovery | Rules without `repo.*` cannot observe live Git state | Previously slow custom-rule group passes in 0.153 seconds; full suite passes in 11.452 seconds | Rule evaluation itself as the cost | Unobservable live Git discovery |
| Inject snapshots into higher-level Git policy tests | Policy tests need repository activation, not repeated Git mechanics | Four-test group passes in 0.203 seconds; full suite passes in 7.799 seconds | Event parsing, state transitions, or CEL as the cost | Redundant real-Git setup in policy tests |
| Parameterize higher-level repository resolution | Path-policy tests need deterministic repository identity, not repeated Git subprocesses | Three-test path group passes in 0.157 seconds; full suite passes in 5.762 seconds | Path logic as the cost | Redundant live repository discovery |
| Reuse the compiled test executable for CLI integration | Building Ward inside its already-built test binary is redundant | Installer integration passes in 0.335 seconds; full suite passes in 3.003 and 2.607 seconds on consecutive uncached runs | Installer behavior as the cost | Redundant nested compilation |

## Current Best Theory

Repeated external-process startup was the root cause. Consolidating and reusing repository snapshots, disabling inherited fsmonitor, injecting exact fixtures, skipping unobservable discovery, parameterizing higher-level resolution, and reusing the compiled test executable reduced the suite from 65.532 seconds to consecutive uncached runs of 3.003 and 2.607 seconds. Dedicated command-backed fact, real repository-status, and real child-process CLI coverage remain. The final runs created no fsmonitor daemon.

## Open Questions

- None.

## Next Action

Complete: consecutive uncached full-suite runs are under five seconds, no fsmonitor daemon leaked, and the final diff is scoped to the installer integration mechanism plus this record.
