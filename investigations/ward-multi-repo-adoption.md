# Investigation: Ward multi-repository adoption

## Facts (verified)

- The Codex thread workspace is `C:\Users\Q\code\banteng`, while the rejected
  `git add` command was issued with `C:\Users\Q\code\barn` as its execution
  working directory.
- `CODEX_THREAD_ID` was
  `019f5f8f-ded7-7641-b3dc-750eb266d91e`; `WARD_SESSION` and `WARD_ACTOR_ID`
  were unset.
- From the Barn repository, `ward adopt spec/tasks.md spec/go-design.md
  spec/vm.md spec/database.md spec/README.md --session
  019f5f8f-ded7-7641-b3dc-750eb266d91e` exited zero and reported all five
  paths adopted.
- The immediately following exact-path `git add` was denied with `Only touched
  or explicitly adopted paths may be staged.`
- Ward already has unit coverage for adopting an absolute path in a sibling
  repository, but the known successful real-world adoption record used a
  single repository as both thread workspace and command repository.
- The installed hook executable is `C:\Users\Q\go\bin\ward.exe`. Its Go build
  metadata identifies source revision `3cda8e5d06597f6e571bf35ff8c02d39c0333903`
  with `vcs.modified=true`.
- The current checkout is `184151b598c0f6f7bc254c58e0b416152c5bcee1` and
  contains later commits `8b137a3` (Codex patch hook commands), `3af1b08`
  (absolute paths across repositories), and `399dd02` (repository resolution
  in path tests).
- Current `adapters_test.go` already covers a Codex `exec_command` and
  `local_shell` whose top-level `cwd` is repository A and whose nested
  `workdir` is repository B. Current `repo_test.go` already covers adoption in
  a sibling repository and successful staging-rule evaluation after scope
  restoration.
- Reinstalling current revision `184151b5...` did not fix the real failure.
- A temporary transparent capture inside `cmdEval` preserved the exact live
  rejected event. Codex normalized it to the Claude-compatible shape
  `tool_name: "Bash"`, `cwd: "C:\\Users\\Q\\code\\banteng"`, and
  `tool_input.command: "git add -- spec/..."`. The event contained no
  `workdir`, absolute Git path, `git -C`, or shell `cd`, even though the command
  executor ran in `C:\Users\Q\code\barn`.
- The capture instrumentation and attempted hook-wrapper wiring were removed
  after obtaining the event; neither is part of the proposed fix.
- Ward's tracked worktree is clean before this investigation. Existing
  untracked `docs/`, `notes/`, `pyghidra_mcp_projects/`, and
  `scripts/ward_profiles_smoke.sh` are unrelated and remain untouched.

## Theories (plausible)

1. The Codex hook event keeps the thread workspace as `cwd` and does not expose
   or Ward does not honor the nested command's execution `workdir`. Ward then
   parses `spec/...` relative to Banteng while adoption was stored in Barn.
2. The CLI adoption and hook evaluation use different actor keys even though
   they use the same session key, so the hook loads a state record without the
   adopted paths.
3. Repository canonicalization differs between CLI adoption and hook
   evaluation (for example `C:\...`, `\\?\C:\...`, case, or slash form), so
   the per-repository parked state is not restored.
4. The installed hook executable predates the already-tested multi-repository
   fixes in the checkout. This explains the initial deployment drift but not
   the current failure after reinstall.

## Tests Run

| Test | Hypothesis | Result | Rules Out | Supports |
|---|---|---|---|---|
| Exact real Barn `ward adopt` followed by `git add` | Adoption command alone should authorize staging | Adoption reported success; staging was denied | Missing adoption command, wrong session argument syntax | State/repository identity mismatch |
| Inspect live Ward state | Adoption may have been saved under the wrong actor or lost | Main actor state contains the five paths in the parked Barn scope | Actor mismatch, failed persistence, lost adoption | Hook selected Banteng scope while evaluating the Barn command |
| Compare installed binary build metadata with checkout | Live hook may be stale | Installed revision is `3cda8e5d...+dirty`; checkout is `184151b5...` with the relevant later fixes and tests | Current source lacks the fix | Stale installed hook binary |
| Install current tested checkout and repeat real staging | Stale binary fully explains failure | Current binary still denies the exact staging command | Stale binary as complete cause | Live event differs from fixtures |
| Capture Ward's exact live stdin event | Codex may omit nested execution workdir | Event has Banteng `cwd` and relative Git command only; no Barn workdir survives | Actor mismatch, path canonicalization, evaluation ordering | Missing-workdir payload gap |
| Add captured-payload regression | Existing effective-repository owner lacks active-scope fallback | Test failed to compile because the owner accepted only event and status resolver | Existing API can express required fallback | Active scope must be an explicit input |
| Run focused repository-resolution family after fix | Fallback might break explicit target handling | New live-payload test plus workdir, absolute-path, parked-scope, sibling-adoption, and patch-ownership tests passed | Fallback overriding explicit targets | Narrow no-evidence fallback |
| Run `go test ./...` after formatting | Fix may regress another Ward surface | Full suite passed | Known unit/integration regression | Candidate is internally consistent |
| Install candidate, re-adopt five Barn paths, repeat exact `git add` | Unit fix may not match live hook | Adoption and formerly denied staging both exited zero | Fixture-only fix | End-to-end live repair |
| Strengthen explicit-workdir regression with a conflicting active repository | Active-scope fallback might override stronger directory evidence | Test failed: effective repository was the active repository instead of the hook workdir | First candidate is complete | Explicit workdir must precede active-scope fallback |
| Correct fallback ordering and rerun focused plus full suites | Explicit workdir must win while the captured payload still needs active scope | Focused repository family and `go test ./...` passed | Known ordering regression | Final precedence is explicit workdir, command/absolute target, active scope, event cwd |
| Install final candidate and repeat exact Barn adoption and staging | Final ordering fix might regress the live repair | Adoption and the formerly denied relative-path `git add` both exited zero | Test-only or stale-binary success | Final deployed binary repairs the live hook path |

## Current Best Theory

Theory 1 now explains all observed facts, with the exact payload known. The
current parser handles `workdir` when present, but the live Codex compatibility
event omits it. For a relative Git command with no explicit directory evidence,
Ward falls back to the event's Banteng `cwd`, calls `SyncRepo()` with Banteng,
and parks the already-active Barn scope containing the exact adoptions before
CEL evaluates the staging rule.

The correct fallback is Ward's already-active repository scope, not the
thread-workspace `cwd`, when the Git command supplies no `cd`, `git -C`,
absolute path, or preserved `workdir`. An exact `ward adopt` or an earlier
absolute-path edit has already selected that active scope. Explicit command
directory evidence must continue to override it.

The implementation passes the active repository into the existing
`EffectiveRepoDir` owner. `cmdEval` now resolves the effective repository while
holding the actor state, loads project-local policy from that same directory,
computes repository status there, and only then synchronizes and evaluates the
scope. No new adapter or compatibility path was introduced.

## Open Questions

- None for this defect. The real staging operation and all named repository
  resolution tests pass.

## Next Action

Commit the Ward fix and investigation record, then finish the already-staged
five-path Barn documentation commit and resume the Banteng execution ledger.
