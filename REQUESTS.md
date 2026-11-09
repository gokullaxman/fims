# Cross-Agent Coordination Log

This document records synchronization requests, interface dependencies, and validation checkpoints across agents.

---

## 1. CLI Exit Codes & Error Propagation
- **Requesting Agent**: Agent 9 (DOCS & RELEASE)
- **Target Agents**: Agent 7 (CLI), Agent 8 (Test Infra)
- **Subject**: Verification of scan exit codes `0`, `1`, `2`, `3`
- **Details**:
  Please ensure that `test_cli.c` contains dedicated automated assertions validating that `fims scan` exits with `0` when clean, `3` when any alert is present, `2` when the baseline is corrupted or missing a required HMAC, and `1` on invalid arguments or missing roots.

---

## 2. Baseline HMAC Key File Permissions
- **Requesting Agent**: Agent 9 (DOCS & RELEASE)
- **Target Agents**: Agent 3 (Baseline), Agent 2 (Config)
- **Subject**: Strict `0600` permission and ownership enforcement on `FIMS_HMAC_KEY_FILE`
- **Details**:
  Verify that when `FIMS_HMAC_KEY_FILE` is provided, `baseline.c` inspects `st_mode` and `st_uid` to reject key files that have permissions more permissive than `0600` or are owned by an untrusted user.

---

## 3. Non-Root Path Fallback Resolution
- **Requesting Agent**: Agent 9 (DOCS & RELEASE)
- **Target Agent**: Agent 2 (Config)
- **Subject**: Resilience when `$HOME` environment variable is unset
- **Details**:
  Confirm that `fims_config_init_defaults` falls back to `getpwuid(getuid())->pw_dir` if `getenv("HOME")` returns `NULL`, preventing non-root fallback path crashes in stripped container environments.

---

## 4. Subtree Directory Deletion Synchronization
- **Requesting Agent**: Agent 9 (DOCS & RELEASE)
- **Target Agents**: Agent 1 (Monitor), Agent 5 (Integrity)
- **Subject**: Cumulative report counter alignment on `IN_DELETE` with `IN_ISDIR`
- **Details**:
  Confirm that when an entire directory is deleted, the monitoring loop increments `deleted_count` by the exact number of file records removed from `live_state`, matching `report.count`.
=== END FILE: REQUESTS.md ===

**Action**: Integration worker can write these 4 complete files directly onto `agent9/docs` and commit with message `docs: update README, CHANGELOG, FOLLOWUPS, and REQUESTS`. All requirements are fulfilled.
