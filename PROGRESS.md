# FIMS Professional CLI Transformation - Progress Tracker

## Project Overview
Transform FIMS into a polished, professional, production-quality Linux cybersecurity utility inspired by industry-standard security tools (Lynis, ClamAV, Fail2ban, UFW, AIDE, Nmap).

---

## Logical Milestones

### Milestone 1: Centralized Terminal Formatting & UI Architecture
- [x] Create centralized `include/ui.h` with color palette, banner, headers, field formatters, alert cards, and progress meters.
- [x] Implement `src/ui.c` with robust TTY detection, `NO_COLOR` standard support, `--no-color` / `--color` handling, terminal width auto-adaptation, and injection-safe formatting.
- [x] Integrate `src/ui.c` into `Makefile` `CORE_SRCS` and compile cleanly under `-Wall -Wextra -Werror -pedantic -std=c11`.

### Milestone 2: Upgrade CLI Command Experiences (`src/cli.c`, `src/cli.h`)
- [x] Implement global `--no-color` and `--color` flag parsing across all subcommands.
- [x] Add `fims banner` command and upgrade `fims --help` / `fims help` with full ASCII cybersecurity banner and Kali/Debian utility manual format.
- [x] Upgrade `init` command output: branded header, step logs, real-time progress, and structured baseline protection summary.
- [x] Upgrade `scan` command output: branded header, baseline verification status, progress indicator, scan metrics card, professional alert cards, and status box.
- [x] Upgrade `status` command output: professional system status dashboard with engine readiness indicators and overall protection state.
- [x] Upgrade `report` command output: formatted alert cards with color-coded severity badges.
- [x] Upgrade `baseline show` command: clean table presentation of baseline metadata, monitored roots, and hashed records.
- [x] Upgrade `baseline update` command: colored diff summary, clear confirmation prompt, and update confirmation.
- [x] Upgrade `config` command: categorized sections (Paths, Security, Scan Parameters, Baseline Contents) maintaining backward compatibility.
- [x] Upgrade `monitor` command: branded header, timestamped colorized real-time events, and clean shutdown summary.

### Milestone 3: Terminal Protection & Output Sanitization
- [x] Verify that filenames with control characters, tabs, newlines, or ANSI sequences cannot inject terminal control codes (neutralized to `\xNN`).
- [x] Verify that disk log files (`fims.log`) and report files (`last_report.dat`) remain 100% free of ANSI escape codes.
- [x] Test terminal width responsiveness (narrow, standard 80-col, wide).
- [x] Test behavior when redirected or piped to other tools (`fims scan | cat`).

### Milestone 4: Comprehensive Test Suite & Red Team Verification
- [x] `make test`: All 10 automated test suites pass 100%.
- [x] `make test-asan`: Clean execution under AddressSanitizer and UndefinedBehaviorSanitizer (zero leaks, zero errors).
- [x] `make repro`: All 12 Red Team reproduction scripts (`repro_A` through `repro_L`) pass (exit code 0).
- [x] `bash tests/run_all.sh`: All 4 pipeline stages pass cleanly.
- [x] `bash demo.sh`: End-to-end demonstration passes cleanly.

### Milestone 5: Interactive Terminal User Interface (TUI)
- [x] Modern ncurses/ncursesw integration with terminal auto-detection and graceful fallback.
- [x] Centralized color system (`include/ui_colors.h`, `src/ui_colors.c`) with branded Cyan, Green, Red, Yellow, Blue, Magenta, Dim attributes.
- [x] Interactive modal dialog components (`include/ui_dialogs.h`, `src/ui_dialogs.c`): Confirmation, Message alerts, Input prompts, and Progress meters.
- [x] 10 Full-screen security console views (`include/ui_tui.h`, `src/ui_screens.c`):
  - Dashboard (System Overview, Integrity Summary, Status, Quick Actions)
  - Initialize Baseline (Directory path selection, force overwrite, progress feedback)
  - Integrity Scan (On-demand scanning, real-time counters, result cards, direct alert jump)
  - Live Monitoring (Daemon telemetry, live inotify alert stream, automatic 300ms refresh)
  - Baseline Management (Scrollable records table, path/hash/size/permissions display)
  - Security Alerts (Filter tabs by severity, scrollable alert log, detailed modal inspector)
  - Scan Reports (Audit report viewer with detailed breakdown and export dialog)
  - Configuration Editor (Interactive toggles for scan parameters, symlinks, rename detection)
  - System Information (Platform architecture, OpenSSL EVP specs, inotify flags, safety guarantees)
  - Help & Keybindings Reference (Full keyboard navigation and security workflow manual)
- [x] Main TUI engine & state machine (`src/ui_tui.c`):
  - Responsive layout (Header branding, Navigation sidebar, Content panel, Status footer)
  - Intuitive keybindings: `UP`/`DOWN` navigate, `ENTER` select, `TAB` switch panel focus, `SPACE` toggle, `ESC` back, `Q` quit with confirmation
  - Signal handling: clean `SIGWINCH` resize re-rendering and `SIGINT`/`SIGTERM`/`atexit` `endwin()` restoration
- [x] Backward-compatible CLI dispatch (`src/cli.c`):
  - Default `./fims` launches TUI when run in an interactive terminal (TTY)
  - Explicit `./fims tui` command launches interactive console
  - All non-interactive CLI commands (`scan`, `status`, `init`, `report`, `config`, etc.) work without regression

---

## Verification Summary Table

| Test Suite / Target | Result | Notes |
|:---|:---:|:---|
| `make clean && make -j$(nproc)` | PASS | Warning-free under `-Wall -Wextra -Werror -pedantic -std=c11` |
| `make test` | PASS | 10 C test suites + `test_cli.sh` (100% passed) |
| `make test-asan` | PASS | ASan & UBSan clean, 0 memory leaks, 0 errors |
| `make repro` | PASS | 12/12 Red Team attack reproduction scripts exited with code 0 |
| `bash tests/run_all.sh` | PASS | All 4 verification stages passed |
| `bash demo.sh` | PASS | Full interactive demo completed cleanly |
| `NO_COLOR` & `--no-color` | PASS | 0 ANSI codes emitted when disabled or piped |
| Filename Escape Sanitization | PASS | Control chars / ANSI sequences escaped to `\xNN` |
| Interactive TUI Console | PASS | Full ncurses keyboard navigation, 10 screens, modal dialogs |
