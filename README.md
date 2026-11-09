# File Integrity Monitoring System (FIMS)

A modular, Linux-native **File Integrity Monitoring System (FIMS)** engineered in ISO C11 using POSIX system calls, the OpenSSL `EVP` cryptographic API (`SHA-256` and optional `HMAC-SHA256`), `pthread` multithreading, and the Linux `inotify` kernel subsystem.

---

## 1. Project Overview & Objectives

FIMS establishes a tamper-evident cryptographic baseline of regular files across monitored directory trees and continuously compares live filesystem state against that trusted baseline. It detects, records, and audits:

- **`FILE_MODIFIED`**: Cryptographic SHA-256 content digest changes.
- **`FILE_DELETED`**: Removal of previously baselined files (including entire missing or removed monitored root trees).
- **`FILE_ADDED`**: Creation of unauthorized or unbaselined regular files.
- **`FILE_RENAMED`**: Reliably identifiable file moves preserving device ID, inode, size, `mtime`, and SHA-256 digest (paired via inotify cookies).
- **`PERMISSION_CHANGED`**: Modifications to POSIX permission and special mode bits (`07777`, including `setuid`/`setgid`/world-writable escalations).
- **`SIZE_CHANGED`**: Byte-length variations between baseline and live files.
- **`METADATA_CHANGED`**: Ownership (`UID`/`GID`), modification timestamp (`mtime`), change timestamp (`ctime`), or inode updates even when file content remains identical.
- **`EVENT_UNREADABLE` / `PERMISSION_CHANGED`**: Inaccessible files retaining metadata without falsely reporting `FILE_DELETED`.

---

## 2. Command-Line Interface Reference

### Commands & Subcommands

- `fims init <directory> [--force]`
  Scan `<directory>` and create a self-verifying trusted baseline. Rejects overwriting an existing baseline unless `--force` is specified. Flags are accepted in either order (`init <dir> --force` or `init --force <dir>`). Overwriting an existing baseline requires interactive confirmation typing `"yes"` (or unattended automated execution via `--allow-unattended`).
- `fims init --add <directory>`
  Add an additional directory root to the existing baseline without discarding existing baselined roots.
- `fims scan`
  Perform a complete integrity scan comparing the live filesystem against the trusted baseline.
- `fims monitor [--duration <sec>]`
  Start real-time `inotify` monitoring with background `pthread` consistency scans. `--duration` accepts non-negative numeric integers.
- `fims status`
  Display monitoring status, daemon PID, heartbeat freshness (< 3x check interval), monitored roots, tracked file count, and last scan timestamp (prints `"never"` if no scan has been executed).
- `fims report`
  Display the detailed integrity report from the most recent scan or monitoring session.
- `fims baseline show`
  Validate cryptographic integrity and display all header metadata, root directories, and records stored in the trusted baseline.
- `fims baseline update [--yes] [--allow-unattended]`
  Run an integrity scan first, print the alert diff count, and update the baseline after confirmation. Requires typing `"yes"` interactively; `--yes` is honored only when combined with `--allow-unattended`.
- `fims config`
  Display active configuration parameters, monitored roots (aligned with active baseline contents), and excluded paths.
- `fims help`
  Display usage instructions, syntax guide, and exit code reference.

### Scan Exit Codes

The `fims scan` command strictly adheres to deterministic exit codes for CI/CD and SIEM automation:

| Exit Code | Identifier | Description |
|:---------:|:-----------|:------------|
| **`0`** | `FIMS_EXIT_OK` | Clean scan: live filesystem perfectly matches baseline; 0 changes detected. |
| **`1`** | `FIMS_EXIT_ERROR` | Operational or fatal error (e.g. missing arguments, I/O errors, invalid configuration, unreadable paths). |
| **`2`** | `FIMS_EXIT_CORRUPT` | Baseline corruption or authenticity failure: header mismatch, parsing failure, `BODY_SHA256` digest failure, or missing/invalid HMAC key/digest. |
| **`3`** | `FIMS_EXIT_CHANGES` | Integrity changes detected: one or more `FILE_MODIFIED`, `FILE_DELETED`, `FILE_ADDED`, `FILE_RENAMED`, `PERMISSION_CHANGED`, `SIZE_CHANGED`, or `METADATA_CHANGED` events identified. |

---

## 3. Configuration & Path Resolution

### Default Paths & Fallback Hierarchy

FIMS uses absolute paths by default rather than depending on the current working directory (`cwd`):

| File Purpose | Root / System Default | Non-Root User Fallback (`~/.local/state/fims`) |
|:-------------|:----------------------|:----------------------------------------------|
| **Baseline File** | `/var/lib/fims/baseline.dat` | `~/.local/state/fims/baseline.dat` |
| **Log File** | `/var/log/fims/fims.log` | `~/.local/state/fims/fims.log` |
| **Config File** | `/etc/fims/fims.conf` | `~/.local/state/fims/fims.conf` |
| **Report File** | `/var/lib/fims/last_report.dat` | `~/.local/state/fims/last_report.dat` |
| **State File** | `/var/lib/fims/status.dat` | `~/.local/state/fims/status.dat` |

### Environment Variable Overrides

All default paths can be explicitly overridden via environment variables:

- `FIMS_BASELINE_PATH`: Custom path to trusted baseline file.
- `FIMS_LOG_PATH`: Custom path to structured log file.
- `FIMS_CONFIG_PATH`: Custom path to configuration file.
- `FIMS_REPORT_PATH`: Custom path to last report file.
- `FIMS_STATE_PATH`: Custom path to daemon state file.
- `FIMS_HMAC_KEY_FILE`: Absolute path to the HMAC-SHA256 secret key file.

### Ownership & Permission Hardening

To prevent local privilege escalation:
- Configuration and baseline files must be owned by the current user or `root`.
- FIMS refuses to load any configuration or baseline file that is group-writable (`0020`) or world-writable (`0002`).
- Operational log files and baseline files are created with strict `0600` permissions.

---

## 4. Exclusion Engine & Semantics

FIMS implements strict exclusion semantics to prevent false positives and eliminate evasion vulnerabilities:

1. **Absolute Path Canonicalization**:
   All exclusion rules specified relatively in configuration or CLI arguments are resolved to canonical absolute paths relative to `cwd` upon ingestion.
2. **Boundary Prefix Matching (`/`)**:
   Exclusions match either exact paths or directory prefixes strictly bounded by `/`. For example, `/var/log` matches `/var/log` and `/var/log/app.log`, but does **not** match `/var/log-backup`.
3. **Automatic Self-Exclusion**:
   FIMS automatically excludes its own operational files: `cfg->baseline_file`, `cfg->log_file`, `cfg->report_file`, `cfg->state_file`, `cfg->config_file`, and temporary baseline staging files (`<baseline>.tmp.*`).
4. **Subdirectory `.git` Monitoring**:
   Basename-only exclusion for `.git` is eliminated. A `.git` folder located inside a monitored directory tree is monitored by default.
5. **Pattern Exclusions (`exclude_glob`)**:
   To exclude files by pattern across the entire tree, use the explicit configuration directive:
   ```ini
   exclude_glob = **/.git/**
   exclude_glob = *.tmp
   ```

---

## 5. Security Architecture & Baseline Authenticity

### Built-in Security Controls

1. **OpenSSL EVP Cryptography**: Uses streaming 64 KB heap buffers with `EVP_DigestInit_ex`, `EVP_DigestUpdate`, and `EVP_DigestFinal_ex` for chunked SHA-256 calculation. Full files are never buffered into memory.
2. **Symlink & TOCTOU Hardening**: File opening uses `O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK` followed by `fstat` on the opened file descriptor to prevent FIFO hangs and TOCTOU directory swap attacks.
3. **Log & Report Injection Defense**: All user-controlled strings, file paths, and event descriptions are sanitized through a unified escaping helper converting control characters (`< 0x20`, `0x7f`), quotes (`"`), backslashes (`\`), and ANSI escape sequences into `\xNN` representations.
4. **Atomic Baseline Writes**: Baseline serialization writes to a temporary file created with `O_EXCL | O_CREAT` (mode `0600`), validates write return codes, flushes and `fsync`s the file descriptor, atomically replaces the target via `rename()`, and `fsync`s the parent directory.
5. **Read-Only Observer Discipline**: FIMS never modifies, deletes, or executes monitored files, and never silently updates the baseline upon detecting changes.

### Baseline Authenticity & HMAC-SHA256

Baseline files include all header metadata (`CREATED_AT`, `RECORD_COUNT`, `ROOT_DIR`) and all serialized record lines within the cryptographic digest computation.

FIMS supports an optional **HMAC-SHA256** baseline authenticity mechanism enabled via `FIMS_HMAC_KEY_FILE`:
- The key file specified by `FIMS_HMAC_KEY_FILE` must have mode `0600` and be owned exclusively by the current user or `root`.
- When configured, a baseline missing an `HMAC_SHA256` header or failing HMAC validation is rejected with `FIMS_ERR_CORRUPT` (exit code `2`).

> **CRITICAL SECURITY NOTICE**:
> **WITHOUT an HMAC key file (`FIMS_HMAC_KEY_FILE`), the baseline checksum (`BODY_SHA256`) detects ACCIDENTAL CORRUPTION ONLY, NOT MALICIOUS TAMPERING.**
> An adversary with write permissions to the baseline file can recalculate and overwrite the `BODY_SHA256` digest header. True tamper resistance against adversaries with filesystem access requires an out-of-band protected key (`FIMS_HMAC_KEY_FILE`), an append-only filesystem (`chattr +i` / `+a`), or storing the baseline on read-only media.

---

## 6. Build & Test Instructions

### Build
```bash
make
```

### Run Tests
```bash
make test
```

### Run Tests under AddressSanitizer and UndefinedBehaviorSanitizer
```bash
make clean
make CFLAGS="-Wall -Wextra -Werror -pedantic -std=c11 -O2 -Iinclude -fsanitize=address,undefined" test
```

### Clean
```bash
make clean
```
=== END FILE: README.md ===
