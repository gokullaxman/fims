# File Integrity Monitoring System (FIMS)

A modular, Linux-native **File Integrity Monitoring System (FIMS)** engineered in ISO C11 using POSIX system calls, the OpenSSL `EVP` cryptographic API (`SHA-256`), `pthread` multithreading, and the Linux `inotify` kernel subsystem.

## 1. Project Overview & Objectives

FIMS establishes a tamper-evident cryptographic baseline of regular files across monitored directory trees and continuously compares live filesystem state against that trusted baseline. It detects and logs:

- **`FILE_MODIFIED`**: Cryptographic SHA-256 content digest changes.
- **`FILE_DELETED`**: Removal of previously baselined files.
- **`FILE_ADDED`**: Creation of unauthorized or unbaselined regular files.
- **`FILE_RENAMED`**: Reliably identifiable file moves preserving device ID, inode, size, `mtime`, and SHA-256 digest.
- **`PERMISSION_CHANGED`**: Modifications to POSIX permission and special mode bits (`07777`, including `setuid`/`setgid`/world-writable escalations).
- **`SIZE_CHANGED`**: Byte-length variations between baseline and live files.
- **`METADATA_CHANGED`**: Ownership (`UID`/`GID`) or modification timestamp (`mtime`) changes even when file content remains identical.

## 2. Repository Structure

```text
fims/
├── include/
│   └── fims.h              # Shared constants, status enums, data structures, and safe string/path helpers
├── src/
│   ├── main.c              # Entry point delegating to CLI dispatcher
│   ├── cli.c / cli.h       # Command-line parser and subcommand handlers
│   ├── config.c / config.h # Configuration manager, exclusion engine, and path traversal sanitizer
│   ├── logger.c / logger.h # Thread-safe structured alert & operational audit logging engine (mode 0600)
│   ├── hash.c / hash.h     # Chunked 64 KB streaming SHA-256 generator via OpenSSL EVP API
│   ├── scanner.c / scanner.h # Recursive POSIX directory scanner with symlink & cycle protection
│   ├── baseline.c / baseline.h # Self-validating baseline manager with atomic writes & BODY_SHA256 header
│   ├── integrity.c / integrity.h # Multi-pass baseline vs. live filesystem comparison engine
│   └── monitor.c / monitor.h # Real-time Linux inotify event loop + periodic pthread consistency scanner
├── tests/
│   ├── test_hash.c         # NIST vectors, empty files, 2.66 MB multi-chunk streaming, symlink & EACCES tests
│   ├── test_scanner.c      # Nested directories, symlink loop prevention, EACCES handling, path traversal tests
│   ├── test_baseline.c     # 0600 permissions, overwrite protection, corrupt record & header rejection tests
│   └── test_integrity.c    # Modified/Deleted/Added/Permission/Size/Metadata/Unchanged + real-time monitor tests
├── data/
│   └── baseline.dat        # Trusted baseline storage (created at runtime with mode 0600)
├── logs/
│   └── fims.log            # Structured security alert & audit log (created at runtime with mode 0600)
├── Makefile                # Build system (make, make test, make clean)
├── README.md               # Project documentation
└── .gitignore              # Git ignore rules
```

## 3. Linux Dependencies & Installation

Install the GCC C compiler, standard C development headers, POSIX threads, and OpenSSL 3.x development libraries:

- **Debian / Ubuntu / Kali Linux**:
  ```bash
  sudo apt-get update && sudo apt-get install -y build-essential gcc make libssl-dev
  ```
- **Fedora / RHEL / Rocky Linux**:
  ```bash
  sudo dnf install -y gcc make openssl-devel
  ```
- **Arch Linux**:
  ```bash
  sudo pacman -S base-devel gcc make openssl
  ```

## 4. Build & Test Instructions

Compile the `fims` executable with strict compiler flags (`-Wall -Wextra -Werror -pedantic -std=c11 -O2`):

```bash
make
```

Run the automated 4-binary test suite covering all 12 functional and security test requirements:

```bash
make test
```

Clean compiled binaries, object files, and temporary runtime state:

```bash
make clean
```

## 5. Command-Line Interface Reference

- `fims init /path/to/directory` — Scan target directory and create a self-verifying trusted baseline in `data/baseline.dat`.
- `fims scan` — Perform a full integrity scan comparing the live filesystem against the trusted baseline.
- `fims monitor [--duration <sec>]` — Start real-time `inotify` monitoring with background `pthread` consistency scans.
- `fims status` — Display baseline verification status, tracked file counts, and monitoring metrics.
- `fims report` — Display the detailed integrity report from the most recent scan or monitoring session.
- `fims baseline show` — Validate and display all records stored in the trusted baseline.
- `fims baseline update [--yes]` — Re-scan monitored directories and update the baseline after explicit user confirmation.
- `fims config` — Display active configuration parameters, monitored roots, and excluded paths.
- `fims help` — Display usage instructions.

## 6. Security Architecture & Limitations

### Built-in Security Controls
1. **Cryptographic Hashing (`OpenSSL EVP`)**: Uses `EVP_DigestInit_ex`, `EVP_DigestUpdate`, and `EVP_DigestFinal_ex` with `EVP_sha256()` over fixed 64 KB heap buffers. Entire files are never loaded into memory.
2. **Symlink & TOCTOU Hardening**: Directory traversal uses `lstat()` to identify and skip symbolic links without dereferencing them. Regular files, baseline files, and logs are opened with `O_NOFOLLOW | O_CLOEXEC`.
3. **Baseline Self-Integrity (`BODY_SHA256`)**: `data/baseline.dat` stores a cryptographic SHA-256 digest of all serialized record lines in its header and writes updates atomically via temporary files (`0600` permissions). Any unauthorized edit or corruption of `baseline.dat` is rejected with `FIMS_ERR_CORRUPT`.
4. **Never Mutates Monitored Files**: FIMS operates strictly as a read-only observer on monitored directories—it never executes, deletes, quarantines, or modifies monitored files, and never silently updates the baseline after detecting anomalies.
5. **Integrity Change vs. Malicious Activity**: FIMS reports objective integrity deviations (`FILE_MODIFIED`, `PERMISSION_CHANGED`, etc.) so analysts can correlate authorized maintenance windows against unauthorized intrusion activity.

### Documented Operational Limitations
- **Root Privileges & Kernel-Level Evasion**: When run as an unprivileged user, FIMS cannot hash files owned by `root` with `0000`/`0600` permissions (these are safely counted and logged as skipped). Conversely, an adversary who achieves `root` (`CAP_SYS_ADMIN`) compromise on the same host could modify both the monitored files and `data/baseline.dat` unless `baseline.dat` is stored on read-only media, an append-only filesystem (`chattr +i` / `+a`), or shipped off-host via remote syslog.
- **Filesystem TOCTOU Races**: Between an `inotify` event notification and the subsequent `open()`/`read()` hash calculation, a rapidly mutating process may modify or unlink a file. FIMS mitigates transient races by combining real-time `inotify` watches (`IN_CLOSE_WRITE`, `IN_MODIFY`, `IN_ATTRIB`, `IN_MOVED_*`, `IN_Q_OVERFLOW`) with a periodic full-tree consistency scan thread.
