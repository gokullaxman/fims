# Forensic Observations & Future Enhancements

This document catalogs technical observations, secondary findings, and architectural recommendations discovered across the C11 FIMS codebase without modifying product code.

---

## 1. Kernel Event Subsystem: `inotify` vs. `fanotify`

- **Observation**:
  `inotify` operates by attaching individual watch descriptors (`wd`) to directories recursively (`add_watch_recursive`). On systems monitoring vast enterprise directory trees (>500,000 directories), this can quickly exhaust `/proc/sys/fs/inotify/max_user_watches`, causing subsequent `inotify_add_watch` calls to fail with `ENOSPC`.
- **Recommendation**:
  For Linux kernel versions >= 5.1, evaluate a dual-mode backend supporting `fanotify` with `FAN_REPORT_FID` and `FAN_MARK_FILESYSTEM`. This allows monitoring entire mount points with a single file descriptor without consuming individual directory watch descriptors.

---

## 2. Symbolic Link Target Auditing

- **Observation**:
  FIMS strictly adheres to `O_NOFOLLOW` and skips symlinks during directory scans (`list->skipped_symlinks++`). While this prevents symlink loop exhaustion and traversal attacks, it blinds the system to malicious alterations of symlink targets (e.g. replacing a symlink pointing to `/usr/bin/python3` with a pointer to `/tmp/malicious_binary`).
- **Recommendation**:
  Introduce a `RECORD_TYPE_SYMLINK` record in the baseline that invokes `readlink()` to capture the target path string and verify target integrity without dereferencing or traversing the link.

---

## 3. Extended Attributes (`xattr`) & Linux Capabilities

- **Observation**:
  Current metadata comparisons track `dev`, `inode`, `mode`, `uid`, `gid`, `size`, `mtime`, and `ctime`. Security-critical attributes such as POSIX capabilities (`security.capability`), SELinux contexts (`security.selinux`), and POSIX ACLs (`system.posix_acl_access`) are stored in extended attributes and are currently unhashed.
- **Recommendation**:
  Add an optional compilation flag or configuration option (`track_xattrs = true`) using `llistxattr()` and `lgetxattr()` to compute a deterministic SHA-256 hash over sorted attribute name/value tuples.

---

## 4. Multi-Process Concurrency & Advisory Baseline Locking

- **Observation**:
  If a background `fims monitor` daemon executes while an administrator runs `fims baseline update` or `fims scan`, both processes access and potentially modify `baseline.dat` or `status.dat`. While atomic `rename()` prevents partial file corruption, one process may overwrite another's newly committed records.
- **Recommendation**:
  Implement advisory file locking via POSIX `fcntl(fd, F_SETLK, ...)` or `flock()` on a dedicated lock file (`/var/run/fims.lock` or `<baseline>.lock`) to coordinate concurrent access between CLI commands and the monitoring daemon.

---

## 5. Structured SIEM Logging (RFC 5424 & JSON Format)

- **Observation**:
  Operational and alert logs are formatted in plaintext (`[YYYY-MM-DD HH:MM:SS +ZZZZ] [SEVERITY] MESSAGE`). Parsing this requires custom regex rules in log forwarders (e.g., Filebeat, Fluentbit, Splunk).
- **Recommendation**:
  Add a configuration directive `log_format = json` allowing alerts to be emitted as single-line JSON objects with ISO 8601 timestamps, facilitating ingestion into modern SIEM pipelines.

---

## 6. Memory Mapped (`mmap`) Streaming vs. Chunked Read Hashing

- **Observation**:
  `fims_hash_file_sha256` uses a fixed 64 KB heap buffer with standard POSIX `read()`. For extremely large files (e.g., database images or virtual disk containers > 50 GB), standard `read()` incurs significant user/kernel context switching overhead.
- **Recommendation**:
  Benchmark a hybrid approach where files smaller than 1 GB use `mmap(..., PROT_READ, MAP_SHARED | MAP_NORESERVE, ...)` with `madvise(..., MADV_SEQUENTIAL)` to allow the kernel page cache to stream the digest with zero user-space copying.
=== END FILE: FOLLOWUPS.md ===
