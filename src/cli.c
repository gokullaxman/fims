#include "cli.h"
#include "config.h"
#include "scanner.h"
#include "baseline.h"
#include "integrity.h"
#include "monitor.h"
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>
#include <time.h>

static void cli_trim_whitespace(char *str) {
    if (!str) return;
    char *start = str;
    while (*start && isspace((unsigned char)*start)) {
        start++;
    }
    if (start != str) {
        memmove(str, start, strlen(start) + 1);
    }
    size_t len = strlen(str);
    while (len > 0 && isspace((unsigned char)str[len - 1])) {
        str[len - 1] = '\0';
        len--;
    }
}

void fims_cli_print_help(const char *prog_name) {
    const char *prog = prog_name ? prog_name : "fims";
    printf("================================================================================\n");
    printf(" File Integrity Monitoring System (FIMS) v%s\n", FIMS_VERSION);
    printf("================================================================================\n");
    printf("Usage:\n");
    printf("  %s init <dir> [--force] [--add]      Create or extend trusted baseline for <dir>\n", prog);
    printf("  %s scan                              Perform complete integrity scan against baseline\n", prog);
    printf("  %s monitor [--duration <sec>]        Start real-time Linux inotify monitoring\n", prog);
    printf("  %s status                            Display monitoring status and statistics\n", prog);
    printf("  %s report                            Display detected integrity changes from last scan\n", prog);
    printf("  %s baseline show                     Display trusted baseline records and metadata\n", prog);
    printf("  %s baseline update [--yes]           Update baseline after diff confirmation\n", prog);
    printf("  %s config                            Display active configuration and baseline info\n", prog);
    printf("  %s help                              Display this usage guide\n", prog);
    printf("================================================================================\n");
    printf("Canonical Scan Exit Codes (%s scan):\n", prog);
    printf("  0  Clean: No integrity alerts/changes detected\n");
    printf("  1  System/runtime error (I/O failure, invalid argument, permission denied)\n");
    printf("  2  Baseline corrupt (or missing/invalid HMAC checksum)\n");
    printf("  3  Changes detected: One or more integrity alerts found\n");
    printf("================================================================================\n");
}

void fims_cli_print_scan_help(const char *prog_name) {
    const char *prog = prog_name ? prog_name : "fims";
    printf("Usage: %s scan\n\n", prog);
    printf("Perform a complete filesystem integrity scan against the trusted baseline.\n\n");
    printf("Canonical Scan Exit Codes:\n");
    printf("  0  Clean: No integrity alerts/changes detected\n");
    printf("  1  System/runtime error (I/O failure, invalid argument, permission denied)\n");
    printf("  2  Baseline corrupt (or missing/invalid HMAC checksum)\n");
    printf("  3  Changes detected: One or more integrity alerts found\n");
}

static int cmd_init(int argc, char **argv, fims_config_t *cfg) {
    const char *target_dir = NULL;
    bool force = false;
    bool add_mode = false;
    bool has_yes = false;
    bool has_unattended = false;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s init <directory> [--force] [--add] [--yes --allow-unattended]\n\n"
                   "Create or extend a trusted baseline for <directory>.\n"
                   "  --force             Overwrite existing baseline after diff confirmation\n"
                   "  --add               Add directory to existing multi-root baseline\n"
                   "  --yes               Confirm overwrite (requires --allow-unattended)\n"
                   "  --allow-unattended  Allow unattended/non-interactive execution\n",
                   argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--force") == 0 || strcmp(argv[i], "-f") == 0) {
            force = true;
        } else if (strcmp(argv[i], "--add") == 0) {
            add_mode = true;
        } else if (strcmp(argv[i], "--yes") == 0 || strcmp(argv[i], "-y") == 0) {
            has_yes = true;
        } else if (strcmp(argv[i], "--allow-unattended") == 0) {
            has_unattended = true;
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "[ERROR] Unrecognized option '%s' for init command.\n", argv[i]);
            fims_cli_print_help(argv[0]);
            return 1;
        } else {
            if (!target_dir) {
                target_dir = argv[i];
            } else {
                fprintf(stderr, "[ERROR] Unexpected argument '%s'. Usage: fims init <directory> [--force] [--add]\n", argv[i]);
                fims_cli_print_help(argv[0]);
                return 1;
            }
        }
    }

    if (!target_dir) {
        fprintf(stderr, "[ERROR] Missing target directory. Usage: fims init /path/to/directory\n");
        fims_cli_print_help(argv[0]);
        return 1;
    }

    if (has_yes && !has_unattended) {
        fprintf(stderr, "[ERROR] The '--yes' flag is ONLY permitted if accompanied by '--allow-unattended'.\n");
        return 1;
    }

    fims_logger_init(cfg->log_file);
    bool confirmed = (has_yes && has_unattended);

    if (add_mode) {
        char clean_target[FIMS_MAX_PATH];
        fims_status_t st = fims_sanitize_path(target_dir, clean_target, sizeof(clean_target));
        if (st != FIMS_OK) {
            fprintf(stderr, "[ERROR] Invalid directory path '%s'.\n", target_dir);
            return 1;
        }

        fims_file_list_t baseline;
        st = fims_baseline_load(cfg->baseline_file, &baseline);
        if (st == FIMS_ERR_NOT_FOUND) {
            size_t count = 0;
            st = fims_baseline_init_from_dir(clean_target, cfg, force, &count);
            if (st != FIMS_OK) {
                fprintf(stderr, "[ERROR] Failed to initialize baseline for '%s' (status %d).\n", clean_target, (int)st);
                return 1;
            }
            fims_config_save(cfg, NULL);
            fims_status_save(cfg->state_file, cfg, NULL, count, 0);
            printf("[OK] Trusted baseline initialized at '%s' (%zu regular files hashed).\n", cfg->baseline_file, count);
            return 0;
        } else if (st == FIMS_ERR_CORRUPT) {
            fprintf(stderr, "[CRITICAL] Baseline file '%s' is corrupted or tampered! Cannot add root.\n", cfg->baseline_file);
            return 2;
        } else if (st != FIMS_OK) {
            fprintf(stderr, "[ERROR] Unable to load baseline at '%s' (status %d).\n", cfg->baseline_file, (int)st);
            return 1;
        }

        bool already_root = false;
        for (size_t i = 0; i < baseline.root_dir_count; i++) {
            if (strcmp(baseline.root_dirs[i], clean_target) == 0) {
                already_root = true;
                break;
            }
        }
        if (!already_root) {
            if (baseline.root_dir_count >= FIMS_MAX_DIRS) {
                fprintf(stderr, "[ERROR] Maximum number of monitored roots (%d) reached.\n", FIMS_MAX_DIRS);
                fims_file_list_free(&baseline);
                return 1;
            }
            fims_str_copy(baseline.root_dirs[baseline.root_dir_count], FIMS_MAX_PATH, clean_target);
            baseline.root_dir_count++;
        }

        fims_file_list_t new_files;
        if (fims_file_list_init(&new_files) != FIMS_OK) {
            fims_file_list_free(&baseline);
            return 1;
        }
        st = fims_scan_directory(clean_target, cfg, &new_files);
        if (st != FIMS_OK) {
            fprintf(stderr, "[ERROR] Failed to scan directory '%s' (status %d).\n", clean_target, (int)st);
            fims_file_list_free(&new_files);
            fims_file_list_free(&baseline);
            return 1;
        }

        for (size_t i = 0; i < new_files.count; i++) {
            const fims_file_record_t *nr = &new_files.records[i];
            bool found = false;
            for (size_t j = 0; j < baseline.count; j++) {
                if (strcmp(baseline.records[j].path, nr->path) == 0) {
                    baseline.records[j] = *nr;
                    found = true;
                    break;
                }
            }
            if (!found) {
                if (fims_file_list_append(&baseline, nr) != FIMS_OK) {
                    fims_file_list_free(&new_files);
                    fims_file_list_free(&baseline);
                    return 1;
                }
            }
        }
        fims_file_list_free(&new_files);
        fims_file_list_sort(&baseline);

        st = fims_baseline_save(cfg->baseline_file, &baseline, true);
        if (st != FIMS_OK) {
            fprintf(stderr, "[ERROR] Failed to save updated baseline (status %d).\n", (int)st);
            fims_file_list_free(&baseline);
            return 1;
        }

        fims_config_add_dir(cfg, clean_target);
        fims_config_save(cfg, NULL);
        fims_status_save(cfg->state_file, cfg, NULL, baseline.count, 0);

        if (cfg->log_file[0]) {
            fims_log_message(cfg->log_file, SEV_INFO,
                             "Added root directory '%s' to baseline (%zu total files across %zu roots)",
                             clean_target, baseline.count, baseline.root_dir_count);
        }

        printf("[OK] Added '%s' to trusted baseline at '%s' (%zu regular files recorded across %zu roots).\n",
               clean_target, cfg->baseline_file, baseline.count, baseline.root_dir_count);

        fims_file_list_free(&baseline);
        return 0;
    }

    if (access(cfg->baseline_file, F_OK) == 0) {
        if (!force) {
            fprintf(stderr,
                    "[ERROR] Baseline file '%s' already exists.\n"
                    "        To prevent accidental overwriting, use 'fims baseline update' or '--force'.\n",
                    cfg->baseline_file);
            return 1;
        }

        fims_file_list_t existing;
        fims_status_t st = fims_baseline_load(cfg->baseline_file, &existing);
        size_t accepted_alerts = 0;

        if (st == FIMS_OK) {
            fims_file_list_t current;
            if (fims_file_list_init(&current) == FIMS_OK) {
                st = fims_scan_directory(target_dir, cfg, &current);
                if (st == FIMS_OK) {
                    fims_report_t report;
                    if (fims_report_init(&report) == FIMS_OK) {
                        printf("[INFO] Executing integrity check before overwrite...\n");
                        fims_check_integrity(&existing, &current, cfg, true, &report);
                        accepted_alerts = report.count;

                        printf("================================================================================\n");
                        printf(" Baseline Overwrite Diff Summary\n");
                        printf("================================================================================\n");
                        printf(" Total Scanned Files : %zu\n", current.count);
                        printf(" Detected Changes    : %zu\n", report.count);
                        printf("   - Files Added     : %zu\n", report.added_count);
                        printf("   - Files Modified  : %zu\n", report.modified_count);
                        printf("   - Files Deleted   : %zu\n", report.deleted_count);
                        printf("   - Perms Changed   : %zu\n", report.perm_changed_count);
                        printf("================================================================================\n");

                        fims_report_free(&report);
                    }
                }
                fims_file_list_free(&current);
            }
            fims_file_list_free(&existing);
        } else {
            fprintf(stderr, "[WARNING] Existing baseline is invalid or corrupt (status %d).\n", (int)st);
        }

        if (!confirmed) {
            printf("Are you sure you want to overwrite the trusted baseline at '%s'?\n", cfg->baseline_file);
            printf("Type 'yes' to confirm: ");
            fflush(stdout);
            char ans[64];
            if (!fgets(ans, sizeof(ans), stdin)) {
                printf("\nBaseline initialization cancelled.\n");
                return 0;
            }
            cli_trim_whitespace(ans);
            if (strcmp(ans, "yes") != 0) {
                printf("Baseline initialization cancelled (did not receive 'yes').\n");
                return 0;
            }
        }

        size_t count = 0;
        st = fims_baseline_init_from_dir(target_dir, cfg, true, &count);
        if (st != FIMS_OK) {
            fprintf(stderr, "[ERROR] Failed to initialize baseline for '%s' (error code %d).\n", target_dir, (int)st);
            return 1;
        }

        fims_config_save(cfg, NULL);
        fims_status_save(cfg->state_file, cfg, NULL, count, 0);

        if (cfg->log_file[0]) {
            fims_log_message(cfg->log_file, SEV_INFO,
                             "Trusted baseline overwritten via init --force after confirmation (%zu files, %zu accepted alerts)",
                             count, accepted_alerts);
        }

        printf("[OK] Trusted baseline initialized at '%s' (%zu regular files hashed).\n", cfg->baseline_file, count);
        return 0;
    }

    size_t count = 0;
    fims_status_t st = fims_baseline_init_from_dir(target_dir, cfg, force, &count);
    if (st == FIMS_ERR_EXISTS) {
        fprintf(stderr,
                "[ERROR] Baseline file '%s' already exists.\n"
                "        To prevent accidental overwriting, use 'fims baseline update' or '--force'.\n",
                cfg->baseline_file);
        return 1;
    }
    if (st != FIMS_OK) {
        fprintf(stderr, "[ERROR] Failed to initialize baseline for '%s' (error code %d).\n",
                target_dir, (int)st);
        return 1;
    }

    fims_config_save(cfg, NULL);
    fims_status_save(cfg->state_file, cfg, NULL, count, 0);
    printf("[OK] Trusted baseline initialized at '%s' (%zu regular files hashed).\n",
           cfg->baseline_file, count);
    return 0;
}

static int cmd_scan(int argc, char **argv, fims_config_t *cfg) {
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            fims_cli_print_scan_help(argv[0]);
            return 0;
        }
        fprintf(stderr, "[ERROR] Unrecognized option '%s' for scan command.\n", argv[i]);
        fims_cli_print_scan_help(argv[0]);
        return FIMS_EXIT_ERROR;
    }

    fims_file_list_t baseline;
    fims_status_t st = fims_baseline_load(cfg->baseline_file, &baseline);
    if (st == FIMS_ERR_NOT_FOUND) {
        fprintf(stderr, "[ERROR] Baseline file '%s' not found. Run 'fims init <dir>' first.\n",
                cfg->baseline_file);
        return FIMS_EXIT_ERROR;
    }
    if (st == FIMS_ERR_CORRUPT) {
        fprintf(stderr, "[CRITICAL] Baseline file '%s' failed cryptographic integrity validation!\n",
                cfg->baseline_file);
        return FIMS_EXIT_CORRUPT;
    }
    if (st != FIMS_OK) {
        fprintf(stderr, "[ERROR] Unable to load baseline (status %d).\n", (int)st);
        return FIMS_EXIT_ERROR;
    }

    fims_file_list_t current;
    if (fims_file_list_init(&current) != FIMS_OK) {
        fims_file_list_free(&baseline);
        return FIMS_EXIT_ERROR;
    }

    bool missing_or_unreadable_root = false;
    for (size_t i = 0; i < baseline.root_dir_count; i++) {
        struct stat root_st;
        if (stat(baseline.root_dirs[i], &root_st) != 0) {
            missing_or_unreadable_root = true;
            fprintf(stderr, "[WARNING] Monitored root directory missing or inaccessible: %s\n",
                    baseline.root_dirs[i]);
            if (cfg->log_file[0]) {
                fims_log_message(cfg->log_file, SEV_HIGH,
                                 "Monitored root directory missing or inaccessible: %s",
                                 baseline.root_dirs[i]);
            }
        } else if (!S_ISDIR(root_st.st_mode) || access(baseline.root_dirs[i], R_OK | X_OK) != 0) {
            missing_or_unreadable_root = true;
            fprintf(stderr, "[WARNING] Monitored root directory not readable or not a directory: %s\n",
                    baseline.root_dirs[i]);
            if (cfg->log_file[0]) {
                fims_log_message(cfg->log_file, SEV_HIGH,
                                 "Monitored root directory not readable or not a directory: %s",
                                 baseline.root_dirs[i]);
            }
        }
    }

    st = fims_scan_directories((const char (*)[FIMS_MAX_PATH])baseline.root_dirs,
                               baseline.root_dir_count,
                               cfg,
                               &current);
    if (st != FIMS_OK) {
        if (st == FIMS_ERR_NOT_FOUND || st == FIMS_ERR_PERMISSION) {
            missing_or_unreadable_root = true;
        } else {
            fprintf(stderr, "[ERROR] Filesystem scan failed (status %d).\n", (int)st);
            fims_file_list_free(&current);
            fims_file_list_free(&baseline);
            return FIMS_EXIT_ERROR;
        }
    }

    fims_report_t report;
    if (fims_report_init(&report) != FIMS_OK) {
        fims_file_list_free(&current);
        fims_file_list_free(&baseline);
        return FIMS_EXIT_ERROR;
    }

    st = fims_check_integrity(&baseline, &current, cfg, true, &report);
    if (st != FIMS_OK) {
        fprintf(stderr, "[ERROR] Integrity check failed (status %d).\n", (int)st);
        fims_report_free(&report);
        fims_file_list_free(&current);
        fims_file_list_free(&baseline);
        return FIMS_EXIT_ERROR;
    }

    fims_report_save(cfg->report_file, &report);
    fims_status_save(cfg->state_file, cfg, NULL, baseline.count, report.count);

    if (report.count == 0 && !missing_or_unreadable_root) {
        printf("[OK] Integrity scan complete (%zu files verified, 0 changes detected).\n",
               current.count);
    } else {
        printf("[SUMMARY] Integrity scan complete: %zu change(s) detected across %zu scanned files.\n",
               report.count, current.count);
    }

    int exit_code = (report.count > 0 || missing_or_unreadable_root) ? FIMS_EXIT_CHANGES : FIMS_EXIT_OK;

    fims_report_free(&report);
    fims_file_list_free(&current);
    fims_file_list_free(&baseline);
    return exit_code;
}

static int cmd_baseline(int argc, char **argv, fims_config_t *cfg) {
    if (argc < 3) {
        fprintf(stderr, "[ERROR] Usage: fims baseline <show|update>\n");
        return 1;
    }

    if (strcmp(argv[2], "show") == 0) {
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
                printf("Usage: %s baseline show\n\nDisplay trusted baseline records and metadata.\n", argv[0]);
                return 0;
            }
            fprintf(stderr, "[ERROR] Unrecognized option '%s' for baseline show.\n", argv[i]);
            return 1;
        }

        fims_status_t st = fims_baseline_show(cfg->baseline_file);
        if (st == FIMS_ERR_NOT_FOUND) {
            fprintf(stderr, "[ERROR] Baseline file '%s' does not exist.\n", cfg->baseline_file);
            return 1;
        }
        if (st == FIMS_ERR_CORRUPT) {
            fprintf(stderr, "[CRITICAL] Baseline file '%s' is corrupted or tampered!\n",
                    cfg->baseline_file);
            return 2;
        }
        return (st == FIMS_OK) ? 0 : 1;
    }

    if (strcmp(argv[2], "update") == 0) {
        bool has_yes = false;
        bool has_unattended = false;

        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--yes") == 0 || strcmp(argv[i], "-y") == 0) {
                has_yes = true;
            } else if (strcmp(argv[i], "--allow-unattended") == 0) {
                has_unattended = true;
            } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
                printf("Usage: %s baseline update [--yes --allow-unattended]\n\n"
                       "Execute an integrity scan, display diff summary, and update baseline after confirmation.\n",
                       argv[0]);
                return 0;
            } else {
                fprintf(stderr, "[ERROR] Unrecognized option '%s' for baseline update.\n", argv[i]);
                return 1;
            }
        }

        if (has_yes && !has_unattended) {
            fprintf(stderr, "[ERROR] The '--yes' flag is ONLY permitted if accompanied by '--allow-unattended'.\n");
            return 1;
        }

        bool confirmed = (has_yes && has_unattended);

        fims_file_list_t existing;
        fims_status_t st = fims_baseline_load(cfg->baseline_file, &existing);
        if (st == FIMS_ERR_NOT_FOUND) {
            fprintf(stderr, "[ERROR] Baseline file '%s' does not exist. Run 'fims init <dir>' first.\n",
                    cfg->baseline_file);
            return 1;
        }
        if (st == FIMS_ERR_CORRUPT) {
            fprintf(stderr, "[CRITICAL] Baseline file '%s' failed cryptographic integrity validation!\n",
                    cfg->baseline_file);
            return 2;
        }
        if (st != FIMS_OK) {
            fprintf(stderr, "[ERROR] Cannot update baseline: existing baseline invalid or inaccessible (%d).\n",
                    (int)st);
            return 1;
        }

        fims_file_list_t current;
        if (fims_file_list_init(&current) != FIMS_OK) {
            fims_file_list_free(&existing);
            return 1;
        }

        st = fims_scan_directories((const char (*)[FIMS_MAX_PATH])existing.root_dirs,
                                   existing.root_dir_count,
                                   cfg,
                                   &current);
        if (st != FIMS_OK) {
            fprintf(stderr, "[WARNING] Filesystem scan encountered errors (%d); proceeding with available records.\n", (int)st);
        }

        fims_report_t report;
        if (fims_report_init(&report) != FIMS_OK) {
            fims_file_list_free(&current);
            fims_file_list_free(&existing);
            return 1;
        }

        printf("[INFO] Executing integrity check to identify baseline changes...\n");
        fims_check_integrity(&existing, &current, cfg, true, &report);

        printf("================================================================================\n");
        printf(" Baseline Update Diff Summary\n");
        printf("================================================================================\n");
        printf(" Total Scanned Files : %zu\n", current.count);
        printf(" Detected Changes    : %zu\n", report.count);
        printf("   - Files Added     : %zu\n", report.added_count);
        printf("   - Files Modified  : %zu\n", report.modified_count);
        printf("   - Files Deleted   : %zu\n", report.deleted_count);
        printf("   - Perms Changed   : %zu\n", report.perm_changed_count);
        printf("================================================================================\n");

        if (!confirmed) {
            printf("Are you sure you want to accept all detected changes and update the trusted baseline?\n");
            printf("Type 'yes' to confirm: ");
            fflush(stdout);
            char ans[64];
            if (!fgets(ans, sizeof(ans), stdin)) {
                printf("\nBaseline update cancelled.\n");
                fims_report_free(&report);
                fims_file_list_free(&current);
                fims_file_list_free(&existing);
                return 0;
            }
            cli_trim_whitespace(ans);
            if (strcmp(ans, "yes") != 0) {
                printf("Baseline update cancelled (did not receive 'yes').\n");
                fims_report_free(&report);
                fims_file_list_free(&current);
                fims_file_list_free(&existing);
                return 0;
            }
        }

        for (size_t i = 0; i < existing.root_dir_count; i++) {
            bool found = false;
            for (size_t j = 0; j < current.root_dir_count; j++) {
                if (strcmp(current.root_dirs[j], existing.root_dirs[i]) == 0) {
                    found = true;
                    break;
                }
            }
            if (!found && current.root_dir_count < FIMS_MAX_DIRS) {
                fims_str_copy(current.root_dirs[current.root_dir_count], FIMS_MAX_PATH, existing.root_dirs[i]);
                current.root_dir_count++;
            }
        }

        size_t accepted_alerts = report.count;
        st = fims_baseline_save(cfg->baseline_file, &current, true);

        if (st == FIMS_OK) {
            printf("[OK] Trusted baseline updated (%zu files recorded).\n", current.count);
            fims_logger_init(cfg->log_file);
            if (cfg->log_file[0]) {
                fims_log_message(cfg->log_file, SEV_INFO,
                                 "Trusted baseline manually updated after user confirmation (%zu files, %zu accepted alerts)",
                                 current.count, accepted_alerts);
            }
            fims_status_save(cfg->state_file, cfg, NULL, current.count, 0);
        } else {
            fprintf(stderr, "[ERROR] Failed to save updated baseline (status %d).\n", (int)st);
        }

        fims_report_free(&report);
        fims_file_list_free(&current);
        fims_file_list_free(&existing);
        return (st == FIMS_OK) ? 0 : 1;
    }

    fprintf(stderr, "[ERROR] Unknown baseline subcommand '%s'. Use 'show' or 'update'.\n", argv[2]);
    return 1;
}

static int cmd_monitor(int argc, char **argv, fims_config_t *cfg) {
    uint32_t max_seconds = 0;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s monitor [--duration <sec>]\n\n"
                   "Start real-time Linux inotify monitoring.\n"
                   "  --duration <sec>  Stop monitoring after <sec> seconds (positive integer)\n",
                   argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--duration") == 0 || strcmp(argv[i], "-d") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "[ERROR] Missing value for %s. Expected positive integer in seconds.\n", argv[i]);
                fims_cli_print_help(argv[0]);
                return 1;
            }
            i++;
            char *endptr = NULL;
            errno = 0;
            long v = strtol(argv[i], &endptr, 10);
            if (errno != 0 || !endptr || *endptr != '\0' || endptr == argv[i] || v <= 0) {
                fprintf(stderr, "[ERROR] Invalid duration value '%s'. Expected positive integer in seconds.\n", argv[i]);
                fims_cli_print_help(argv[0]);
                return 1;
            }
            max_seconds = (uint32_t)v;
        } else {
            fprintf(stderr, "[ERROR] Unrecognized option '%s' for monitor command.\n", argv[i]);
            fims_cli_print_help(argv[0]);
            return 1;
        }
    }

    fims_logger_init(cfg->log_file);
    printf("[INFO] Starting FIMS real-time inotify monitor (Press Ctrl+C to stop)...\n");
    fflush(stdout);

    fims_monitor_reset_stop();
    fims_status_t st = fims_monitor_run(cfg, max_seconds);
    if (st != FIMS_OK) {
        fprintf(stderr, "[ERROR] Real-time monitor exited with error code %d.\n", (int)st);
        return 1;
    }
    printf("[INFO] FIMS real-time monitor stopped cleanly.\n");
    return 0;
}

static int cmd_status(int argc, char **argv, fims_config_t *cfg) {
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s status\n\nDisplay monitoring status and statistics.\n", argv[0]);
            return 0;
        }
        fprintf(stderr, "[ERROR] Unrecognized option '%s' for status command.\n", argv[i]);
        return 1;
    }
    return (fims_status_display(cfg) == FIMS_OK) ? 0 : 1;
}

static int cmd_report(int argc, char **argv, fims_config_t *cfg) {
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s report\n\nDisplay detected integrity changes from last scan.\n", argv[0]);
            return 0;
        }
        fprintf(stderr, "[ERROR] Unrecognized option '%s' for report command.\n", argv[i]);
        return 1;
    }
    fims_status_t st = fims_report_display(cfg->report_file);
    if (st == FIMS_ERR_NOT_FOUND) {
        printf("[INFO] No scan report found at '%s'. Run 'fims scan' first.\n", cfg->report_file);
        return 0;
    }
    return (st == FIMS_OK) ? 0 : 1;
}

static int cmd_config(int argc, char **argv, const fims_config_t *cfg) {
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s config\n\nDisplay active FIMS configuration and baseline state.\n", argv[0]);
            return 0;
        }
        fprintf(stderr, "[ERROR] Unrecognized option '%s' for config command.\n", argv[i]);
        return 1;
    }

    fims_config_print(cfg);

    printf("\n============================================================\n");
    printf(" Active Baseline Contents (%s)\n", cfg->baseline_file);
    printf("============================================================\n");

    fims_file_list_t bl;
    fims_status_t st = fims_baseline_load(cfg->baseline_file, &bl);
    if (st == FIMS_OK) {
        time_t created = (time_t)bl.created_at;
        char ts_buf[64];
        struct tm tm_info;
        if (localtime_r(&created, &tm_info) != NULL) {
            strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%d %H:%M:%S %z", &tm_info);
        } else {
            snprintf(ts_buf, sizeof(ts_buf), "%lld", (long long)bl.created_at);
        }

        printf(" Baseline Status     : VALID\n");
        printf(" Creation Timestamp  : %s\n", ts_buf);
        printf(" Recorded Files      : %zu\n", bl.count);
        printf(" Monitored Roots (%zu):\n", bl.root_dir_count);
        for (size_t i = 0; i < bl.root_dir_count; i++) {
            printf("   - %s\n", bl.root_dirs[i]);
        }
        fims_file_list_free(&bl);
    } else if (st == FIMS_ERR_NOT_FOUND) {
        printf(" Baseline Status     : NOT FOUND (run 'fims init <dir>' to create)\n");
    } else if (st == FIMS_ERR_CORRUPT) {
        printf(" Baseline Status     : CORRUPTED / TAMPERED\n");
    } else {
        printf(" Baseline Status     : ERROR (code %d)\n", (int)st);
    }
    printf("============================================================\n");
    return 0;
}

int fims_cli_dispatch(int argc, char **argv) {
    if (argc < 2) {
        fims_cli_print_help(argc > 0 ? argv[0] : "fims");
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0) {
        fims_cli_print_help(argv[0]);
        return 0;
    }

    if (strcmp(cmd, "--version") == 0 || strcmp(cmd, "-v") == 0) {
        printf("FIMS version %s\n", FIMS_VERSION);
        return 0;
    }

    fims_config_t cfg;
    fims_config_init_defaults(&cfg);
    fims_config_load(&cfg, NULL);

    if (strcmp(cmd, "init") == 0) {
        return cmd_init(argc, argv, &cfg);
    }
    if (strcmp(cmd, "scan") == 0) {
        return cmd_scan(argc, argv, &cfg);
    }
    if (strcmp(cmd, "monitor") == 0) {
        return cmd_monitor(argc, argv, &cfg);
    }
    if (strcmp(cmd, "status") == 0) {
        return cmd_status(argc, argv, &cfg);
    }
    if (strcmp(cmd, "report") == 0) {
        return cmd_report(argc, argv, &cfg);
    }
    if (strcmp(cmd, "baseline") == 0) {
        return cmd_baseline(argc, argv, &cfg);
    }
    if (strcmp(cmd, "config") == 0) {
        return cmd_config(argc, argv, &cfg);
    }

    fprintf(stderr, "[ERROR] Unrecognized command '%s'. Run 'fims help' for usage.\n", cmd);
    fims_cli_print_help(argv[0]);
    return 1;
}
