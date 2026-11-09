#include "cli.h"
#include "config.h"
#include "scanner.h"
#include "baseline.h"
#include "integrity.h"
#include "monitor.h"
#include "logger.h"
#include "ui.h"
#include "ui_tui.h"

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

    fims_ui_banner();

    const char *c_cyan = fims_ui_color(UI_COLOR_BOLD_CYAN);
    const char *c_wht  = fims_ui_color(UI_COLOR_BOLD_WHITE);
    const char *c_dim  = fims_ui_color(UI_COLOR_DIM);
    const char *c_grn  = fims_ui_color(UI_COLOR_GREEN);
    const char *c_yel  = fims_ui_color(UI_COLOR_YELLOW);
    const char *c_red  = fims_ui_color(UI_COLOR_RED);
    const char *c_rst  = fims_ui_color(UI_COLOR_RESET);

    printf("\n%sUSAGE:%s\n", c_cyan, c_rst);
    printf("  %s%s%s %s<command>%s [options] [arguments]\n\n", c_wht, prog, c_rst, c_cyan, c_rst);

    printf("%sCORE COMMANDS:%s\n", c_cyan, c_rst);
    printf("  %s%-34s%s %sCreate or extend trusted baseline for <dir>%s\n",
           c_wht, "init <dir> [--force] [--add]", c_rst, c_dim, c_rst);
    printf("  %s%-34s%s %sPerform complete integrity scan against baseline%s\n",
           c_wht, "scan", c_rst, c_dim, c_rst);
    printf("  %s%-34s%s %sStart real-time Linux inotify monitoring%s\n",
           c_wht, "monitor [--duration <sec>]", c_rst, c_dim, c_rst);
    printf("  %s%-34s%s %sDisplay monitoring status and statistics%s\n",
           c_wht, "status", c_rst, c_dim, c_rst);
    printf("  %s%-34s%s %sDisplay detected integrity changes from last scan%s\n",
           c_wht, "report", c_rst, c_dim, c_rst);
    printf("  %s%-34s%s %sDisplay trusted baseline records and metadata%s\n",
           c_wht, "baseline show", c_rst, c_dim, c_rst);
    printf("  %s%-34s%s %sUpdate baseline after diff confirmation%s\n",
           c_wht, "baseline update [--yes]", c_rst, c_dim, c_rst);
    printf("  %s%-34s%s %sDisplay active configuration and baseline info%s\n",
           c_wht, "config", c_rst, c_dim, c_rst);
    printf("  %s%-34s%s %sLaunch interactive full-screen Security Console%s\n",
           c_wht, "tui", c_rst, c_dim, c_rst);
    printf("  %s%-34s%s %sDisplay cybersecurity startup banner%s\n",
           c_wht, "banner", c_rst, c_dim, c_rst);
    printf("  %s%-34s%s %sDisplay this usage guide%s\n",
           c_wht, "help, --help, -h", c_rst, c_dim, c_rst);

    printf("\n%sGLOBAL OPTIONS:%s\n", c_cyan, c_rst);
    printf("  %s%-34s%s %sDisable ANSI colored output (also respects NO_COLOR)%s\n",
           c_wht, "--no-color", c_rst, c_dim, c_rst);
    printf("  %s%-34s%s %sForce ANSI colored output%s\n",
           c_wht, "--color", c_rst, c_dim, c_rst);
    printf("  %s%-34s%s %sDisplay version information and exit%s\n",
           c_wht, "--version, -v", c_rst, c_dim, c_rst);

    printf("\n================================================================================\n");
    printf("Canonical Scan Exit Codes (%s scan):\n", prog);
    printf("  %s0  Clean%s: No integrity alerts/changes detected\n", c_grn, c_rst);
    printf("  %s1  System/runtime error%s (I/O failure, invalid argument, permission denied)\n", c_yel, c_rst);
    printf("  %s2  Baseline corrupt%s (or missing/invalid HMAC checksum)\n", c_red, c_rst);
    printf("  %s3  Changes detected%s: One or more integrity alerts found\n", c_red, c_rst);
    printf("================================================================================\n");

    printf("\n%sSECURITY OPERATIONS EXAMPLES:%s\n", c_cyan, c_rst);
    printf("  %s# 1. Initialize trusted baseline for /etc:%s\n", c_dim, c_rst);
    printf("  %s%s init /etc%s\n\n", c_wht, prog, c_rst);
    printf("  %s# 2. Add second monitored root to existing baseline:%s\n", c_dim, c_rst);
    printf("  %s%s init --add /var/www%s\n\n", c_wht, prog, c_rst);
    printf("  %s# 3. Perform automated integrity scan (deterministic exit codes):%s\n", c_dim, c_rst);
    printf("  %s%s scan%s\n\n", c_wht, prog, c_rst);
    printf("  %s# 4. Run real-time monitoring for 1 hour:%s\n", c_dim, c_rst);
    printf("  %s%s monitor --duration 3600%s\n\n", c_wht, prog, c_rst);
    printf("  %s# 5. Review differences and update baseline:%s\n", c_dim, c_rst);
    printf("  %s%s baseline update%s\n\n", c_wht, prog, c_rst);
}

void fims_cli_print_scan_help(const char *prog_name) {
    const char *prog = prog_name ? prog_name : "fims";
    fims_ui_header("SCAN COMMAND REFERENCE");
    printf("Usage: %s scan [--no-color]\n\n", prog);
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
            printf("Usage: %s init <directory> [--force] [--add] [--yes --allow-unattended] [--no-color]\n\n"
                   "Create or extend a trusted baseline for <directory>.\n"
                   "  --force             Overwrite existing baseline after diff confirmation\n"
                   "  --add               Add directory to existing multi-root baseline\n"
                   "  --yes               Confirm overwrite (requires --allow-unattended)\n"
                   "  --allow-unattended  Allow unattended/non-interactive execution\n"
                   "  --no-color          Disable ANSI color output\n",
                   argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--no-color") == 0 || strcmp(argv[i], "--color") == 0) {
            continue;
        } else if (strcmp(argv[i], "--force") == 0 || strcmp(argv[i], "-f") == 0) {
            force = true;
        } else if (strcmp(argv[i], "--add") == 0) {
            add_mode = true;
        } else if (strcmp(argv[i], "--yes") == 0 || strcmp(argv[i], "-y") == 0) {
            has_yes = true;
        } else if (strcmp(argv[i], "--allow-unattended") == 0) {
            has_unattended = true;
        } else if (argv[i][0] == '-') {
            fims_ui_error("Unrecognized option '%s' for init command.", argv[i]);
            fims_cli_print_help(argv[0]);
            return 1;
        } else {
            if (!target_dir) {
                target_dir = argv[i];
            } else {
                fims_ui_error("Unexpected argument '%s'. Usage: fims init <directory> [--force] [--add]", argv[i]);
                fims_cli_print_help(argv[0]);
                return 1;
            }
        }
    }

    if (!target_dir) {
        fims_ui_error("Missing target directory. Usage: fims init /path/to/directory");
        fims_cli_print_help(argv[0]);
        return 1;
    }

    if (has_yes && !has_unattended) {
        fims_ui_error("The '--yes' flag is ONLY permitted if accompanied by '--allow-unattended'.");
        return 1;
    }

    fims_logger_init(cfg->log_file);
    bool confirmed = (has_yes && has_unattended);
    const char *hmac_key_file = getenv("FIMS_HMAC_KEY_FILE");
    bool has_hmac = (hmac_key_file && hmac_key_file[0] != '\0');

    if (add_mode) {
        fims_ui_header("BASELINE EXTENSION");
        char clean_target[FIMS_MAX_PATH];
        fims_status_t st = fims_sanitize_path(target_dir, clean_target, sizeof(clean_target));
        if (st != FIMS_OK) {
            fims_ui_error("Invalid directory path '%s'.", target_dir);
            return 1;
        }

        fims_ui_info("Adding directory root: %s", clean_target);

        fims_file_list_t baseline;
        st = fims_baseline_load(cfg->baseline_file, &baseline);
        if (st == FIMS_ERR_NOT_FOUND) {
            size_t count = 0;
            fims_ui_info("Calculating SHA-256 hashes for initial baseline...");
            st = fims_baseline_init_from_dir(clean_target, cfg, force, &count);
            if (st != FIMS_OK) {
                fims_ui_error("Failed to initialize baseline for '%s' (status %d).", clean_target, (int)st);
                return 1;
            }
            fims_config_save(cfg, NULL);
            fims_status_save(cfg->state_file, cfg, NULL, count, 0);

            fims_ui_success("Baseline created successfully");
            fims_ui_success("Cryptographic authentication verified");
            printf("[OK] Trusted baseline initialized at '%s' (%zu regular files hashed).\n", cfg->baseline_file, count);
            fims_ui_field("Tracked files", "%zu", count);
            fims_ui_field("Algorithm", "SHA-256");
            fims_ui_field("Protection", "%s", has_hmac ? "HMAC-SHA256 Authenticated" : "SHA-256 Self-Digest");
            fims_ui_status_box("BASELINE PROTECTED", true, "Cryptographic integrity verified");
            return 0;
        } else if (st == FIMS_ERR_CORRUPT) {
            fims_ui_critical("Baseline file '%s' is corrupted or tampered! Cannot add root.", cfg->baseline_file);
            return 2;
        } else if (st != FIMS_OK) {
            fims_ui_error("Unable to load baseline at '%s' (status %d).", cfg->baseline_file, (int)st);
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
                fims_ui_error("Maximum number of monitored roots (%d) reached.", FIMS_MAX_DIRS);
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

        fims_ui_info("Scanning new root files...");
        st = fims_scan_directory(clean_target, cfg, &new_files);
        if (st != FIMS_OK) {
            fims_ui_error("Failed to scan directory '%s' (status %d).", clean_target, (int)st);
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
            fims_ui_error("Failed to save updated baseline (status %d).", (int)st);
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

        fims_ui_success("Added '%s' to trusted baseline at '%s'", clean_target, cfg->baseline_file);
        printf("[OK] Added '%s' to trusted baseline at '%s' (%zu regular files recorded across %zu roots).\n",
               clean_target, cfg->baseline_file, baseline.count, baseline.root_dir_count);
        fims_ui_field("Tracked files", "%zu", baseline.count);
        fims_ui_field("Monitored Roots", "%zu", baseline.root_dir_count);
        fims_ui_field("Algorithm", "SHA-256");
        fims_ui_field("Protection", "%s", has_hmac ? "HMAC-SHA256 Authenticated" : "SHA-256 Self-Digest");
        fims_ui_status_box("BASELINE EXTENDED", true, "All monitored roots protected");

        fims_file_list_free(&baseline);
        return 0;
    }

    fims_ui_header("BASELINE INITIALIZATION");
    fims_ui_info("Monitoring directory: %s", target_dir);
    if (has_hmac) {
        fims_ui_info("Generating HMAC-SHA256 authentication (Key: %s)...", hmac_key_file);
    } else {
        fims_ui_info("Calculating SHA-256 hashes...");
    }

    if (access(cfg->baseline_file, F_OK) == 0) {
        if (!force) {
            fims_ui_error("Baseline file '%s' already exists.", cfg->baseline_file);
            fprintf(stderr, "        To prevent accidental overwriting, use 'fims baseline update' or '--force'.\n");
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
                        fims_ui_info("Executing integrity check before overwrite...");
                        fims_check_integrity(&existing, &current, cfg, false, &report);
                        accepted_alerts = report.count;

                        printf("\n================================================================================\n");
                        printf(" Baseline Overwrite Diff Summary\n");
                        printf("================================================================================\n");
                        fims_ui_field("Total Scanned Files", "%zu", current.count);
                        fims_ui_field("Detected Changes", "%zu", report.count);
                        fims_ui_field("  - Files Added", "%zu", report.added_count);
                        fims_ui_field("  - Files Modified", "%zu", report.modified_count);
                        fims_ui_field("  - Files Deleted", "%zu", report.deleted_count);
                        fims_ui_field("  - Perms Changed", "%zu", report.perm_changed_count);
                        printf("================================================================================\n\n");

                        fims_report_free(&report);
                    }
                }
                fims_file_list_free(&current);
            }
            fims_file_list_free(&existing);
        } else {
            fims_ui_warn("Existing baseline is invalid or corrupt (status %d).", (int)st);
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
            fims_ui_error("Failed to initialize baseline for '%s' (error code %d).", target_dir, (int)st);
            return 1;
        }

        fims_config_save(cfg, NULL);
        fims_status_save(cfg->state_file, cfg, NULL, count, 0);

        if (cfg->log_file[0]) {
            fims_log_message(cfg->log_file, SEV_INFO,
                             "Trusted baseline overwritten via init --force after confirmation (%zu files, %zu accepted alerts)",
                             count, accepted_alerts);
        }

        fims_ui_success("Baseline created successfully");
        fims_ui_success("Cryptographic authentication verified");
        printf("[OK] Trusted baseline initialized at '%s' (%zu regular files hashed).\n", cfg->baseline_file, count);
        fims_ui_field("Tracked files", "%zu", count);
        fims_ui_field("Algorithm", "SHA-256");
        fims_ui_field("Protection", "%s", has_hmac ? "HMAC-SHA256 Authenticated" : "SHA-256 Self-Digest");
        fims_ui_status_box("BASELINE PROTECTED", true, "Cryptographic integrity verified");
        return 0;
    }

    size_t count = 0;
    fims_status_t st = fims_baseline_init_from_dir(target_dir, cfg, force, &count);
    if (st == FIMS_ERR_EXISTS) {
        fims_ui_error("Baseline file '%s' already exists.", cfg->baseline_file);
        fprintf(stderr, "        To prevent accidental overwriting, use 'fims baseline update' or '--force'.\n");
        return 1;
    }
    if (st != FIMS_OK) {
        fims_ui_error("Failed to initialize baseline for '%s' (error code %d).", target_dir, (int)st);
        return 1;
    }

    fims_config_save(cfg, NULL);
    fims_status_save(cfg->state_file, cfg, NULL, count, 0);

    fims_ui_success("Baseline created successfully");
    fims_ui_success("Cryptographic authentication verified");
    printf("[OK] Trusted baseline initialized at '%s' (%zu regular files hashed).\n",
           cfg->baseline_file, count);
    fims_ui_field("Tracked files", "%zu", count);
    fims_ui_field("Algorithm", "SHA-256");
    fims_ui_field("Protection", "%s", has_hmac ? "HMAC-SHA256 Authenticated" : "SHA-256 Self-Digest");
    fims_ui_status_box("BASELINE PROTECTED", true, "Cryptographic integrity verified");
    return 0;
}

static int cmd_scan(int argc, char **argv, fims_config_t *cfg) {
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            fims_cli_print_scan_help(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--no-color") == 0 || strcmp(argv[i], "--color") == 0) {
            continue;
        }
        fims_ui_error("Unrecognized option '%s' for scan command.", argv[i]);
        fims_cli_print_scan_help(argv[0]);
        return FIMS_EXIT_ERROR;
    }

    fims_ui_header("INTEGRITY SCAN");
    fims_ui_info("Loading trusted baseline: %s", cfg->baseline_file);

    fims_file_list_t baseline;
    fims_status_t st = fims_baseline_load(cfg->baseline_file, &baseline);
    if (st == FIMS_ERR_NOT_FOUND) {
        fims_ui_error("Baseline file '%s' not found. Run 'fims init <dir>' first.",
                      cfg->baseline_file);
        return FIMS_EXIT_ERROR;
    }
    if (st == FIMS_ERR_CORRUPT) {
        fims_ui_critical("Baseline file '%s' failed cryptographic integrity validation!",
                         cfg->baseline_file);
        return FIMS_EXIT_CORRUPT;
    }
    if (st != FIMS_OK) {
        fims_ui_error("Unable to load baseline (status %d).", (int)st);
        return FIMS_EXIT_ERROR;
    }

    fims_ui_success("Baseline authentication verified");

    fims_file_list_t current;
    if (fims_file_list_init(&current) != FIMS_OK) {
        fims_file_list_free(&baseline);
        return FIMS_EXIT_ERROR;
    }

    fims_ui_info("Scanning monitored files...");

    bool missing_or_unreadable_root = false;
    for (size_t i = 0; i < baseline.root_dir_count; i++) {
        struct stat root_st;
        if (stat(baseline.root_dirs[i], &root_st) != 0) {
            missing_or_unreadable_root = true;
            fims_ui_warn("Monitored root directory missing or inaccessible: %s", baseline.root_dirs[i]);
            if (cfg->log_file[0]) {
                fims_log_message(cfg->log_file, SEV_HIGH,
                                 "Monitored root directory missing or inaccessible: %s",
                                 baseline.root_dirs[i]);
            }
        } else if (!S_ISDIR(root_st.st_mode) || access(baseline.root_dirs[i], R_OK | X_OK) != 0) {
            missing_or_unreadable_root = true;
            fims_ui_warn("Monitored root directory not readable or not a directory: %s", baseline.root_dirs[i]);
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
            fims_ui_error("Filesystem scan failed (status %d).", (int)st);
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

    /* Run integrity check (alerts will be formatted via fims_ui_alert_card below) */
    st = fims_check_integrity(&baseline, &current, cfg, false, &report);
    if (st != FIMS_OK) {
        fims_ui_error("Integrity check failed (status %d).", (int)st);
        fims_report_free(&report);
        fims_file_list_free(&current);
        fims_file_list_free(&baseline);
        return FIMS_EXIT_ERROR;
    }

    fims_report_save(cfg->report_file, &report);
    fims_status_save(cfg->state_file, cfg, NULL, baseline.count, report.count);

    /* Display structured scan metrics card */
    fims_ui_section("Scan Summary Metrics");
    fims_ui_field("Files scanned", "%zu", current.count);
    fims_ui_field("Unchanged", "%zu", report.unchanged_files);
    fims_ui_field("Modified", "%zu", report.modified_count);
    fims_ui_field("Added", "%zu", report.added_count);
    fims_ui_field("Deleted", "%zu", report.deleted_count);
    if (report.renamed_count > 0) {
        fims_ui_field("Renamed", "%zu", report.renamed_count);
    }
    if (report.perm_changed_count > 0) {
        fims_ui_field("Perms Changed", "%zu", report.perm_changed_count);
    }
    if (report.meta_changed_count > 0) {
        fims_ui_field("Metadata Changed", "%zu", report.meta_changed_count);
    }

    /* Display alerts if detected */
    if (report.count > 0 || missing_or_unreadable_root) {
        fims_ui_warn("Integrity violations detected!");
        for (size_t i = 0; i < report.count; i++) {
            fims_ui_alert_card(&report.alerts[i]);
            fims_log_alert(cfg->log_file, &report.alerts[i], false);
        }
        printf("[SUMMARY] Integrity scan complete: %zu change(s) detected across %zu scanned files.\n",
               report.count, current.count);
        fims_ui_status_box("VIOLATIONS DETECTED", false, "Unapproved changes require security investigation");
        fims_ui_info("Report saved successfully: %s", cfg->report_file);
    } else {
        fims_ui_success("Integrity scan complete (%zu files verified, 0 changes detected).", current.count);
        printf("[OK] Integrity scan complete (%zu files verified, 0 changes detected).\n", current.count);
        fims_ui_status_box("PROTECTED", true, "Filesystem matches trusted baseline");
    }

    int exit_code = (report.count > 0 || missing_or_unreadable_root) ? FIMS_EXIT_CHANGES : FIMS_EXIT_OK;

    fims_report_free(&report);
    fims_file_list_free(&current);
    fims_file_list_free(&baseline);
    return exit_code;
}

static int cmd_baseline(int argc, char **argv, fims_config_t *cfg) {
    if (argc < 3) {
        fims_ui_error("Usage: fims baseline <show|update>");
        return 1;
    }

    if (strcmp(argv[2], "show") == 0) {
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
                printf("Usage: %s baseline show [--no-color]\n\nDisplay trusted baseline records and metadata.\n", argv[0]);
                return 0;
            } else if (strcmp(argv[i], "--no-color") == 0 || strcmp(argv[i], "--color") == 0) {
                continue;
            }
            fims_ui_error("Unrecognized option '%s' for baseline show.", argv[i]);
            return 1;
        }

        fims_ui_header("TRUSTED BASELINE");
        fims_status_t st = fims_baseline_show(cfg->baseline_file);
        if (st == FIMS_ERR_NOT_FOUND) {
            fims_ui_error("Baseline file '%s' does not exist.", cfg->baseline_file);
            return 1;
        }
        if (st == FIMS_ERR_CORRUPT) {
            fims_ui_critical("Baseline file '%s' is corrupted or tampered!", cfg->baseline_file);
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
            } else if (strcmp(argv[i], "--no-color") == 0 || strcmp(argv[i], "--color") == 0) {
                continue;
            } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
                printf("Usage: %s baseline update [--yes --allow-unattended] [--no-color]\n\n"
                       "Execute an integrity scan, display diff summary, and update baseline after confirmation.\n",
                       argv[0]);
                return 0;
            } else {
                fims_ui_error("Unrecognized option '%s' for baseline update.", argv[i]);
                return 1;
            }
        }

        if (has_yes && !has_unattended) {
            fims_ui_error("The '--yes' flag is ONLY permitted if accompanied by '--allow-unattended'.");
            return 1;
        }

        fims_ui_header("BASELINE UPDATE");
        bool confirmed = (has_yes && has_unattended);

        fims_file_list_t existing;
        fims_status_t st = fims_baseline_load(cfg->baseline_file, &existing);
        if (st == FIMS_ERR_NOT_FOUND) {
            fims_ui_error("Baseline file '%s' does not exist. Run 'fims init <dir>' first.",
                          cfg->baseline_file);
            return 1;
        }
        if (st == FIMS_ERR_CORRUPT) {
            fims_ui_critical("Baseline file '%s' failed cryptographic integrity validation!",
                             cfg->baseline_file);
            return 2;
        }
        if (st != FIMS_OK) {
            fims_ui_error("Cannot update baseline: existing baseline invalid or inaccessible (%d).",
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
            fims_ui_warn("Filesystem scan encountered errors (%d); proceeding with available records.", (int)st);
        }

        fims_report_t report;
        if (fims_report_init(&report) != FIMS_OK) {
            fims_file_list_free(&current);
            fims_file_list_free(&existing);
            return 1;
        }

        fims_ui_info("Executing integrity check to identify baseline changes...");
        fims_check_integrity(&existing, &current, cfg, false, &report);

        printf("\n================================================================================\n");
        printf(" Baseline Update Diff Summary\n");
        printf("================================================================================\n");
        fims_ui_field("Total Scanned Files", "%zu", current.count);
        fims_ui_field("Detected Changes", "%zu", report.count);
        fims_ui_field("  - Files Added", "%zu", report.added_count);
        fims_ui_field("  - Files Modified", "%zu", report.modified_count);
        fims_ui_field("  - Files Deleted", "%zu", report.deleted_count);
        fims_ui_field("  - Perms Changed", "%zu", report.perm_changed_count);
        printf("================================================================================\n\n");

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
            fims_ui_success("Trusted baseline updated (%zu files recorded).", current.count);
            printf("[OK] Trusted baseline updated (%zu files recorded).\n", current.count);
            fims_logger_init(cfg->log_file);
            if (cfg->log_file[0]) {
                fims_log_message(cfg->log_file, SEV_INFO,
                                 "Trusted baseline manually updated after user confirmation (%zu files, %zu accepted alerts)",
                                 current.count, accepted_alerts);
            }
            fims_status_save(cfg->state_file, cfg, NULL, current.count, 0);
            fims_ui_status_box("BASELINE UPDATED", true, "All accepted changes incorporated");
        } else {
            fims_ui_error("Failed to save updated baseline (status %d).", (int)st);
        }

        fims_report_free(&report);
        fims_file_list_free(&current);
        fims_file_list_free(&existing);
        return (st == FIMS_OK) ? 0 : 1;
    }

    fims_ui_error("Unknown baseline subcommand '%s'. Use 'show' or 'update'.", argv[2]);
    return 1;
}

static int cmd_monitor(int argc, char **argv, fims_config_t *cfg) {
    uint32_t max_seconds = 0;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s monitor [--duration <sec>] [--no-color]\n\n"
                   "Start real-time Linux inotify monitoring.\n"
                   "  --duration <sec>  Stop monitoring after <sec> seconds (positive integer)\n"
                   "  --no-color        Disable ANSI color output\n",
                   argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--no-color") == 0 || strcmp(argv[i], "--color") == 0) {
            continue;
        } else if (strcmp(argv[i], "--duration") == 0 || strcmp(argv[i], "-d") == 0) {
            if (i + 1 >= argc) {
                fims_ui_error("Missing value for %s. Expected positive integer in seconds.", argv[i]);
                fims_cli_print_help(argv[0]);
                return 1;
            }
            i++;
            char *endptr = NULL;
            errno = 0;
            long v = strtol(argv[i], &endptr, 10);
            if (errno != 0 || !endptr || *endptr != '\0' || endptr == argv[i] || v <= 0) {
                fims_ui_error("Invalid duration value '%s'. Expected positive integer in seconds.", argv[i]);
                fims_cli_print_help(argv[0]);
                return 1;
            }
            max_seconds = (uint32_t)v;
        } else {
            fims_ui_error("Unrecognized option '%s' for monitor command.", argv[i]);
            fims_cli_print_help(argv[0]);
            return 1;
        }
    }

    fims_logger_init(cfg->log_file);
    fims_ui_header("REAL-TIME INOTIFY MONITOR");
    fims_ui_info("Starting FIMS real-time inotify monitor (Press Ctrl+C to stop)...");
    printf("[INFO] Starting FIMS real-time inotify monitor (Press Ctrl+C to stop)...\n");
    fflush(stdout);

    fims_monitor_reset_stop();
    fims_status_t st = fims_monitor_run(cfg, max_seconds);
    if (st != FIMS_OK) {
        fims_ui_error("Real-time monitor exited with error code %d.", (int)st);
        return 1;
    }
    fims_ui_success("FIMS real-time monitor stopped cleanly.");
    printf("[INFO] FIMS real-time monitor stopped cleanly.\n");
    return 0;
}

static int cmd_status(int argc, char **argv, fims_config_t *cfg) {
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s status [--no-color]\n\nDisplay monitoring status and statistics.\n", argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--no-color") == 0 || strcmp(argv[i], "--color") == 0) {
            continue;
        }
        fims_ui_error("Unrecognized option '%s' for status command.", argv[i]);
        return 1;
    }
    fims_ui_header("SYSTEM STATUS");
    return (fims_status_display(cfg) == FIMS_OK) ? 0 : 1;
}

static int cmd_report(int argc, char **argv, fims_config_t *cfg) {
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s report [--no-color]\n\nDisplay detected integrity changes from last scan.\n", argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--no-color") == 0 || strcmp(argv[i], "--color") == 0) {
            continue;
        }
        fims_ui_error("Unrecognized option '%s' for report command.", argv[i]);
        return 1;
    }
    fims_ui_header("INTEGRITY REPORT");
    fims_status_t st = fims_report_display(cfg->report_file);
    if (st == FIMS_ERR_NOT_FOUND) {
        fims_ui_info("No scan report found at '%s'. Run 'fims scan' first.", cfg->report_file);
        printf("[INFO] No scan report found at '%s'. Run 'fims scan' first.\n", cfg->report_file);
        return 0;
    }
    return (st == FIMS_OK) ? 0 : 1;
}

static int cmd_config(int argc, char **argv, const fims_config_t *cfg) {
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s config [--no-color]\n\nDisplay active FIMS configuration and baseline state.\n", argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--no-color") == 0 || strcmp(argv[i], "--color") == 0) {
            continue;
        }
        fims_ui_error("Unrecognized option '%s' for config command.", argv[i]);
        return 1;
    }

    fims_ui_header("CONFIGURATION & ARCHITECTURE");
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
    /* Initialize UI and detect global --no-color / --color flags */
    bool force_no_color = false;
    bool force_color = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--no-color") == 0) {
            force_no_color = true;
        } else if (strcmp(argv[i], "--color") == 0) {
            force_color = true;
        }
    }
    fims_ui_init(force_no_color, force_color);

    if (argc < 2) {
        if (isatty(STDIN_FILENO) && isatty(STDOUT_FILENO)) {
            fims_config_t cfg;
            fims_config_init_defaults(&cfg);
            fims_config_load(&cfg, NULL);
            return fims_tui_main(&cfg);
        }
        fims_cli_print_help(argc > 0 ? argv[0] : "fims");
        return 1;
    }

    /* Locate first non-color argument as the command */
    int cmd_idx = 1;
    while (cmd_idx < argc && (strcmp(argv[cmd_idx], "--no-color") == 0 || strcmp(argv[cmd_idx], "--color") == 0)) {
        cmd_idx++;
    }

    if (cmd_idx >= argc) {
        fims_cli_print_help(argv[0]);
        return 1;
    }

    const char *cmd = argv[cmd_idx];

    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0) {
        fims_cli_print_help(argv[0]);
        return 0;
    }

    if (strcmp(cmd, "banner") == 0) {
        fims_ui_banner();
        return 0;
    }

    if (strcmp(cmd, "--version") == 0 || strcmp(cmd, "-v") == 0 || strcmp(cmd, "version") == 0) {
        const char *c_cyan = fims_ui_color(UI_COLOR_BOLD_CYAN);
        const char *c_wht  = fims_ui_color(UI_COLOR_BOLD_WHITE);
        const char *c_dim  = fims_ui_color(UI_COLOR_DIM);
        const char *c_rst  = fims_ui_color(UI_COLOR_RESET);
        printf("%sFIMS%s version %s%s%s (ISO C11, OpenSSL EVP, Linux inotify)\n",
               c_cyan, c_rst, c_wht, FIMS_VERSION, c_rst);
        printf("%sLinux Security & File Integrity Monitoring System%s\n", c_dim, c_rst);
        return 0;
    }

    fims_config_t cfg;
    fims_config_init_defaults(&cfg);
    fims_config_load(&cfg, NULL);

    if (strcmp(cmd, "tui") == 0 || strcmp(cmd, "--tui") == 0) {
        if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
            fims_ui_error("TUI requires an interactive terminal (TTY)");
            return 1;
        }
        return fims_tui_main(&cfg);
    }

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

    fims_ui_error("Unrecognized command '%s'. Run 'fims help' for usage.", cmd);
    fims_cli_print_help(argv[0]);
    return 1;
}
