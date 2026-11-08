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

void fims_cli_print_help(const char *prog_name) {
    const char *prog = prog_name ? prog_name : "fims";
    printf("================================================================================\n");
    printf(" File Integrity Monitoring System (FIMS) v%s\n", FIMS_VERSION);
    printf("================================================================================\n");
    printf("Usage:\n");
    printf("  %s init <directory> [--force]   Create a trusted SHA-256 baseline for <directory>\n", prog);
    printf("  %s scan                         Perform a complete integrity scan against baseline\n", prog);
    printf("  %s monitor [--duration <sec>]   Start real-time Linux inotify monitoring\n", prog);
    printf("  %s status                       Display monitoring status and statistics\n", prog);
    printf("  %s report                       Display detected integrity changes from last scan\n", prog);
    printf("  %s baseline show                Display trusted baseline records and metadata\n", prog);
    printf("  %s baseline update [--yes]      Update the trusted baseline after confirmation\n", prog);
    printf("  %s config                       Display active FIMS configuration\n", prog);
    printf("  %s help                         Display this usage guide\n", prog);
    printf("================================================================================\n");
}

static int cmd_init(int argc, char **argv, fims_config_t *cfg) {
    if (argc < 3) {
        fprintf(stderr, "[ERROR] Missing target directory. Usage: fims init /path/to/directory\n");
        return 1;
    }

    const char *target_dir = argv[2];
    bool force = false;
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--force") == 0 || strcmp(argv[i], "-f") == 0) {
            force = true;
        }
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

static int cmd_scan(fims_config_t *cfg) {
    fims_file_list_t baseline;
    fims_status_t st = fims_baseline_load(cfg->baseline_file, &baseline);
    if (st == FIMS_ERR_NOT_FOUND) {
        fprintf(stderr, "[ERROR] Baseline file '%s' not found. Run 'fims init <dir>' first.\n",
                cfg->baseline_file);
        return 1;
    }
    if (st == FIMS_ERR_CORRUPT) {
        fprintf(stderr, "[CRITICAL] Baseline file '%s' failed cryptographic integrity validation!\n",
                cfg->baseline_file);
        return 2;
    }
    if (st != FIMS_OK) {
        fprintf(stderr, "[ERROR] Unable to load baseline (status %d).\n", (int)st);
        return 1;
    }

    fims_file_list_t current;
    if (fims_file_list_init(&current) != FIMS_OK) {
        fims_file_list_free(&baseline);
        return 1;
    }

    st = fims_scan_directories((const char (*)[FIMS_MAX_PATH])baseline.root_dirs,
                               baseline.root_dir_count,
                               cfg,
                               &current);
    if (st != FIMS_OK) {
        fprintf(stderr, "[ERROR] Filesystem scan failed (status %d).\n", (int)st);
        fims_file_list_free(&current);
        fims_file_list_free(&baseline);
        return 1;
    }

    fims_report_t report;
    if (fims_report_init(&report) != FIMS_OK) {
        fims_file_list_free(&current);
        fims_file_list_free(&baseline);
        return 1;
    }

    st = fims_check_integrity(&baseline, &current, cfg, true, &report);
    fims_report_save(cfg->report_file, &report);
    fims_status_save(cfg->state_file, cfg, NULL, baseline.count, report.count);

    if (report.count == 0) {
        printf("[OK] Integrity scan complete (%zu files verified, 0 changes detected).\n",
               current.count);
    } else {
        printf("[SUMMARY] Integrity scan complete: %zu change(s) detected across %zu scanned files.\n",
               report.count, current.count);
    }

    fims_report_free(&report);
    fims_file_list_free(&current);
    fims_file_list_free(&baseline);
    return (st == FIMS_OK) ? 0 : 1;
}

static int cmd_baseline(int argc, char **argv, fims_config_t *cfg) {
    if (argc < 3) {
        fprintf(stderr, "[ERROR] Usage: fims baseline <show|update>\n");
        return 1;
    }

    if (strcmp(argv[2], "show") == 0) {
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
        bool confirmed = false;
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--yes") == 0 || strcmp(argv[i], "-y") == 0) {
                confirmed = true;
            }
        }

        fims_file_list_t existing;
        fims_status_t st = fims_baseline_load(cfg->baseline_file, &existing);
        if (st != FIMS_OK) {
            fprintf(stderr, "[ERROR] Cannot update baseline: existing baseline invalid or missing (%d).\n",
                    (int)st);
            return 1;
        }

        if (!confirmed) {
            printf("Are you sure you want to update the trusted baseline at '%s'? [y/N]: ",
                   cfg->baseline_file);
            fflush(stdout);
            char ans[32];
            if (!fgets(ans, sizeof(ans), stdin) || (ans[0] != 'y' && ans[0] != 'Y')) {
                printf("Baseline update cancelled.\n");
                fims_file_list_free(&existing);
                return 0;
            }
        }

        fims_file_list_t updated;
        if (fims_file_list_init(&updated) != FIMS_OK) {
            fims_file_list_free(&existing);
            return 1;
        }

        st = fims_scan_directories((const char (*)[FIMS_MAX_PATH])existing.root_dirs,
                                   existing.root_dir_count,
                                   cfg,
                                   &updated);
        if (st == FIMS_OK) {
            st = fims_baseline_save(cfg->baseline_file, &updated, true);
        }

        if (st == FIMS_OK) {
            printf("[OK] Trusted baseline updated (%zu files recorded).\n", updated.count);
            if (cfg->log_file[0]) {
                fims_log_message(cfg->log_file, SEV_INFO,
                                 "Trusted baseline manually updated after user confirmation (%zu files)",
                                 updated.count);
            }
        } else {
            fprintf(stderr, "[ERROR] Failed to update baseline (status %d).\n", (int)st);
        }

        fims_file_list_free(&updated);
        fims_file_list_free(&existing);
        return (st == FIMS_OK) ? 0 : 1;
    }

    fprintf(stderr, "[ERROR] Unknown baseline subcommand '%s'. Use 'show' or 'update'.\n", argv[2]);
    return 1;
}

static int cmd_monitor(int argc, char **argv, fims_config_t *cfg) {
    uint32_t max_seconds = 0;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--duration") == 0 && i + 1 < argc) {
            long v = strtol(argv[++i], NULL, 10);
            if (v > 0) max_seconds = (uint32_t)v;
        }
    }

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

int fims_cli_dispatch(int argc, char **argv) {
    if (argc < 2) {
        fims_cli_print_help(argc > 0 ? argv[0] : "fims");
        return 1;
    }

    fims_config_t cfg;
    fims_config_init_defaults(&cfg);
    fims_config_load(&cfg, NULL);
    fims_logger_init(cfg.log_file);

    const char *cmd = argv[1];

    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0) {
        fims_cli_print_help(argv[0]);
        return 0;
    }
    if (strcmp(cmd, "init") == 0) {
        return cmd_init(argc, argv, &cfg);
    }
    if (strcmp(cmd, "scan") == 0) {
        return cmd_scan(&cfg);
    }
    if (strcmp(cmd, "monitor") == 0) {
        return cmd_monitor(argc, argv, &cfg);
    }
    if (strcmp(cmd, "status") == 0) {
        return (fims_status_display(&cfg) == FIMS_OK) ? 0 : 1;
    }
    if (strcmp(cmd, "report") == 0) {
        fims_status_t st = fims_report_display(cfg.report_file);
        if (st == FIMS_ERR_NOT_FOUND) {
            printf("[INFO] No scan report found at '%s'. Run 'fims scan' first.\n", cfg.report_file);
            return 0;
        }
        return (st == FIMS_OK) ? 0 : 1;
    }
    if (strcmp(cmd, "baseline") == 0) {
        return cmd_baseline(argc, argv, &cfg);
    }
    if (strcmp(cmd, "config") == 0) {
        fims_config_print(&cfg);
        return 0;
    }

    fprintf(stderr, "[ERROR] Unrecognized command '%s'. Run 'fims help' for usage.\n", cmd);
    return 1;
}
