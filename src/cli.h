#ifndef FIMS_CLI_H
#define FIMS_CLI_H

#include "../include/fims.h"

/**
 * Print CLI usage and command reference (`fims help` / `fims --help`).
 */
void fims_cli_print_help(const char *prog_name);

/**
 * Print scan command reference and canonical exit codes (`fims scan --help`).
 */
void fims_cli_print_scan_help(const char *prog_name);

/**
 * Parse command-line arguments and dispatch the requested FIMS command.
 * Returns process exit code (0 on clean/success, 3 on changes, 2 on corrupt baseline, 1 on error).
 */
int fims_cli_dispatch(int argc, char **argv);

#endif /* FIMS_CLI_H */
