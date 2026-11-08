#ifndef FIMS_CLI_H
#define FIMS_CLI_H

#include "../include/fims.h"

/**
 * Print CLI usage and command reference (`fims help`).
 */
void fims_cli_print_help(const char *prog_name);

/**
 * Parse command-line arguments and dispatch the requested FIMS command.
 * Returns process exit code (0 on success, non-zero on error).
 */
int fims_cli_dispatch(int argc, char **argv);

#endif /* FIMS_CLI_H */
