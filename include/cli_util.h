#ifndef MC_CLI_UTIL_H
#define MC_CLI_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* Outcome of reading a password line. */
enum {
    CLI_PASSWORD_OK = 0,
    CLI_PASSWORD_ERROR = 1,     /* end of input, or the read failed      */
    CLI_PASSWORD_TOO_LONG = 2   /* line exceeded the password buffer     */
};

/* Reads one line from `in` as a password: strips a trailing CR/LF pair,
 * and refuses rather than truncates a line too long for the buffer.
 * Returns a newly malloc'd, NUL-terminated string (caller must free and
 * should wipe), or NULL. *status receives one of the CLI_PASSWORD_*
 * values above and may be NULL.
 *
 * This is the part of password reading that makes a decision, split out
 * from the terminal handling so it can be tested against an ordinary
 * FILE * without a console. */
char *cli_read_password_line(FILE *in, int *status);

/* Prompts on stderr and reads a password from the terminal with echo
 * disabled where possible. Returns a newly malloc'd, NUL-terminated
 * string (caller must free), or NULL on error. Falls back to visible
 * input if terminal echo control isn't available (e.g. piped stdin). */
char *cli_read_password(const char *prompt);

/* Reads an entire file into a newly malloc'd buffer. Returns NULL on
 * failure. Caller must free the buffer. */
uint8_t *cli_read_file(const char *path, size_t *out_len);

/* Writes `len` bytes from `data` to `path`, truncating/creating the
 * file. Returns 0 on success, -1 on failure. */
int cli_write_file(const char *path, const uint8_t *data, size_t len);

#endif /* MC_CLI_UTIL_H */
