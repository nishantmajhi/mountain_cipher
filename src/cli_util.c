#define _POSIX_C_SOURCE 200809L

#include "cli_util.h"
#include "mountain_cipher.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__unix__) || defined(__APPLE__)
#include <termios.h>
#include <unistd.h>
#define MC_HAVE_TERMIOS 1
#elif defined(_WIN32)
#include <windows.h>
#define MC_HAVE_WIN32_CONSOLE 1
#endif

#define MC_PASSWORD_MAX 1024

char *cli_read_password_line(FILE *in, int *status) {
    int local_status = 0;
    if (!status) status = &local_status;
    *status = CLI_PASSWORD_ERROR;
    if (!in) return NULL;

    char *buf = (char *)malloc(MC_PASSWORD_MAX);
    if (!buf) return NULL;

    if (!fgets(buf, MC_PASSWORD_MAX, in)) {
        mc_secure_wipe(buf, MC_PASSWORD_MAX);
        free(buf);
        return NULL;
    }

    size_t len = strlen(buf);

    /* fgets stops at MC_PASSWORD_MAX-1 bytes and leaves the rest of the
     * line on the stream. Originally that remainder was simply dropped,
     * so a password longer than 1023 characters silently became its own
     * first 1023 characters - a different key than the user typed, with
     * no indication, and the tail left in the input for whatever read
     * next. A line that fills the buffer and does not end in a newline is
     * either over-long or the very last line of the input with no
     * terminator, and only reading one more byte tells them apart. */
    if (len == MC_PASSWORD_MAX - 1 && buf[len - 1] != '\n') {
        int next = fgetc(in);
        /* EOF means the input simply ended here, and a newline means the
         * password was exactly the maximum length - both are fine. Only a
         * third case, an actual further character, means the line was
         * longer than the buffer. */
        if (next != EOF && next != '\n') {
            while (next != EOF && next != '\n') next = fgetc(in);
            mc_secure_wipe(buf, MC_PASSWORD_MAX);
            free(buf);
            *status = CLI_PASSWORD_TOO_LONG;
            return NULL;
        }
    }

    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) {
        buf[--len] = '\0';
    }
    *status = CLI_PASSWORD_OK;
    return buf;
}

char *cli_read_password(const char *prompt) {
    if (prompt) fprintf(stderr, "%s", prompt);

#if defined(MC_HAVE_TERMIOS)
    struct termios old_term, new_term;
    int echo_disabled = 0;
    if (isatty(fileno(stdin)) && tcgetattr(fileno(stdin), &old_term) == 0) {
        new_term = old_term;
        new_term.c_lflag &= (tcflag_t)~ECHO;
        echo_disabled = (tcsetattr(fileno(stdin), TCSAFLUSH, &new_term) == 0);
    }
#elif defined(MC_HAVE_WIN32_CONSOLE)
    /* The original disabled echo only under __unix__ / __APPLE__, so on
     * Windows - which is where this project is developed - the whole
     * block compiled out and the password was typed in plain view. */
    HANDLE console = GetStdHandle(STD_INPUT_HANDLE);
    DWORD old_mode = 0;
    int echo_disabled = 0;
    if (console != INVALID_HANDLE_VALUE && GetConsoleMode(console, &old_mode)) {
        /* GetConsoleMode only succeeds for a real console, so piped or
         * redirected input takes the visible path as before. */
        echo_disabled = SetConsoleMode(console, old_mode & ~(DWORD)ENABLE_ECHO_INPUT) != 0;
    }
#else
    int echo_disabled = 0;
#endif

    int status = CLI_PASSWORD_ERROR;
    char *password = cli_read_password_line(stdin, &status);

#if defined(MC_HAVE_TERMIOS)
    if (echo_disabled) {
        tcsetattr(fileno(stdin), TCSAFLUSH, &old_term);
        fprintf(stderr, "\n");
    }
#elif defined(MC_HAVE_WIN32_CONSOLE)
    if (echo_disabled) {
        SetConsoleMode(console, old_mode);
        fprintf(stderr, "\n");
    }
#endif
    (void)echo_disabled;

    if (!password && status == CLI_PASSWORD_TOO_LONG) {
        fprintf(stderr, "Error: password is longer than %d characters\n",
                MC_PASSWORD_MAX - 1);
    }
    return password;
}

uint8_t *cli_read_file(const char *path, size_t *out_len) {
    if (!path || !out_len) return NULL;
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long size = ftell(f);
    if (size < 0) { fclose(f); return NULL; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }

    uint8_t *buf = (uint8_t *)malloc((size_t)size > 0 ? (size_t)size : 1);
    if (!buf) { fclose(f); return NULL; }

    size_t read_bytes = fread(buf, 1, (size_t)size, f);
    fclose(f);
    if (read_bytes != (size_t)size) { free(buf); return NULL; }

    *out_len = (size_t)size;
    return buf;
}

int cli_write_file(const char *path, const uint8_t *data, size_t len) {
    if (!path || (!data && len > 0)) return -1;
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t written = len > 0 ? fwrite(data, 1, len, f) : 0;
    /* fclose can fail where fwrite did not: buffered bytes are flushed
     * here, so a full disk surfaces at close time and must not be read
     * as success. */
    int closed = fclose(f);
    if (written != len || closed != 0) return -1;
    return 0;
}
