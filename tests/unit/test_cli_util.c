/* ===========================================================================
 * test_cli_util.c - tests for the command-line helpers: password line
 * parsing, and reading and writing whole files.
 *
 * None of this was covered before. The password path in particular had two
 * defects that only a test which feeds it a stream could see: a password
 * longer than the buffer was silently truncated to its own first 1023
 * characters, and the remainder was left on the stream for whatever read
 * next.
 * ===========================================================================
 */

#include "test_framework.h"
#include "cli_util.h"
#include "mountain_cipher.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Builds a FILE* over `text` without needing a temp file, so these tests
 * do not depend on a writable directory. tmpfile() is used rather than
 * fmemopen(), which is POSIX-only and absent on Windows. */
static FILE *stream_of(const char *text, size_t len) {
    FILE *f = tmpfile();
    if (!f) return NULL;
    if (len > 0) fwrite(text, 1, len, f);
    rewind(f);
    return f;
}

static void test_password_line_trimming(void) {
    fprintf(stderr, "test_password_line_trimming:\n");

    struct { const char *input; const char *expected; const char *what; } cases[] = {
        { "hunter2\n",        "hunter2",     "a trailing newline is stripped" },
        { "hunter2\r\n",      "hunter2",     "a trailing CRLF is stripped" },
        { "hunter2",          "hunter2",     "a final line with no terminator is accepted" },
        { "\n",               "",            "an empty line yields an empty password" },
        { "with spaces \n",   "with spaces ", "internal and trailing spaces are kept" },
        { "p\xc3\xa4ssw\xc3\xb6rd\n", "p\xc3\xa4ssw\xc3\xb6rd", "non-ASCII bytes pass through" },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        FILE *f = stream_of(cases[i].input, strlen(cases[i].input));
        MC_CHECK(f != NULL, "can open a stream for the password test");
        if (!f) continue;
        int status = -1;
        char *pw = cli_read_password_line(f, &status);
        MC_CHECK(status == CLI_PASSWORD_OK, cases[i].what);
        MC_CHECK(pw != NULL && strcmp(pw, cases[i].expected) == 0, cases[i].what);
        free(pw);
        fclose(f);
    }
}

static void test_password_line_rejects_over_long_input(void) {
    fprintf(stderr, "test_password_line_rejects_over_long_input:\n");

    /* 3000 characters, then a newline, then a second line. The original
     * code returned the first 1023 characters as if they were the whole
     * password - so a user who typed a long passphrase got a key derived
     * from a prefix of it, and "tail\n" was left on stdin. */
    size_t long_len = 3000;
    char *input = (char *)malloc(long_len + 16);
    memset(input, 'x', long_len);
    memcpy(input + long_len, "\ntail\n", 7);

    FILE *f = stream_of(input, long_len + 6);
    MC_CHECK(f != NULL, "can open a stream for the over-long password test");
    if (f) {
        int status = -1;
        char *pw = cli_read_password_line(f, &status);
        MC_CHECK(pw == NULL, "an over-long password is refused, not returned");
        MC_CHECK(status == CLI_PASSWORD_TOO_LONG, "the refusal says the password was too long");

        /* The rest of the over-long line must have been consumed, so the
         * next read sees the following line and not the tail of this one. */
        char next[32] = {0};
        char *got = fgets(next, sizeof(next), f);
        MC_CHECK(got != NULL && strcmp(next, "tail\n") == 0,
                  "the remainder of the over-long line is drained from the stream");
        free(pw);
        fclose(f);
    }
    free(input);

    /* A password of exactly the maximum length is still accepted. */
    size_t max_len = 1023;
    char *exact = (char *)malloc(max_len + 2);
    memset(exact, 'y', max_len);
    exact[max_len] = '\n';
    FILE *g = stream_of(exact, max_len + 1);
    if (g) {
        int status = -1;
        char *pw = cli_read_password_line(g, &status);
        MC_CHECK(status == CLI_PASSWORD_OK && pw != NULL && strlen(pw) == max_len,
                  "a password of exactly the maximum length is accepted");
        free(pw);
        fclose(g);
    }
    free(exact);
}

static void test_password_line_handles_end_of_input(void) {
    fprintf(stderr, "test_password_line_handles_end_of_input:\n");

    FILE *f = stream_of("", 0);
    MC_CHECK(f != NULL, "can open an empty stream");
    if (f) {
        int status = -1;
        char *pw = cli_read_password_line(f, &status);
        MC_CHECK(pw == NULL, "reading a password at end of input returns NULL");
        MC_CHECK(status == CLI_PASSWORD_ERROR, "end of input is reported as an error");
        fclose(f);
    }

    int status = -1;
    MC_CHECK(cli_read_password_line(NULL, &status) == NULL, "a null stream is refused");
    /* The status pointer is optional. */
    MC_CHECK(cli_read_password_line(NULL, NULL) == NULL, "a null status pointer is allowed");
}

static void test_file_round_trip(void) {
    fprintf(stderr, "test_file_round_trip:\n");

    /* tmpnam is deprecated and mkstemp is POSIX-only, so build a name in
     * the working directory, which the test runner already writes to. */
    const char *path = "mc_cli_util_test.tmp";
    const uint8_t payload[] = { 0x00, 0x01, 0xFF, 0x7F, 0x80, '\n', '\r', 0x00, 'z' };

    MC_CHECK(cli_write_file(path, payload, sizeof(payload)) == 0, "writing a file succeeds");

    size_t len = 0;
    uint8_t *read_back = cli_read_file(path, &len);
    MC_CHECK(read_back != NULL, "reading the file back succeeds");
    MC_CHECK(len == sizeof(payload), "the length round-trips");
    /* Embedded NULs and CR/LF must survive: the file is opened in binary
     * mode, and on Windows a text-mode read would eat the CR. */
    MC_CHECK(read_back != NULL && memcmp(read_back, payload, sizeof(payload)) == 0,
              "every byte round-trips, including NUL and CRLF");
    free(read_back);

    /* Zero-length files are a real case here: encrypting an empty file is
     * supported, and its hash is taken from a zero-length read. */
    MC_CHECK(cli_write_file(path, payload, 0) == 0, "writing a zero-length file succeeds");
    size_t zero_len = 123;
    uint8_t *empty = cli_read_file(path, &zero_len);
    MC_CHECK(empty != NULL, "reading a zero-length file returns a buffer, not NULL");
    MC_CHECK(zero_len == 0, "a zero-length file reads as zero bytes");
    free(empty);

    remove(path);
}

static void test_file_errors(void) {
    fprintf(stderr, "test_file_errors:\n");

    size_t len = 99;
    MC_CHECK(cli_read_file("mc_definitely_not_here.tmp", &len) == NULL,
              "reading a missing file returns NULL");
    MC_CHECK(cli_read_file(NULL, &len) == NULL, "a null path is refused");
    MC_CHECK(cli_read_file("mc_cli_util_test.tmp", NULL) == NULL,
              "a null length pointer is refused");

    const uint8_t byte = 'x';
    MC_CHECK(cli_write_file(NULL, &byte, 1) != 0, "writing to a null path fails");
    MC_CHECK(cli_write_file("mc_cli_util_test.tmp", NULL, 1) != 0,
              "writing a null buffer with a nonzero length fails");
    remove("mc_cli_util_test.tmp");

    /* A directory is not a writable file; this must be an error rather
     * than a crash or a silent success. */
    MC_CHECK(cli_write_file(".", &byte, 1) != 0, "writing over a directory fails");
}

static void test_secure_wipe(void) {
    fprintf(stderr, "test_secure_wipe:\n");

    unsigned char buf[64];
    memset(buf, 0xAB, sizeof(buf));
    mc_secure_wipe(buf, sizeof(buf));
    int all_zero = 1;
    for (size_t i = 0; i < sizeof(buf); i++) if (buf[i] != 0) all_zero = 0;
    MC_CHECK(all_zero, "the whole buffer is zeroed");

    /* Only the requested prefix is touched. */
    memset(buf, 0xAB, sizeof(buf));
    mc_secure_wipe(buf, 8);
    MC_CHECK(buf[7] == 0 && buf[8] == 0xAB, "exactly `len` bytes are wiped");

    mc_secure_wipe(NULL, 16);   /* must not crash */
    mc_secure_wipe(buf, 0);     /* must not crash */
    MC_CHECK(buf[8] == 0xAB, "a zero-length wipe changes nothing");
}

int main(void) {
    test_password_line_trimming();
    test_password_line_rejects_over_long_input();
    test_password_line_handles_end_of_input();
    test_file_round_trip();
    test_file_errors();
    test_secure_wipe();
    MC_TEST_EXIT();
}
