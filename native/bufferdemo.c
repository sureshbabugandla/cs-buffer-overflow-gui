/*
 * bufferdemo.c — EDUCATIONAL buffer-overflow demonstration (defensive lab).
 *
 * This program is run as a short-lived SUBPROCESS by the web application. Running
 * it as a subprocess is itself a safety measure: if the vulnerable code crashes,
 * only the child process dies — the web server keeps running and simply reports
 * what happened. That isolation mirrors how risky native code would be sandboxed.
 *
 * It supports four modes (argv[1]) with the user input in argv[2]:
 *   unsafe      - strcpy into a fixed stack buffer (NO bounds check)  -> can crash
 *   safe        - bounded copy + explicit length validation           -> never overflows
 *   flag-unsafe - overflow corrupts an ADJACENT variable (integrity)  -> shows corruption
 *   flag-safe   - same logic, bounded                                  -> stays correct
 *
 * IMPORTANT: This file intentionally contains NO exploit: there is no
 * return-address hijacking, no shellcode, no ASLR/DEP/canary bypass. It only
 * demonstrates (a) that an overflow causes a crash / corruption, and (b) how the
 * safe versions and compiler protections prevent it. That is the full educational
 * scope of the lab.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SMALL_BUF 64

/* --- VULNERABLE: classic unbounded copy into a fixed stack buffer. --- */
static int run_unsafe(const char *input) {
    char buffer[SMALL_BUF];           /* fixed 64-byte buffer on the stack   */
    /* strcpy copies until the NUL terminator with NO regard for buffer size.
       If 'input' is longer than 63 chars, it writes past 'buffer', corrupting
       the stack (saved registers / return address) and typically causing a
       SIGSEGV crash when this function returns. */
    strcpy(buffer, input);            /* <-- the vulnerability               */
    printf("processed (unsafe): %s\n", buffer);
    printf("input length was %zu bytes; buffer holds %d.\n", strlen(input), SMALL_BUF);
    return 0;
}

/* --- SAFE: validate length, then bounded copy. --- */
static int run_safe(const char *input) {
    char buffer[SMALL_BUF];
    if (strlen(input) >= SMALL_BUF) {            /* bounds check (prevention)  */
        fprintf(stderr, "rejected: input too long (%zu >= %d). No overflow.\n",
                strlen(input), SMALL_BUF);
        return 2;                                /* refuse, like HTTP 400      */
    }
    snprintf(buffer, sizeof(buffer), "%s", input); /* bounded copy, always NUL */
    printf("processed (safe): %s\n", buffer);
    return 0;
}

/* --- VULNERABLE (integrity): overflow OVERWRITES an adjacent SECRET. ---
 * A sample secret (e.g. a session token) is stored in a 'secret' field placed
 * immediately after the 16-byte buffer. Overflowing 'buf' spills the attacker's
 * input into 'secret', replacing the real token with the input bytes. This shows
 * vividly that a buffer overflow can corrupt sensitive neighbouring data. */
static int run_flag_unsafe(const char *input) {
    struct { char buf[16]; char secret[32]; } frame;
    /* The sensitive value living right after the buffer. */
    strcpy(frame.secret, "AUTH=Adm1n-9F3A7C2E");
    char before[33];
    memcpy(before, frame.secret, 32); before[32] = '\0';   /* snapshot original */

    unsigned long a_buf = (unsigned long)(void *) frame.buf;
    unsigned long a_sec = (unsigned long)(void *) frame.secret;

    strcpy(frame.buf, input);                 /* overflow may clobber the secret */

    /* Read back the secret SAFELY (bound to 32 bytes so the print can't over-read). */
    char after[33];
    memcpy(after, frame.secret, 32); after[32] = '\0';
    int corrupted = (strcmp(before, after) != 0);

    printf("addr_buf=0x%lx\n", a_buf);
    printf("addr_secret=0x%lx\n", a_sec);
    printf("gap_bytes=%ld\n", (long)(a_sec - a_buf));
    printf("buffer_size=16\n");
    printf("input_len=%zu\n", strlen(input));
    printf("secret_before=%s\n", before);
    printf("secret_after=%s\n", after);
    printf("verdict=%s\n", corrupted ? "CORRUPTED" : "OK");
    return corrupted ? 3 : 0;
}

/* --- SAFE (integrity): bounded copy keeps the adjacent secret intact. --- */
static int run_flag_safe(const char *input) {
    struct { char buf[16]; char secret[32]; } frame;
    strcpy(frame.secret, "AUTH=Adm1n-9F3A7C2E");
    char before[33];
    memcpy(before, frame.secret, 32); before[32] = '\0';

    unsigned long a_buf = (unsigned long)(void *) frame.buf;
    unsigned long a_sec = (unsigned long)(void *) frame.secret;

    /* Bounded copy: snprintf writes at most 15 chars + NUL, so even an oversized
       input is truncated and can never reach 'secret'. */
    snprintf(frame.buf, sizeof(frame.buf), "%s", input);

    char after[33];
    memcpy(after, frame.secret, 32); after[32] = '\0';
    int corrupted = (strcmp(before, after) != 0);

    printf("addr_buf=0x%lx\n", a_buf);
    printf("addr_secret=0x%lx\n", a_sec);
    printf("gap_bytes=%ld\n", (long)(a_sec - a_buf));
    printf("buffer_size=16\n");
    printf("input_len=%zu\n", strlen(input));
    printf("secret_before=%s\n", before);
    printf("secret_after=%s\n", after);
    printf("verdict=%s\n", corrupted ? "CORRUPTED" : "OK");
    return 0;
}

/* --- VULNERABLE (authorization bypass): overflow flips an is_admin gate. ---
 * This shows the SECURITY CONSEQUENCE of memory corruption: an overflow of a
 * local buffer overwrites an adjacent 'is_admin' flag, so the program makes its
 * access-control decision on corrupted data and treats an ordinary request as an
 * administrator. It is the same mechanism as flag-unsafe, framed as a privilege
 * escalation. It contains NO code execution / shellcode / control-flow hijack —
 * it only demonstrates that corrupting a guard variable subverts a check. */
static int run_auth_unsafe(const char *input) {
    struct { char buf[16]; volatile unsigned int is_admin; } frame;
    frame.is_admin = 0u;                          /* request is NOT admin      */
    unsigned long a_buf  = (unsigned long)(void *) frame.buf;
    unsigned long a_flag = (unsigned long)(void *) &frame.is_admin;
    strcpy(frame.buf, input);                     /* overflow can flip is_admin */
    unsigned int after = frame.is_admin;
    printf("addr_buf=0x%lx\n", a_buf);
    printf("addr_authorized=0x%lx\n", a_flag);
    printf("gap_bytes=%ld\n", (long)(a_flag - a_buf));
    printf("buffer_size=16\n");
    printf("input_len=%zu\n", strlen(input));
    printf("authorized_before=0x%08x\n", 0u);
    printf("authorized_after=0x%08x\n", after);
    printf("verdict=%s\n", after != 0u ? "CORRUPTED" : "OK");
    /* The access-control decision is made on the (possibly corrupted) flag. */
    printf("access=%s\n", after != 0u ? "GRANTED" : "DENIED");
    return after != 0u ? 4 : 0;
}

/* --- SAFE (authorization): bounded copy keeps the is_admin gate intact. --- */
static int run_auth_safe(const char *input) {
    struct { char buf[16]; volatile unsigned int is_admin; } frame;
    frame.is_admin = 0u;
    unsigned long a_buf  = (unsigned long)(void *) frame.buf;
    unsigned long a_flag = (unsigned long)(void *) &frame.is_admin;
    snprintf(frame.buf, sizeof(frame.buf), "%s", input);  /* bounded: truncates */
    unsigned int after = frame.is_admin;
    printf("addr_buf=0x%lx\n", a_buf);
    printf("addr_authorized=0x%lx\n", a_flag);
    printf("gap_bytes=%ld\n", (long)(a_flag - a_buf));
    printf("buffer_size=16\n");
    printf("input_len=%zu\n", strlen(input));
    printf("authorized_before=0x%08x\n", 0u);
    printf("authorized_after=0x%08x\n", after);
    printf("verdict=%s\n", after != 0u ? "CORRUPTED" : "OK");
    printf("access=%s\n", after != 0u ? "GRANTED" : "DENIED");
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <unsafe|safe|flag-unsafe|flag-safe|auth-unsafe|auth-safe> <input>\n", argv[0]);
        return 1;
    }
    const char *mode = argv[1];
    const char *input = argv[2];

    if (strcmp(mode, "unsafe") == 0)       return run_unsafe(input);
    if (strcmp(mode, "safe") == 0)         return run_safe(input);
    if (strcmp(mode, "flag-unsafe") == 0)  return run_flag_unsafe(input);
    if (strcmp(mode, "flag-safe") == 0)    return run_flag_safe(input);
    if (strcmp(mode, "auth-unsafe") == 0)  return run_auth_unsafe(input);
    if (strcmp(mode, "auth-safe") == 0)    return run_auth_safe(input);

    fprintf(stderr, "unknown mode: %s\n", mode);
    return 1;
}
