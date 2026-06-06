/*
 * bufferdemo.c — EDUCATIONAL buffer-overflow demonstration (defensive lab).
 *
 * This program is run as a short-lived SUBPROCESS by the web application. Running
 * it as a subprocess is itself a safety measure: if the vulnerable code crashes,
 * only the child process dies — the web server keeps running and simply reports
 * what happened. That isolation mirrors how you would sandbox risky native code.
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

/* --- VULNERABLE (integrity): overflow corrupts an ADJACENT variable. ---
 * Using a struct fixes the memory layout so the demo is deterministic: members
 * are laid out in declaration order at increasing addresses, so writing past
 * 'buf' writes into 'authorized'. This shows that an overflow crosses a boundary
 * and corrupts neighbouring data — the defining property of memory corruption
 * (and what distinguishes it from mere heap exhaustion). */
static int run_flag_unsafe(const char *input) {
    struct { char buf[16]; volatile int authorized; } frame;
    frame.authorized = 0;                         /* user is NOT authorized    */
    strcpy(frame.buf, input);                     /* overflow past 16 bytes... */
    if (frame.authorized != 0) {
        printf("INTEGRITY VIOLATION: adjacent 'authorized' was corrupted to 0x%x "
               "by the overflow.\n", frame.authorized);
        printf("A %zu-byte input overran a 16-byte buffer and changed neighbouring "
               "memory.\n", strlen(input));
        return 3;
    }
    printf("ok (flag-unsafe): authorized=%d (no corruption for this input).\n",
           frame.authorized);
    return 0;
}

/* --- SAFE (integrity): bounded copy keeps the neighbour intact. --- */
static int run_flag_safe(const char *input) {
    struct { char buf[16]; volatile int authorized; } frame;
    frame.authorized = 0;
    if (strlen(input) >= sizeof(frame.buf)) {
        fprintf(stderr, "rejected: input too long for 16-byte buffer. No overflow.\n");
        return 2;
    }
    snprintf(frame.buf, sizeof(frame.buf), "%s", input);
    printf("ok (flag-safe): authorized=%d (neighbour intact).\n", frame.authorized);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <unsafe|safe|flag-unsafe|flag-safe> <input>\n", argv[0]);
        return 1;
    }
    const char *mode = argv[1];
    const char *input = argv[2];

    if (strcmp(mode, "unsafe") == 0)       return run_unsafe(input);
    if (strcmp(mode, "safe") == 0)         return run_safe(input);
    if (strcmp(mode, "flag-unsafe") == 0)  return run_flag_unsafe(input);
    if (strcmp(mode, "flag-safe") == 0)    return run_flag_safe(input);

    fprintf(stderr, "unknown mode: %s\n", mode);
    return 1;
}
