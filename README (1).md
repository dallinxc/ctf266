/*
 * tinyparse.c — WALKTHROUGH target
 *
 * A deliberately fragile "name parser" for CAPEC-28 Fuzzing practice.
 * Reads a line from stdin, copies it into a fixed 32-byte buffer using
 * strcpy (no length check), and prints a greeting.
 *
 * Any input longer than ~32 bytes will smash the stack and crash.
 *
 * Compile:   gcc -o tinyparse tinyparse.c -fno-stack-protector -z execstack
 * Run:       echo "Dallin" | ./tinyparse
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void greet(const char *raw) {
    char name[32];
    strcpy(name, raw);            /* ← the bug */
    printf("Hello, %s!\n", name);
}

int main(void) {
    char input[512];
    if (!fgets(input, sizeof(input), stdin)) {
        fprintf(stderr, "no input\n");
        return 1;
    }

    /* trim trailing newline */
    size_t n = strlen(input);
    if (n && input[n-1] == '\n') input[n-1] = '\0';

    greet(input);
    return 0;
}
