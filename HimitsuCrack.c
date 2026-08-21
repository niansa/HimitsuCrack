#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>

static const char *SIGNATURES[] = {
    "#!/bin/bash",
    "#!/bin/sh",
    "#!/usr/bin/env sh",
    "#!/usr/bin/env bash",
    "#! /bin/bash",
    "#! /bin/sh",
    "#! /usr/bin/env",
    "if [",
    "if\n[",
    "then\n",
    "echo \"",
    "echo '"
};

#define NUM_SIGS (sizeof(SIGNATURES) / sizeof(SIGNATURES[0]))

// Wait for unpacking phase, monitoring for early exit
static int wait_or_check_child(pid_t pid, int timeout_ms) {
    struct timespec step = {0, 5 * 1000000L}; // 5ms steps
    int elapsed = 0;

    while (elapsed < timeout_ms) {
        int status;
        // WNOHANG returns 0 if child is still running
        if (waitpid(pid, &status, WNOHANG) == pid) {
            printf("[!] Child process %d exited prematurely.\n", pid);
            return -1; 
        }
        nanosleep(&step, NULL);
        elapsed += 5;
    }
    return 0;
}

void extract_and_dump_script(pid_t pid) {
    char maps_path[64], mem_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

    FILE *maps_file = fopen(maps_path, "r");
    int mem_fd = open(mem_path, O_RDONLY);
    
    if (!maps_file || mem_fd < 0) {
        perror("[-] Failed to open /proc files (try running with sudo)");
        if (maps_file) fclose(maps_file);
        if (mem_fd >= 0) close(mem_fd);
        return;
    }

    char line[256];
    int extracted_count = 0;

    while (fgets(line, sizeof(line), maps_file)) {
        unsigned long start, end;
        char perms[5];

        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3) continue;
        if (perms[0] != 'r') continue; // Readable regions only

        size_t size = end - start;
        if (size > 1024 * 1024 * 256) continue; // Skip mappings > 256MB

        char *buffer = malloc(size);
        if (!buffer) continue;

        ssize_t bytes_read = pread(mem_fd, buffer, size, start);
        if (bytes_read > 0) {
            void *match = NULL;
            const char *matched_sig = NULL;

            for (size_t i = 0; i < NUM_SIGS; i++) {
                match = memmem(buffer, bytes_read, SIGNATURES[i], strlen(SIGNATURES[i]));
                if (match) {
                    matched_sig = SIGNATURES[i];
                    break;
                }
            }

            if (match) {
                // Calculate script length: stop at first null byte (\0)
                char *script_start = (char *)match;
                size_t script_len = 0;
                size_t max_len = bytes_read - (script_start - buffer);
                
                while (script_len < max_len && script_start[script_len] != '\0') {
                    script_len++;
                }

                printf("[+] Signature match (\"%s\") in region 0x%lx\n", matched_sig, start);

                char dump_filename[128];
                snprintf(dump_filename, sizeof(dump_filename), "extracted_%d.sh", pid);

                FILE *dump_file = fopen(dump_filename, "wb");
                if (dump_file) {
                    fwrite(script_start, 1, script_len, dump_file);
                    fclose(dump_file);
                    printf("    -> Cleanly extracted %zu bytes to %s\n", script_len, dump_filename);
                    extracted_count++;
                } else {
                    perror("[-] Failed to write dump file");
                }
            }
        }
        free(buffer);
    }

    if (extracted_count == 0) {
        printf("[-] No target signatures identified in process memory.\n");
    }

    close(mem_fd);
    fclose(maps_file);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <path_to_binary> [args...]\n", argv[0]);
        return 1;
    }

    pid_t pid = fork();

    if (pid < 0) {
        perror("[-] Fork failed");
        return 1;
    }

    if (pid == 0) {
        // Child Process
        execvp(argv[1], &argv[1]);
        perror("[-] Exec failed");
        exit(1);
    } else {
        // Parent Process
        printf("[*] Spawned child process PID: %d\n", pid);
        printf("[*] Waiting up to 10 ms for unpacking phase...\n");

        if (wait_or_check_child(pid, 10) == 0) {
            printf("[*] Sending SIGSTOP to pause execution...\n");
            kill(pid, SIGSTOP);
            
            // Wait for child to enter stopped state
            int status;
            waitpid(pid, &status, WUNTRACED);
            if (WIFSTOPPED(status)) {
                printf("[*] Process paused. Scanning memory...\n");
                extract_and_dump_script(pid);
            } else {
                fprintf(stderr, "[-] Target did not stop properly.\n");
            }
        }

        printf("[*] Terminating target process PID %d...\n", pid);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0); // Clean up zombie
        printf("[*] Done.\n");
    }

    return 0;
}
