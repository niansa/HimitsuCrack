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

int attempt_extraction(pid_t pid) {
    char maps_path[64], mem_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

    FILE *maps_file = fopen(maps_path, "r");
    int mem_fd = open(mem_path, O_RDONLY);

    if (!maps_file || mem_fd < 0) {
        if (maps_file) fclose(maps_file);
        if (mem_fd >= 0) close(mem_fd);
        return -1;
    }

    char line[512];
    int found = 0;

    while (fgets(line, sizeof(line), maps_file)) {
        unsigned long start, end, inode = 0;
        char perms[5] = {0};
        char path[256] = "";

        int parsed = sscanf(line, "%lx-%lx %4s %*x %*s %lu %255s",
                            &start, &end, perms, &inode, path);

        if (parsed < 4 || perms[0] != 'r') continue;

        if (inode != 0 && strstr(path, "memfd:") == NULL && strstr(path, "(deleted)") == NULL)
            continue;

        size_t size = end - start;
        if (size > 1024 * 1024 * 256) continue;

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
                size_t offset = (char *)match - buffer;
                size_t last_len = 0;
                int stable_count = 0;

                printf("[+] Signature match (\"%s\") in dynamic region 0x%lx\n", matched_sig, start);
                printf("[*] Unpacking detected. Waiting for memory to stabilize...\n");

                while (stable_count < 5) {
                    usleep(2000);

                    ssize_t fresh_read = pread(mem_fd, buffer, size, start);
                    if (fresh_read <= 0) break;

                    char *script_start = buffer + offset;
                    size_t max_len = fresh_read - offset;
                    size_t current_len = 0;

                    while (current_len < max_len && script_start[current_len] != '\0')
                        current_len++;

                    if (current_len != last_len) {
                        stable_count = 0;
                        last_len = current_len;
                    } else if (current_len > 0) {
                        stable_count++;
                    }
                }

                char *final_script_start = buffer + offset;
                size_t final_len = last_len;

                char dump_filename[128];
                snprintf(dump_filename, sizeof(dump_filename), "extracted_%d.sh", pid);

                FILE *dump_file = fopen(dump_filename, "wb");
                if (dump_file) {
                    fwrite(final_script_start, 1, final_len, dump_file);
                    fclose(dump_file);
                    printf("    -> Extracted %zu bytes to %s\n", final_len, dump_filename);
                    found = 1;
                } else {
                    perror("[-] Failed to write dump file");
                }
            }
        }
        free(buffer);
        if (found) break;
    }

    close(mem_fd);
    fclose(maps_file);
    return found;
}

long long current_time_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
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
        execvp(argv[1], &argv[1]);
        perror("[-] Exec failed");
        exit(1);
    } else {
        printf("[*] Spawned child process PID: %d\n", pid);
        printf("[*] Polling memory for signatures...\n");

        long long start_ms = current_time_ms();
        long long timeout_ms = 2000;
        struct timespec sleep_step = {0, 1000000L};
        int extracted = 0;

        while (current_time_ms() - start_ms < timeout_ms) {
            int status;
            if (waitpid(pid, &status, WNOHANG) == pid) {
                printf("[!] Target process exited before payload was found.\n");
                break;
            }

            int result = attempt_extraction(pid);
            if (result == 1) {
                extracted = 1;
                break;
            } else if (result == -1) {
                break;
            }

            nanosleep(&sleep_step, NULL);
        }

        if (extracted) 
            printf("[*] Extraction successful. Terminating target PID %d...\n", pid);
        else 
            printf("[-] Timeout or process exit reached. Terminating target PID %d...\n", pid);

        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        printf("[*] Done.\n");
    }

    return 0;
}
