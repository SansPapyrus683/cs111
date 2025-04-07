/*
 * Word count application with one process per input file.
 *
 * You may modify this file in any way you like, and are expected to modify it.
 * Your solution must read each input file from a separate thread. We encourage
 * you to make as few changes as necessary.
 */

/*
 * Copyright © 2019 University of California, Berkeley
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#define _GNU_SOURCE

#include <ctype.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include "word_count.h"
#include "word_helpers.h"

/*
 * Read stream of counts and accumulate globally.
 */
void merge_counts(word_count_list_t* wclist, FILE* count_stream) {
    char* word;
    int count;
    int rv;
    while ((rv = fscanf(count_stream, "%8d\t%ms\n", &count, &word)) == 2) {
        add_word_with_count(wclist, word, count);
    }
    if ((rv == EOF) && (feof(count_stream) == 0)) {
        perror("could not read counts");
    } else if (rv != EOF) {
        fprintf(stderr, "read ill-formed count (matched %d)\n", rv);
    }
}

/*
 * main - handle command line, spawning one process per file.
 */
int main(int argc, char* argv[]) {
    /* Create the empty data structure. */
    word_count_list_t word_counts;
    init_words(&word_counts);

    if (argc <= 1) {
        /* Process stdin in a single process. */
        count_words(&word_counts, stdin);
    } else {
        pid_t* pids = malloc((argc - 1) * sizeof(pid_t));
        int (*pipes)[2] = malloc((argc - 1) * 2 * sizeof(int));
        for (int i = 1; i < argc; i++) {
            int* fd = pipes[i - 1];
            if (pipe(fd) != 0) { perror("pipe"); }

            int new_size = 1024 * 1024;
            if (fcntl(fd[0], F_SETPIPE_SZ, new_size) == -1) {
                perror("fcntl");
                return 1;
            }

            if ((pids[i - 1] = fork()) < 0) {
                perror("fork");
                return 1;
            } else if (pids[i - 1] == 0) {
                close(fd[0]);

                FILE* read_from = fopen(argv[i], "r");
                if (read_from == NULL) {
                    perror("fopen");
                    return 1;
                }
                count_words(&word_counts, read_from);
                fclose(read_from);

                FILE* write_to = fdopen(fd[1], "w");
                fprint_words(&word_counts, write_to);
                fclose(write_to);

                return 0;
            } else {
                close(fd[1]);
            }
        }

        int left = argc - 1;
        while (left > 0) {
            pid_t done = wait(NULL);
            for (int i = 0; i < argc - 1; i++) {
                if (done == pids[i]) {
                    FILE* read_from = fdopen(pipes[i][0], "r");
                    merge_counts(&word_counts, read_from);
                }
            }

            left--;
        }
    }

    /* Output final result of all process' work. */
    wordcount_sort(&word_counts, less_count);
    fprint_words(&word_counts, stdout);
}
