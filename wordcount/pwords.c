/*
 * Word count application with one thread per input file.
 *
 * You may modify this file in any way you like, and are expected to modify it.
 * Your solution must read each input file from a separate thread. We encourage
 * you to make as few changes as necessary.
 */

/*
 * Copyright (C) 2019 University of California, Berkeley
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

#include <ctype.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "word_count.h"
#include "word_helpers.h"

const int NUM_THREADS = 4;

int file_num;
char** files;

word_count_list_t word_counts;

void* proc_files(void* thread_id) {
    long tid = (long)thread_id;
    FILE* infile = fopen(files[tid], "r");
    if (infile == NULL) {
        pthread_exit((void*) 1);
    }
    count_words(&word_counts, infile);
    fclose(infile);
    pthread_exit(NULL);
}

/*
 * main - handle command line, spawning one thread per file.
 */
int main(int argc, char** argv) {
    init_words(&word_counts);

    if (argc <= 1) {
        count_words(&word_counts, stdin);
    } else {
        file_num = argc - 1;
        files = malloc(file_num * sizeof(*files));
        for (int i = 1; i <= file_num; i++) {
            files[i - 1] = strdup(argv[i]);
        }

        pthread_t* threads = malloc(file_num * sizeof(pthread_t));
        for (long t = 0; t < file_num; t++) {
            int rc = pthread_create(&threads[t], NULL, proc_files, (void*)t);
            if (rc) {
                printf("ERROR; return code from pthread_create() is %d\n", rc);
                exit(-1);
            }
        }

        for (long t = 0; t < file_num; t++) {
            pthread_join(threads[t], NULL);
        }
    }

    // Output final result of all threads' work.
    wordcount_sort(&word_counts, less_count);
    fprint_words(&word_counts, stdout);

    pthread_exit(NULL);
}
