#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include "tokenizer.h"

/* Convenience macro to silence compiler warnings about unused function
 * parameters. */
#define unused __attribute__((unused))

/* Whether the shell is connected to an actual terminal or not. */
bool shell_is_interactive;

/* File descriptor for the shell input */
int shell_terminal;

/* Terminal mode settings for the shell */
struct termios shell_tmodes;

/* Process group id for the shell */
pid_t shell_pgid;

int cmd_exit(struct tokens *tokens);
int cmd_help(struct tokens *tokens);
int cmd_cd(struct tokens *tokens);
int cmd_pwd(struct tokens *tokens);

/* Built-in command functions take token array (see parse.h) and return int */
typedef int cmd_fun_t(struct tokens *tokens);

/* Built-in command struct and lookup table */
typedef struct fun_desc {
    cmd_fun_t *fun;
    char *cmd;
    char *doc;
} fun_desc_t;

fun_desc_t cmd_table[] = {
    {cmd_help, "?", "show this help menu"},
    {cmd_exit, "exit", "exit the command shell"},
    {cmd_cd, "cd", "change the current working directory"},
    {cmd_pwd, "pwd", "print the current working directory"},
};

/* Prints a helpful description for the given command */
int cmd_help(unused struct tokens *tokens) {
    for (unsigned int i = 0; i < sizeof(cmd_table) / sizeof(fun_desc_t); i++) {
        printf("%s - %s\n", cmd_table[i].cmd, cmd_table[i].doc);
    }
    return 1;
}

/* Exits this shell */
int cmd_exit(unused struct tokens *tokens) { exit(0); }

int cmd_cd(struct tokens *tokens) {
    if (tokens_get_length(tokens) != 2) {
        printf("cd only takes 1 arg\n");
        return 1;
    }
    if (chdir(tokens_get_token(tokens, 1)) != 0) {
        perror("chdir() error");
        return 1;
    }
    return 0;
}

int cmd_pwd(unused struct tokens *tokens) {
    char path[PATH_MAX];
    if (getcwd(path, sizeof(path)) != NULL) {
        printf("%s\n", path);
    } else {
        perror("getcwd() error");
        return 1;
    }
    return 0;
}

/* Looks up the built-in command, if it exists. */
int lookup(char *cmd) {
    if (cmd != NULL) {
        for (int i = 0; i < sizeof(cmd_table) / sizeof(fun_desc_t); i++) {
            if (strcmp(cmd_table[i].cmd, cmd) == 0) { return i; }
        }
    }
    return -1;
}

const char *resolve_cmd(const char *cmd) {
    const char *PATH = getenv("PATH");
    const char *cmd_copy = strdup(cmd);

    if (PATH == NULL) { return cmd_copy; }

    const int len = strlen(PATH);
    int start = 0;
    for (int i = 0; i < len + 1; i++) {
        if (i == len || PATH[i] == ':') {
            const int dir_len = i - start;
            char *total_path = malloc(dir_len + len + 2);
            strncpy(total_path, PATH + start, dir_len);
            strcpy(total_path + dir_len + 1, cmd);
            total_path[dir_len] = '/';
            int test = open(total_path, O_RDONLY);
            if (test != -1) {
                free((char *)cmd_copy);
                close(test);
                return total_path;
            }
            free(total_path);
            start = i + 1;
        }
    }
    return cmd_copy;
}

/* Intialization procedures for this shell */
void init_shell() {
    /* Our shell is connected to standard input. */
    shell_terminal = STDIN_FILENO;

    /* Check if we are running interactively */
    shell_is_interactive = isatty(shell_terminal);

    if (shell_is_interactive) {
        /* If the shell is not currently in the foreground, we must pause the
         * shell until it becomes a foreground process. We use SIGTTIN to pause
         * the shell. When the shell gets moved to the foreground, we'll receive
         * a SIGCONT. */
        while (tcgetpgrp(shell_terminal) != (shell_pgid = getpgrp())) {
            kill(-shell_pgid, SIGTTIN);
        }

        /* Saves the shell's process id */
        shell_pgid = getpid();

        /* Take control of the terminal */
        tcsetpgrp(shell_terminal, shell_pgid);

        /* Save the current termios to a variable, so it can be restored later.
         */
        tcgetattr(shell_terminal, &shell_tmodes);
    }
}

int main(unused int argc, unused char *argv[]) {
    init_shell();

    static char line[4096];
    int line_num = 0;

    /* Only print shell prompts when standard input is not a tty */
    if (shell_is_interactive) { fprintf(stdout, "%d: ", line_num); }

    signal(SIGTTOU, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    while (fgets(line, 4096, stdin)) {
        /* Split our line into words. */
        struct tokens *tokens = tokenize(line);

        /* Find which built-in function to run. */
        int fundex = lookup(tokens_get_token(tokens, 0));

        if (fundex >= 0) {
            cmd_table[fundex].fun(tokens);
        } else {
            const char *prog = resolve_cmd(tokens_get_token(tokens, 0));

            pid_t kid;
            if ((kid = fork()) < 0) {
                perror("fork");
            } else if (kid == 0) {
                if (setpgrp() != 0) {
                    perror("setpgrp");
                    exit(1);
                }
                if (tcsetpgrp(fileno(stdin), getpgrp()) != 0) {
                    perror("tcsetpgrp");
                    exit(1);
                }
                signal(SIGTTOU, SIG_DFL);
                signal(SIGTTIN, SIG_DFL);

                size_t len = tokens_get_length(tokens);
                char **args = malloc((len + 1) * sizeof(char *));

                size_t pos = 0, args_at = 0;
                char *fin = NULL, *fout = NULL;
                while (pos < len) {
                    char *tok = tokens_get_token(tokens, pos);
                    if (strcmp(tok, "<") == 0) {
                        if (pos == len - 1) {
                            fprintf(stderr, "Syntax error: Expected filename after <");
                            exit(1);
                        }
                        fin = tokens_get_token(tokens, pos + 1);
                        pos++;
                    } else if (strcmp(tok, ">") == 0) {
                        if (pos == len - 1) {
                            fprintf(stderr, "Syntax error: Expected filename after >");
                            exit(1);
                        }
                        fout = tokens_get_token(tokens, pos + 1);
                        pos++;
                    } else {
                        args[args_at++] = tok;
                    }
                    pos++;
                }
                args[args_at] = NULL;

                if (fin != NULL) {
                    int in_fd = open(fin, O_RDONLY);
                    if (in_fd < 0) { perror("open"); }
                    dup2(in_fd, fileno(stdin));
                }
                if (fout != NULL) {
                    int out_fd = open(fout, O_WRONLY | O_CREAT, 0666);
                    if (out_fd < 0) { perror("open"); }
                    dup2(out_fd, fileno(stdout));
                }

                if (execv(prog, args) != 0) {
                    perror("execv");
                    exit(1);
                }
            } else {
                waitpid(kid, NULL, 0);
                tcsetpgrp(0, getpgrp());
            }

            free((char *)prog);
        }

        if (shell_is_interactive) {
            /* Only print shell prompts when standard input is not a tty. */
            fprintf(stdout, "%d: ", ++line_num);
        }

        /* Clean up memory. */
        tokens_destroy(tokens);
    }
}
