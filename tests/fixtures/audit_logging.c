#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Execute an audited command with controlled stderr; parent never uses LD_AUDIT. */
int main(int argc, char **argv)
{
    if (argc < 4)
        return 2;
    int capture = strcmp(argv[1], "capture") == 0;
    int closed = strcmp(argv[1], "closed") == 0;
    int blocking = strcmp(argv[1], "blocking") == 0;
    int quiet = strcmp(argv[1], "quiet") == 0;
    int pipefd[2];
    if (pipe(pipefd) != 0)
        return 2;
    int original_flags = fcntl(pipefd[1], F_GETFL);
    if (original_flags < 0 || fcntl(pipefd[1], F_SETFL, original_flags | O_NONBLOCK) < 0)
        return 2;
    if (!capture && !closed && !quiet)
    {
        char buf[4096];
        memset(buf, 'x', sizeof(buf));
        while (write(pipefd[1], buf, sizeof(buf)) > 0) {}
        if (errno != EAGAIN)
            return 2;
    }
    if (blocking && fcntl(pipefd[1], F_SETFL, original_flags) != 0)
        return 2;
    if (quiet && fcntl(pipefd[0], F_SETFL, O_NONBLOCK) != 0)
        return 2;
    if (closed)
        close(pipefd[0]);
    pid_t child = fork();
    if (child < 0)
        return 2;
    if (child == 0)
    {
        if (!closed)
            close(pipefd[0]);
        if (dup2(pipefd[1], STDERR_FILENO) < 0)
            _exit(2);
        close(pipefd[1]);
        if (setenv("LD_AUDIT", argv[2], 1) != 0)
            _exit(2);
        execvp(argv[3], &argv[3]);
        _exit(2);
    }
    if (capture)
    {
        close(pipefd[1]);
        char buf[4096];
        ssize_t n;
        while ((n = read(pipefd[0], buf, sizeof(buf))) > 0)
        {
            ssize_t sent = 0;
            while (sent < n)
            {
                ssize_t result = write(STDOUT_FILENO, buf + sent, (size_t)(n - sent));
                if (result <= 0)
                    return 2;
                sent += result;
            }
        }
        close(pipefd[0]);
    }
    int status = 0;
    for (int i = 0; i < 300; i++)
    {
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child)
        {
            /* Diagnostic code must not modify the application's open-file flags. */
            int flags = capture ? -1 : fcntl(pipefd[1], F_GETFL);
            if (!capture && flags != (blocking ? original_flags : original_flags | O_NONBLOCK))
                return 4;
            if (quiet)
            {
                char byte;
                if (read(pipefd[0], &byte, 1) != -1 || errno != EAGAIN)
                    return 5;
            }
            return WIFEXITED(status) ? WEXITSTATUS(status) : 3;
        }
        if (result < 0)
            return 2;
        struct timespec delay = {0, 10000000};
        nanosleep(&delay, NULL);
    }
    kill(child, SIGKILL);
    waitpid(child, &status, 0);
    return 124;
}
