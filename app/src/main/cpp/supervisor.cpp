#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t terminating = 0;

static void handle_signal(int) { terminating = 1; }

static long elapsed_ms(const timespec& before, const timespec& after) {
    return (after.tv_sec - before.tv_sec) * 1000L +
           (after.tv_nsec - before.tv_nsec) / 1000000L;
}

static void pause_ms(long milliseconds) {
    const timespec delay = {milliseconds / 1000, (milliseconds % 1000) * 1000000L};
    nanosleep(&delay, nullptr);
}

static void stop_owned_group(pid_t child) {
    kill(-child, SIGTERM);
    for (int attempts = 0; attempts < 30; ++attempts) {
        const pid_t waited = waitpid(child, nullptr, WNOHANG);
        if (waited == child || (waited < 0 && errno == ECHILD)) return;
        pause_ms(100);
    }
    kill(child, SIGKILL);
    waitpid(child, nullptr, 0);
}

static void close_descriptors_from(int first_descriptor) {
    long limit = sysconf(_SC_OPEN_MAX);
    if (limit < 0 || limit > 65536) limit = 65536;
    for (int descriptor = first_descriptor; descriptor < limit; ++descriptor) close(descriptor);
}

static void close_inherited_descriptors() {
    close_descriptors_from(0);
    const int null_descriptor = open("/dev/null", O_RDWR);
    if (null_descriptor < 0) _exit(127);
    if (null_descriptor != STDIN_FILENO && dup2(null_descriptor, STDIN_FILENO) < 0) _exit(127);
    if (null_descriptor != STDOUT_FILENO && dup2(null_descriptor, STDOUT_FILENO) < 0) _exit(127);
    if (null_descriptor != STDERR_FILENO && dup2(null_descriptor, STDERR_FILENO) < 0) _exit(127);
    if (null_descriptor > STDERR_FILENO) close(null_descriptor);
}

static int exec_with_closed_descriptors(
        const char* stdout_path, const char* stderr_path, char* const child_argv[]) {
    const int null_descriptor = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (null_descriptor < 0) return 1;
    const int stdout_descriptor =
            open(stdout_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (stdout_descriptor < 0) return 1;
    const int stderr_descriptor =
            open(stderr_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (stderr_descriptor < 0) return 1;
    if (dup2(null_descriptor, STDIN_FILENO) < 0 ||
        dup2(stdout_descriptor, STDOUT_FILENO) < 0 ||
        dup2(stderr_descriptor, STDERR_FILENO) < 0) {
        return 1;
    }
    close_descriptors_from(3);
    execv(child_argv[0], child_argv);
    return 127;
}

static int detach_and_exec(char* const child_argv[]) {
    const pid_t session_child = fork();
    if (session_child < 0) return 1;
    if (session_child == 0) {
        if (setsid() < 0) _exit(127);
        const pid_t detached_child = fork();
        if (detached_child < 0) _exit(127);
        if (detached_child > 0) _exit(0);
        if (chdir("/") < 0) _exit(127);
        if (setenv("RKA_INTERNAL_CHILD_LOOP", "1", 1) < 0) _exit(127);
        close_inherited_descriptors();
        execv(child_argv[0], child_argv);
        _exit(127);
    }

    int status = 0;
    if (waitpid(session_child, &status, 0) != session_child) return 1;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 1;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s [--detach|--exec-closed] <daemon> [args...]\n", argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "--detach") == 0) {
        if (argc < 3) return 1;
        return detach_and_exec(&argv[2]);
    }
    if (strcmp(argv[1], "--exec-closed") == 0) {
        if (argc < 5) return 1;
        return exec_with_closed_descriptors(argv[2], argv[3], &argv[4]);
    }

    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);
    long backoff_ms = 500;
    int crashes = 0;

    while (!terminating) {
        timespec started;
        clock_gettime(CLOCK_MONOTONIC, &started);
        const pid_t child = fork();
        if (child < 0) {
            pause_ms(backoff_ms);
            backoff_ms = backoff_ms < 30000 ? backoff_ms * 2 : 30000;
            continue;
        }
        if (child == 0) {
            setpgid(0, 0);
            prctl(PR_SET_PDEATHSIG, SIGKILL);
            setpriority(PRIO_PROCESS, 0, 10);
            execv(argv[1], &argv[1]);
            _exit(127);
        }

        setpgid(child, child);
        int status = 0;
        while (waitpid(child, &status, WNOHANG) == 0) {
            if (terminating) {
                stop_owned_group(child);
                return 0;
            }
            pause_ms(100);
        }
        if (terminating) return 0;

        timespec finished;
        clock_gettime(CLOCK_MONOTONIC, &finished);
        if (elapsed_ms(started, finished) >= 30000) {
            crashes = 0;
            backoff_ms = 500;
            continue;
        }
        if (++crashes > 3) return 2;
        pause_ms(backoff_ms);
        backoff_ms = backoff_ms < 30000 ? backoff_ms * 2 : 30000;
    }
    return 0;
}
