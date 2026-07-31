#include <errno.h>
#include <signal.h>
#include <stdio.h>
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

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <daemon> [args...]\n", argv[0]);
        return 1;
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
