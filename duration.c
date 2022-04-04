//
// Created by limberg on 28.03.2022.
//

#include "classification.h"
#include "duration.h"

void sig_handler(int signum) {
    pid_t pid;
    printf("Signal: %u", signum);
    if (signum == SIGINT) {
        pid = getpid();
        kill(pid, SIGINT);
        exit(-1);
    }
}

void dur_daemon(const char *fin) {
    runtime t;
    if (!time(&t.cur)){
        perror("TIME fail");
    }

    int nocdir = 0;
    int noclo = 0;

    if (daemon(nocdir,noclo))
        perror("time_daemon");

    signal(SIGINT,sig_handler);

    while (1) {
        time(&t.end);
    }
}