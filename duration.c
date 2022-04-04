//
// Created by limberg on 28.03.2022.
//

#include "classification.h"
#include "duration.h"

void dur_daemon(const char *fin) {
    runtime t;
    if (!time(&t.cur)){

    }


    if (1==1){
        pid_t pid;

        pid = fork();
        if (pid < 0)
            exit(EXIT_FAILURE);

        if (setsid() < 0)
            exit(EXIT_FAILURE);

        signal(SIGCHLD, SIG_IGN);
        signal(SIGHUP, SIG_IGN);

        pid = fork();
        if (pid < 0)
            exit(EXIT_FAILURE);

        umask(0);
        openlog("TimerDaemon for queue kill", LOG_PID, LOG_DAEMON);
    }
}