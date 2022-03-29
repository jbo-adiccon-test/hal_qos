//
// Created by limberg on 28.03.2022.
//

#include "classification.h"
#include "duration.h"

void dur_daemon(struct qos_class *queue) {
    if (queue->duration){
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