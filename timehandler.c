//
// Created by limberg on 02.05.2022.
//

#include "timehandler.h"

void sig_handler_time(int signum) {

    pid_t pid = getpid();
    printf("Signal: %u", signum);
    if (signum == SIGINT) {
        pid = getpid();
        kill(pid, SIGINT);
    }
}

char *get_str_time(struct tm time) {
    return asctime(&time);
}

struct tm get_act_time() {
    time_t raw;
    time(&raw);
    tTime.act_t = *localtime(&raw);
    return tTime.act_t;
}
