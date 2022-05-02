//
// Created by limberg on 02.05.2022.
//

#ifndef TESTS_TIMEHANDLER_H
#define TESTS_TIMEHANDLER_H

#include <time.h>
#include <syslog.h>
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DIR_NAME "/usr/ccsp"
struct t_time {
    struct tm act_t;
    struct tm tar_t;
    char *file_name;
} tTime;

void sig_handler_time(int sig);

char *get_str_time(struct tm time);

struct tm get_act_time();

#endif //TESTS_TIMEHANDLER_H
