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
#include <stdbool.h>
#include "classification.h"

#define CLASS_PERSITENT_FILENAME "/usr/ccsp/qos/class"
#define CLASS_FW_FILENAME "/tmp/qos_rules.sh"

struct t_time {
    struct tm act_t;
    struct tm tar_t;
    bool check;
} tTime;

void sig_handler_time(int sig);

char *get_str_time(struct tm time);

struct tm get_act_time(struct tm *act);

u_int8_t struct_greater();

u_int8_t valid(struct tm tm);

struct tm strtotm(const char *str);

long diff();

void duration_check();

//u_int8_t clean_Class()

#endif //TESTS_TIMEHANDLER_H
