//
// Created by limberg on 28.03.2022.
//

#ifndef TESTS_DURATION_H
#define TESTS_DURATION_H

#include <time.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>

struct interval {
    time_t *cur, *end;
    clock_t *beg, *fin;
};
typedef struct interval runtime;

void dur_daemon(const char *fin);

#endif //TESTS_DURATION_H
