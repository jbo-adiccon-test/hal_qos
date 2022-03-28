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

struct interval {
    time_t *start, *end;
    clock_t *beg, *fin;
};



#endif //TESTS_DURATION_H
