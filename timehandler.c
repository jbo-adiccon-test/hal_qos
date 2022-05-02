//
// Created by limberg on 02.05.2022.
//

#include "timehandler.h"

void sig_handler_time(int sig) {

}

int test_time() {
    struct t_time test;

    test.act_t.tm_sec = 15;
    test.act_t.tm_min = 12;
    test.act_t.tm_hour = 5;
    test.act_t.tm_mday = 23;
    test.act_t.tm_mon = 11;
    test.act_t.tm_year = 2022;
};
