//
// Created by limberg on 02.05.2022.
//

#include "timehandler.h"

int main() {
    const char *string = "22:08:12-05.10.2022";

    tTime.tar_t = strtotm(string);

    get_act_time();
    struct_greater();

    printf("%s", get_str_time(tTime.tar_t));
}
