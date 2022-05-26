//
// Created by limberg on 02.05.2022.
//

#include "timehandler.h"

void sig_handler_time(int signum) {
    pid_t pid = getpid();
    pid_t ppid = getppid();

    printf("Signal: %u", signum);

    if (signum == SIGUSR1) {
        kill(ppid, SIGUSR1);
    } else if (signum == SIGUSR2) {
        kill(pid, SIGUSR2);
    } else if (signum == SIGKILL) {
        kill(pid, SIGKILL);
        kill(ppid, SIGKILL);
        return;
    }
}

char *get_str_time(struct tm time) {
    char *t_str;
    if (valid(time) == 1) {
        t_str = malloc(9 * sizeof(char));
        snprintf(t_str, 8, "%i:%i:%i", time.tm_hour, time.tm_min, time.tm_sec);
        return t_str;
    } else if (valid(time) == 0) {
        t_str = malloc(20 * sizeof(char));
        snprintf(t_str, 20, "%i:%i:%i-%i.%i.%i", time.tm_hour, time.tm_min, time.tm_sec, time.tm_mday, time.tm_mon,
                 time.tm_year);
        return t_str;
    } else {
        return "";
    }
}

struct tm get_act_time(struct tm *act) {
    time_t raw;
    time(&raw);
    *act = *localtime(&raw);
    //mktime(&tTime.act_t);
    //printf("%s", asctime(&tTime.act_t));
    (*act).tm_mon = (*act).tm_mon + 1;
    (*act).tm_year = (*act).tm_year + 1900;
    return *act;
}

u_int8_t struct_greater() {
    get_act_time(&tTime.act_t);
    if (valid(tTime.act_t) == 0 && valid(tTime.tar_t) == 0) {
        if (diff() < 0)
            return 0;
        else
            return 1;
    }
    return 2;
}

u_int8_t valid(struct tm tm) {
    if (
            (tm.tm_sec >= 0 && tm.tm_sec < 60) ||
            (tm.tm_min >= 0 && tm.tm_min < 60) ||
            (tm.tm_hour >= 0 && tm.tm_hour < 24)
            ) {
        if (
                tm.tm_mday != 0 &&
                tm.tm_mon != 0 &&
                tm.tm_year != 0
                ) {
            return 0;
        } else {
            return 1;
        }
    } else {
        return 2;
    }
}

struct tm strtotm(const char *str) {
    char *ptr;
    struct tm ret;
    get_act_time(&ret);
    if (strlen(str) >= 8) {
        int hr = (int) strtol(&str[0], &ptr, 10);
        int min = (int) strtol(&str[3], &ptr, 10);
        int sec = (int) strtol(&str[6], &ptr, 10);

        ret.tm_hour = hr;
        ret.tm_min = min;
        ret.tm_sec = sec;

        if (strlen(str) == 19) {
            int day = (int) strtol(&str[9], &ptr, 10);
            int mon = (int) strtol(&str[12], &ptr, 10);
            int year = (int) strtol(&str[15], &ptr, 10);

            ret.tm_mday = day;
            ret.tm_mon = mon;
            ret.tm_year = year;

        }

        return ret;
    }
    return ret;
}

long diff() {
    get_act_time(&tTime.act_t);

    if (tTime.tar_t.tm_mday > tTime.act_t.tm_mday)
        return 1;
    if(tTime.tar_t.tm_mon > tTime.act_t.tm_mon)
        return 1;
    if (tTime.tar_t.tm_year > tTime.act_t.tm_year)
        return 1;

    time_t act = (time_t) mktime(&tTime.act_t);
    time_t tar = (time_t) mktime(&tTime.tar_t);

    long ret = tar - act;

    return ret;
}

void reset_dmcli(uint id) {
    char* str = malloc(512);
    snprintf(str, 512, "%s%i%s", "dmcli eRT setv Device.QoS.Classification.", id, ".Enable bool false");
    system(str);
    strcpy(str, "");
    snprintf(str, 512, "%s%i%s", "dmcli eRT setv Device.QoS.Classification.", id, ".ChainName string \"\"");
    system(str);
    strcpy(str, "");
    snprintf(str, 512, "%s%i%s", "dmcli eRT setv Device.QoS.Classification.", id, ".IfaceIn string \"\"");
    system(str);
    strcpy(str, "");
    snprintf(str, 512, "%s%i%s", "dmcli eRT setv Device.QoS.Classification.", id, ".IfaceOut string \"\"");
    system(str);
    strcpy(str, "");
    snprintf(str, 512, "%s%i%s", "dmcli eRT setv Device.QoS.Classification.", id, ".Duration string \"\"");
    system(str);
    strcpy(str, "");
    snprintf(str, 512, "%s%i%s", "dmcli eRT setv Device.QoS.Classification.", id, ".SourceMACAddress string \"\"");
    system(str);
    strcpy(str, "");
    snprintf(str, 512, "%s%i%s", "dmcli eRT setv Device.QoS.Classification.", id, ".DSCPMark int 0");
    system(str);
    free(str);
}

int time_handler (char *fname) {
    FILE *fp = file_open(fname, "r");

    if (fp == NULL)
        return -2;

    char *s_line = NULL;
    size_t len;

    getline(&s_line, &len, fp);

    char *line = malloc(strlen(s_line)+1);
    snprintf(line, strlen(s_line), "%s", s_line);

    char *token = strtok(line, " ");
    if (strcmp(token, "end:") == 0) {
        token = strtok(NULL, " "); // Isolate time string
        tTime.tar_t = strtotm(del_n(token)); // change str to tm struct
        if (valid(tTime.tar_t) != 2) {
            if (struct_greater() == 0) { // check for oldness
                file_close(fp);
                file_del(fname, s_line);
                revert_iptables(fname);
                char *content = file_read_all(fname);
                file_remove(fname);
                file_del_text(CLASS_FW_FILENAME,content,"\n");

                free(line);
                free(s_line);

                return EXIT_SUCCESS;
            } else {

                free(line);
                free(s_line);
                file_close(fp);

                return EXIT_FAILURE;
            }
        }
    } else
        file_remove(fname);
    return EXIT_FAILURE;
}

void duration_check() {
    if (fork() == 0) {
    signal(SIGUSR1, sig_handler_time);
    signal(SIGUSR2, sig_handler_time);
    signal(SIGKILL, sig_handler_time);

    while (1) {
        uint id = 0;
        get_act_time(&tTime.act_t);
        DIR *dp;
        struct dirent *ep;

        if (!(dp = opendir(CLASS_PERSITENT_FILENAME)))
            log_loc("FAIL: DurationChecker No class DIR in /usr/ccsp/qos/class/");

        while ((ep = readdir(dp)) != NULL) { // Get all entries in Dir
            char *fname = malloc(512);
            snprintf(fname, 512, "%s/%s", CLASS_PERSITENT_FILENAME, ep->d_name);

            if (fname[20] == '.')
                continue;

            if (time_handler(fname) == EXIT_SUCCESS)
                reset_dmcli(id);
        }

        closedir(dp);

        sleep(15);
    }
    } else {
        tTime.check = true;
        log_loc("SUCCESS: DurationChecker Time check active");
    }
}
