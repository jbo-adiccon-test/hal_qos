//
// Created by limberg on 02.05.2022.
//

#include "timehandler.h"

void sig_handler_time(int signum) {
    pid_t pid = getpid();
    pid_t ppid = getppid();

    printf("Signal: %u", signum);

    if (signum == SIGINT) {
        kill(pid, SIGINT);
    } else if (signum == SIGCHLD) {
        kill(ppid, SIGUSR1);
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

struct tm get_act_time() {
    time_t raw;
    time(&raw);
    tTime.act_t = *localtime(&raw);
    //mktime(&tTime.act_t);
    //printf("%s", asctime(&tTime.act_t));
    tTime.act_t.tm_mon = tTime.act_t.tm_mon + 1;
    tTime.act_t.tm_year = tTime.act_t.tm_year + 1900;
    return tTime.act_t;
}

u_int8_t struct_greater() {
    get_act_time();
    if (valid(tTime.act_t) == 0 && valid(tTime.tar_t) == 0) {
        time_t act = mktime(&tTime.act_t);
        time_t tar = mktime(&tTime.tar_t);
        if (difftime(act, tar) < 0)
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
    struct tm ret = get_act_time();
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

int diff() {
    get_act_time();

    time_t act = mktime(&tTime.act_t);
    time_t tar = (time_t) mktime(&tTime.tar_t);

    long ret = tar - act;

    return (int) ret;
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

void duration_check() {
    printf("Timechecker activated SIGINT to deactivate");
    tTime.check = true;

    daemon(0,0);

    //if (fork() == 0) {
        signal(SIGINT, sig_handler_time);
        signal(SIGCHLD, sig_handler_time);

        while (1) {
            bool obsulate = false;
            uint id;
            get_act_time();

            perror("time_daemon");

            DIR *dp;
            struct dirent *ep;

            if (!(dp = opendir(CLASS_PERSITENT_FILENAME)))
                printf("NO Dir");

            while ((ep = readdir(dp)) != NULL) { // Get all entries in Dir
                obsulate = false;
                FILE *fp = NULL;
                char *fname = malloc(512);
                snprintf(fname, 512, "%s/%s", CLASS_PERSITENT_FILENAME, ep->d_name);

                if (fname[20] == '.')
                    continue;

                if (!(fp = fopen(fname, "r") )) { // Open file
                    perror("File Unopenable");
                }

                char *line = NULL;
                size_t len;

                while (getline(&line, &len, fp) != -1) {
                    printf("%s\n", line);

                    if (obsulate == true) {
                        //fclose(fp);
                        qos_removeOneClass(line, CLASS_FW_FILENAME);
                        qos_removeOneClass(line, fname);
                        //line[20] = 'D';
                        //system(line);
                    }

                    if (obsulate == false) {
                        char *tmpstr = malloc(256);
                        snprintf(tmpstr, 256, "%s",line);
                        char *token = strtok(tmpstr, " ");

                        if (strcmp(token, "end:") == 0) {
                            token = strtok(NULL, " "); // Isolate time string
                            tTime.tar_t = strtotm(token); // change str to tm struct
                            if (valid(tTime.tar_t) != 2) {
                                if (struct_greater() != 0) { // check for oldness
                                    //char *s_line = malloc(256);
                                    //snprintf(s_line, 256, "%s %s", line, token);
                                    qos_removeOneClass(line, fname);
                                } else
                                    continue;
                            }
                        } else if (strcmp(token, "id:") == 0) {
                            if (struct_greater() != 0) {
                                token = strtok(NULL, " ");
                                id = (uint) atoi(token);
                                obsulate = true;
                                //char *s_line = malloc(256);
                                //snprintf(s_line, 256, "%s %s", line, token);
                                qos_removeOneClass(line, fname);
                            }
                        }
                        free(tmpstr);
                    }
                }
                fclose(fp);
            }
            closedir(dp);
            if (obsulate)
                reset_dmcli(id);

            sleep(15);
        }
            //qos_removeAllClasses();
    //} else {
          //}
}
