//
// Created by limberg on 02.05.2022.
//

#include "timehandler.h"

/**
 * A signal handler registrated in modul intern forks
 * @param signum
 */
void sig_handler_time(int signum) {
    struct shm_data *procom;
    int shmid = shmget(0x1234, 1024, 0666 | IPC_CREAT);
    procom = (struct shm_data *) shmat(shmid, (void *) 0, 0);

    printf("Signal: %u", signum);

    if (signum == SIGUSR1) {
        log_loc("INFO: kill ppid");
        kill(procom->child, SIGKILL);
    } else if (signum == SIGUSR2) {
        log_loc("INFO: kill pid");
        kill(procom->parent, SIGKILL);
    }

    shmdt(procom);
}

/**
 * Returns a string that shows the time
 * @param time
 * @return
 */
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

/**
 * A function to get the actual time and store it in tTime struct
 * @param act
 * @return
 */
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

/**
 * A function to check time when classification should be deleted in relation to actual time
 * @return
 */
u_int8_t struct_greater() {
    tTime.act_t = get_act_time(&tTime.act_t);

    if (valid(tTime.act_t) == 0 && valid(tTime.tar_t) == 0) {
        if (tTime.tar_t.tm_year > tTime.act_t.tm_year)
            return 1;
        if (tTime.tar_t.tm_mon > tTime.act_t.tm_mon)
            return 1;
        if (tTime.tar_t.tm_mday > tTime.act_t.tm_mday)
            return 1;
        if (tTime.tar_t.tm_hour > tTime.act_t.tm_hour)
            return 1;
        if (tTime.tar_t.tm_min > tTime.act_t.tm_min)
            return 1;
        if (tTime.tar_t.tm_sec > tTime.act_t.tm_sec)
            return 1;
        //return 0;
    } else {
        return 2;
    }

    log_loc("INFO: StructGreater Time run down");
    return 0;
}

/**
 * Checks for validation of substring that is going to be integrated in tTime
 * @param tm
 * @return
 */
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

/**
 * Translate the string out of a file into a tm format
 * @param str
 * @return
 */
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

/**
 * Neutralize the dmcli entries of classification with id ...
 * @param id
 */
void reset_dmcli(uint id) {
    log_loc("INFO dmcliReset:");
    char *str = malloc(512);
    snprintf(str, 512, "%s%i%s", "dmcli eRT setv Device.QoS.Classification.", id, ".ChainName string \"\"");
    exec_run(str);
    strcpy(str, "");
    snprintf(str, 512, "%s%i%s", "dmcli eRT setv Device.QoS.Classification.", id, ".IfaceIn string \"\"");
    exec_run(str);
    strcpy(str, "");
    snprintf(str, 512, "%s%i%s", "dmcli eRT setv Device.QoS.Classification.", id, ".IfaceOut string \"\"");
    exec_run(str);
    strcpy(str, "");
    snprintf(str, 512, "%s%i%s", "dmcli eRT setv Device.QoS.Classification.", id, ".Duration string \"\"");
    exec_run(str);
    strcpy(str, "");
    snprintf(str, 512, "%s%i%s", "dmcli eRT setv Device.QoS.Classification.", id, ".SourceMACAddress string \"\"");
    exec_run(str);
    strcpy(str, "");
    snprintf(str, 512, "%s%i%s", "dmcli eRT setv Device.QoS.Classification.", id, ".DSCPMark int 0");
    exec_run(str);

    free(str);
    char *log = malloc(255);
    snprintf(log, 255, "INFO: reset dnmcli Entry: %i", id);
    log_loc(log);
}

/**
 * Checks time from a file for obsulation
 * @param fname
 * @return
 */
int time_handler(char *fname) {
    FILE *fp = file_open(fname, "r");

    if (fp == NULL)
        return -2;

    char *s_line = NULL;
    size_t len;

    getline(&s_line, &len, fp);

    char *line = malloc(strlen(s_line) + 1);
    snprintf(line, strlen(s_line), "%s", s_line);

    // Split string in end: and time string
    char *token = strtok(line, " ");

    if (strcmp(token, "end:") == 0) {
        token = strtok(NULL, " "); // Isolate time string

        // inf time isnt interesting for handler
        if (strcmp(token, "inf") == 0)
            return EXIT_FAILURE;

        tTime.tar_t = strtotm(del_n(token)); // change str to tm struct
        if (valid(tTime.tar_t) != 2) {

            char *log = malloc(256);
            snprintf(log, 256, "INFO: Time compare:\n ACT:%s - TAR:%s",
                     get_str_time(tTime.act_t), get_str_time(tTime.tar_t));
            log_loc(log);
            free(log);

            // compare tTime
            if (struct_greater() == 0) { // check for oldness
                file_close(fp);
                // file_del(fname, s_line);
                // revert_iptables(fname);
                // char *content = file_read_all(fname);
                // file_remove(fname);
                // file_del_text(CLASS_FW_FILENAME,content,"\n");

                //file_remove(fname);
                //revert_iptables(CLASS_FW_FILENAME);
                //file_remove(CLASS_FW_FILENAME);

                log_loc("INFO: timeHandler deactivate:");
                //if (content != NULL)
                //    log_loc(content);

                free(line);
                free(s_line);

                return EXIT_SUCCESS;
            } else {

                free(line);
                free(s_line);
                file_close(fp);
                log_loc("INFO: timeHandler still running");

                return EXIT_FAILURE;
            }
        }
    } else
        file_remove(fname);
    return EXIT_FAILURE;
}

/**
 * fork to handle deprecated time entries
 */
void duration_check() {

    struct shm_data *procom;
    int shmid = shmget(0x1234, 1024, 0666 | IPC_CREAT);
    procom = (struct shm_data *) shmat(shmid, (void *) 0, 0);

    if (fork() == 0) {
        // Register signal handling
        signal(SIGUSR1, sig_handler_time);
        signal(SIGUSR2, sig_handler_time);

        if (!procom->check)
            return;

        procom->child = getpid();

        char *str = malloc(256);
        snprintf(str, 256, "Fork PID: %d-%d",procom->parent, procom->child);
        log_loc(str);
        free(str);

        while (1) {
            get_act_time(&tTime.act_t);
            DIR *dp;
            struct dirent *ep;

            //log_loc("INFO: Time checker status:");
            //if (tTime.parent == true)
            //    log_loc("TRUE");
            //else
            //    log_loc("FALSE");

            if (!(dp = opendir(CLASS_PERSITENT_FILENAME)))
                log_loc("FAIL: DurationChecker No class DIR in /usr/ccsp/qos/class/");

            while ((ep = readdir(dp)) != NULL) { // Get all entries in Dir
                char *fname = malloc(512);
                snprintf(fname, 512, "%s/%s", CLASS_PERSITENT_FILENAME, ep->d_name);

                // Jump over system paths "." ".." ".tmp" ...
                if (fname[20] == '.')
                    continue;

                // Get id of the obsulate classification
                char *num = &ep->d_name[6];
                uint id = (uint) atoi(num);

                log_loc("INFO: Duration Checker run:");
                log_loc(fname);

                // Call checker routine to controll time
                if (time_handler(fname) == EXIT_SUCCESS) {
                    reset_dmcli(id);
                    char *str = malloc(512);
                    snprintf(str, 512, "%s%i%s", "dmcli eRT setv Device.QoS.Classification.", id,
                             ".Enable bool \"false\"");
                    exec_run(str);
                }
            }

            closedir(dp);

            sleep(15);
        }

    } else {
        procom->check = true;
        log_loc("SUCCESS: DurationChecker Time check active");
    }
    shmdt(procom);
}
