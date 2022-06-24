//
// Created by limberg on 12.01.2022.
//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "classification.h"

#define CLASS_FW_FILENAME "/tmp/qos_rules.sh"

#define CLASS_FW_RELOAD_FILENAME "/etc/utopia/service.d/firewall_log_handle.sh"
#define CLASS_PERSITENT_FILENAME "/usr/ccsp/qos/class"

#define CLASS_IPTABLES_MANGLE_CMD "iptables -t mangle"
#define CLASS_IPTABLES_MANGLE_CMD_6 "ip6tables -t mangle"
#define LOG_FILE "/usr/ccsp/qos/log.txt"

#include "datastruct_params.h"

/**
 * A simple, quiet indicator for run a command status after execution
 * @param str
 * @return EXIT_SUCCESS EXIT_FAILURE
 */
int exec_run(char *str) {
        if (system(str) != -1) {
            log_loc("SUCCESS: ExecRun line:");
            log_loc(str);
            return EXIT_SUCCESS;
        } else {
            // Handle a fail in rerun for 5 times
            log_loc("FAIL: ExecRun NEXT TRYS");
            for (int i = 1; i < 5; i++) {
                int ret = system(str);
                if (ret != -1) {
                    log_loc("SUCCESS: ExecRun line");
                    log_loc(str);
                    return EXIT_SUCCESS;
                }
                log_loc("FAIL: ExecRun retry line");
            }
            log_loc("FAIL: ExecRun fails 5 trys");
            return EXIT_FAILURE;
        }
}

/**
 * A function to check for a string in a file
 * @param comp (char *), fp (FILE *)
 * @return EXIT_SUCCESS, EXIT_FAILURE
 */
int file_contain(char *comp, FILE *fp) {
    char *line = NULL;
    size_t len = 0;

    if (fp == NULL)
        return -2;

    fseek(fp, 0, SEEK_SET);

    while (getline(&line, &len, fp) != -1) {
        if (strcmp(line, comp) == 0) {
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}

/**
 * A function to open a file and return its pointer
 * @param filename
 * @param mode
 * @return FILE* fp
 */
FILE* file_open(char *filename, char *mode) {
    FILE *fp = NULL;

    if(!(fp = fopen(filename, mode))) {
        sleep(1);
        fp = fopen(filename, mode);
        if (fp == NULL) {
            log_loc("FAIL: file openener");
            log_loc(filename);
        }
    }
    return fp;
}

/**
 * Close file
 * @param fp
 * @return
 */
int file_close(FILE *fp) {
    if (fp != NULL) {
        fclose(fp);
        return EXIT_SUCCESS;
    } else
        return EXIT_FAILURE;
}

/**
 * A Function to delete a file by filename
 * @param filename
 * @return
 */
int file_remove(const char *filename) {
    if (remove(filename))
        return EXIT_SUCCESS;
    else
        return EXIT_FAILURE;
}

/**
 * A function to create new File
 * @param filename
 * @return
 */
int file_touch(char *filename) {
    FILE *fp = file_open(filename, "w");

    if (fp == NULL)
        return EXIT_FAILURE;

    rewind(fp);

    file_close(fp);
    return EXIT_SUCCESS;
}

/**
 * Reads a whole File and return its string
 * @param filename
 * @return
 */
char * file_read_all(char *filename) {
    FILE *fp = file_open(filename, "r");
    char *line = NULL;
    char *ret = malloc(1024);
    char *tmp;
    size_t len = 0;
    size_t lret = 0;
    tmp = "\0";

    if (fp == NULL)
        return NULL;

    while (getline(&line, &len, fp) != -1) {
        lret = lret + len;

        if (tmp[0] == '\0')
            snprintf(ret, lret, "%s", line);
        else {
            snprintf(ret, lret, "%s%s", tmp, line);
            free(tmp);
        }

        tmp = malloc(lret);
        snprintf(tmp, lret, "%s", ret);
    }

    file_close(fp);

    log_loc("INFO: File Read:");
    log_loc(ret);

    return ret;
}

/**
 * File write a single line in a File
 * @param filename
 * @param mode
 * @param line
 * @return
 */
int file_write(char *filename, char *mode, char *line) {
    FILE *fp = file_open(filename, "r");

    if (fp != NULL)
        if (file_contain(line, fp) == EXIT_FAILURE) {
            log_loc("SUCCESS: FileWrite File Contains line, no action needed");
            log_loc(line);
            file_close(fp);
            return EXIT_SUCCESS;
        }
    file_close(fp);

    if ((fp = file_open(filename, mode)) == NULL) {
        log_loc("FAIL: FileWrite File not openable");
        return EXIT_FAILURE;
    }

    fwrite(line, 1, strlen(line), fp);

    if (file_close(fp) == EXIT_FAILURE) {
        log_loc("FAIL: FileWrite File not closable");
        return EXIT_FAILURE;
    }



    log_loc("SUCCESS: FileWrite File has been written");
    log_loc(line);

    return EXIT_SUCCESS;
}

char* add_n(char *line) {
    size_t len = strlen(line);

    if (line[len-1] != '\n') {
        char *str = malloc(len + 2);
        snprintf(str, len + 2, "%s\n", line);
        log_loc("SUCCESS: AddN Newline added");
        return str;
    }

    log_loc("SUCCESS: AddN Newline already Exsists");
    return line;
}

/**
 * Delete the newline in the end of a string
 * @param line
 * @return
 */
char* del_n(char *line) {
    size_t len = strlen(line);

    if (line[len-1] == '\n') {
        char *str = malloc(len - 1);
        snprintf(str, len, "%s", line);
        return str;
    }

    return line;
}

/**
 * A function to write a text of a whole text, the text can be seperated by a specific delimiter
 * @param filename
 * @param mode
 * @param text
 * @param delim
 * @return
 */
int file_write_text(char *filename, char *mode, char *text, char *delim) {
    char *tmp = malloc(strlen(text)+1);
    snprintf(tmp, strlen(text)+1, "%s", text);

    char *token = strtok(tmp, delim);
    file_write(filename, mode,add_n(token));

    while (token != NULL) {
        token = strtok(NULL, delim);

        if (token == NULL)
            break;

        file_write(filename, mode,add_n(token));
    }

    return EXIT_SUCCESS;
}

/**
 * A function to delete a bunch of iptable entries out of a file
 * @param fname
 * @return
 */
int revert_iptables(char *fname) {
    log_loc("INFO: RevertIptables init");
    FILE *fp = file_open(fname, "r");

    char *line = NULL;
    size_t len = 0;

    if (fp == NULL) {
        log_loc("FAIL: revertIptables exit file handle");
        return EXIT_FAILURE;
    }

    while (getline(&line, &len, fp) != -1) {
        // Catch end line
        if (line[0] == 'e')
            continue;

        if (line[2] == '6')
            line[21] = 'D';
        else
            line[20] = 'D';

        if (exec_run(del_n(line)) == 0) {
            log_loc("SUCCESS: revertIptables Run iptables Revert:");
            log_loc(del_n(line));
        } else {
            log_loc("FAIL: revertIptables Run iptables Revert:");
            log_loc(del_n(line));
        }
    }

    file_close(fp);
    return EXIT_SUCCESS;
}

/**
 * A function to delete a single line of a file
 * @param filename
 * @param text
 * @return EXIT_SUCCESS, EXIT_FAILURE
 */
int file_del(char *filename, char *text) {
    FILE *fp = file_open(filename, "r");

    if (fp == NULL)
        return EXIT_FAILURE;

    char *line = NULL;
    size_t len = 0;

    file_touch(CLASS_PERSITENT_FILENAME"/.tmp");

    while (getline(&line, &len, fp) != -1) {
        if (strcmp(line, add_n(text)) != 0) {
            file_write(CLASS_PERSITENT_FILENAME"/.tmp", "a",line);
        }
    }

    file_close(fp);

    file_remove(filename);

    rename(CLASS_PERSITENT_FILENAME"/.tmp", filename);

    log_loc("INFO: DelLine in File:");
    log_loc(text);
    log_loc(filename);

    return EXIT_SUCCESS;
}

/**
 * A file to delete a bunch of lines out of a file
 * @param filename
 * @param text
 * @param delim
 * @return EXIT_SUCCESS, EXIT_FAILURE
 */
int file_del_text(char *filename, char *text, char *delim){
    if (text == NULL)
        return EXIT_FAILURE;

    if (delim == NULL)
        return EXIT_FAILURE;

    char *tmp = malloc(strlen(text)+1);
    snprintf(tmp, strlen(text)+1, "%s", text);

    char *token = strtok(tmp, delim);

    while (token != NULL) {
        file_del(filename,token);

        token = strtok(NULL, delim);
    }

    return EXIT_SUCCESS;
}

/**
 * Allocates the data of qos_class
 * @param class
 * @return qos_struct of class
 */
qos_struct *initQosClass(const struct qos_class *class) {
    qos_struct *data = malloc(sizeof(qos_struct));

    data->data = malloc(sizeof(struct qos_class));
    data->data = class;
    data->size = sizeof(*data);
    data->str = "";
    return data;
}

/**
 * Test main func with a debug struct in main to add an set to add (pseudo) classification
 * @return 0 SUCCESS -1 FAIL
 */
int main() {
    struct qos_class *test_class1 = malloc(sizeof(struct qos_class));
    struct qos_class *test_class2 = malloc(sizeof(struct qos_class));

    qos_removeAllClasses();

    test_class1->id = 1;
    test_class1->dscp_mark = 24;
    strcpy(test_class1->mac_src_addr, "00:e0:4c:81:c8:41");
    
    test_class2->dscp_mark = 24;
    strcpy(test_class2->mac_src_addr, "00:e0:4c:81:c8:45");
    strcpy(test_class1->expiration, "20:25:59-27.05.2022");

    if (qos_addClass(test_class1) == -1)
        return EXIT_FAILURE;

    qos_removeAllClasses();
    strcpy(test_class1->expiration, "20:25:59-27.05.2022");

    if (qos_addClass(test_class1) == -1)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}



/**
 * API function
 * checks the data in classification struct from .h file. Then build the dscp_mark iptables in that kind:
 *
 * dmcli eRT addtable Device.QoS.Classification.
 * dmcli eRT setv Device.QoS.Classification.1.ChainName string "postrouting_qos"
 * dmcli eRT setv Device.QoS.Classification.1.IfaceOut string "erouter0"
 * dmcli eRT setv Device.QoS.Classification.1.DSCPMark int 24
 * dmcli eRT setv Device.QoS.Classification.1.SourceMACAddress string "9c:c9:eb:2a:01:0a"
 * dmcli eRT setv Device.QoS.Classification.1.IfaceIn string "brlan0"
 * dmcli eRT setv Device.QoS.Classification.1.Duration string "16:50:00-08.06.2022"
 * dmcli eRT setv Device.QoS.Classification.1.Enable bool true
 *
 * The Parameter must be set
 *
 * @param param
 * @return 0 SUCCESS -1 FAIL
 */
int qos_addClass(const struct qos_class *param) {
    qos_struct *obj = initQosClass(param);

    log_loc("SUCCESS: AddClass Entry AddClass");

    /// Check for used Data
    if (
            obj->data->dscp_mark != 0 &&
            obj->data->mac_src_addr[0] != '\0'
            ) {
        log_loc("SUCCESS: AddClass All Classification Comps are there");

        FILE *fp = file_open(CLASS_FW_FILENAME, "r");

        if (fp == NULL) {
            file_touch(CLASS_FW_FILENAME);
            fp = file_open(CLASS_FW_FILENAME, "r");
        }

        /// Alloc space for command
        char *exec1 = (char *) malloc(255);
        int  ex4 = 0, ex5 = 0, ex9 = 0, ex10 = 0;

        /// Set iptables command in exec
        snprintf(exec1, 255, "%s -I %s -o %s -m mark --mark %d -j DSCP --set-dscp %d", CLASS_IPTABLES_MANGLE_CMD,
                 IP4POSTROUTING, WAN_IFACE, IP4_FIRE_MARK, obj->data->dscp_mark);
        /// Realloc space
        exec1 = realloc(exec1, strlen(exec1) * sizeof(char));

        if (file_contain(add_n(exec1), fp) == EXIT_SUCCESS) {

            if(exec_run(del_n(exec1)) != 0)
                log_loc("FAIL: system exec1");
            else
                log_loc("SUCCESS: system exec1");

            file_close(fp);
            file_write(CLASS_FW_FILENAME, "a", add_n(exec1));
            fp = file_open(CLASS_FW_FILENAME, "r");
        }

        char *exec2 = (char *) malloc(255);
        snprintf(exec2, 255, "%s -I %s -o %s -m mark --mark %d -j DSCP --set-dscp %d", CLASS_IPTABLES_MANGLE_CMD,
                 IP4POSTROUTING, LAN_IFACE, IP4_FIRE_MARK, obj->data->dscp_mark);
        exec2 = realloc(exec2, strlen(exec2) * sizeof(char));
        if (file_contain(add_n(exec2), fp) == EXIT_SUCCESS) {

            if(exec_run(del_n(exec2)) != 0)
                log_loc("FAIL: system exec2");
            else
                log_loc("SUCCESS: addClass exec2");

            file_close(fp);
            file_write(CLASS_FW_FILENAME, "a", add_n(exec2));
            fp = file_open(CLASS_FW_FILENAME, "r");
        }

        char *exec3 = (char *) malloc(255);
        snprintf(exec3, 255, "%s -I %s -o %s -m state --state ESTABLISHED,RELATED -j CONNMARK --restore-mark",
                 CLASS_IPTABLES_MANGLE_CMD, IP4POSTROUTING, LAN_IFACE);
        exec3 = realloc(exec3, strlen(exec3) * sizeof(char));
        if (file_contain(add_n(exec3), fp) == EXIT_SUCCESS) {

            if(exec_run(del_n(exec3)) != 0)
                log_loc("FAIL: system exec3");
            else
                log_loc("SUCCESS: addClass exec3");

            file_close(fp);
            file_write(CLASS_FW_FILENAME, "a", add_n(exec3));
            fp = file_open(CLASS_FW_FILENAME, "r");
        }

        char *exec11 = (char *) malloc(257);
        snprintf(exec11, 256,
                 "%s -I %s -i %s -m mac --mac-source %s -j DSCP --set-dscp %d",
                 CLASS_IPTABLES_MANGLE_CMD, IP4PREROUTING, LAN_IFACE, obj->data->mac_src_addr, obj->data->dscp_mark);
        exec11 = realloc(exec11, strlen(exec11) * sizeof(char) + 1);
        if (file_contain(add_n(exec11), fp) == EXIT_SUCCESS) {

            if (exec_run(del_n(exec11)) != 0)
                log_loc("FAIL: system exec5");
            else
                log_loc("SUCCESS: addClass exec5");

            file_close(fp);
            file_write(CLASS_FW_FILENAME, "a", add_n(exec11));
            fp = file_open(CLASS_FW_FILENAME, "r");
        }

        char *exec4 = (char *) malloc(255);
        snprintf(exec4, 255,
                 "%s -I %s -i %s -m state --state NEW -m mac --mac-source %s -j CONNMARK --save-mark",
                 CLASS_IPTABLES_MANGLE_CMD, IP4PREROUTING ,LAN_IFACE, obj->data->mac_src_addr);
        exec4 = realloc(exec4, strlen(exec4) * sizeof(char));
        if (file_contain(add_n(exec4), fp) == EXIT_SUCCESS) {

            if (exec_run(del_n(exec4)) != 0)
                log_loc("FAIL: system exec4");
            else
                log_loc("SUCCESS: addClass exec4");

            ex4 = 1;
        }

        char *exec5 = (char *) malloc(257);
        snprintf(exec5, 256,
                 "%s -I %s -i %s -m state --state NEW -m mac --mac-source %s -j MARK --set-mark %d",
                 CLASS_IPTABLES_MANGLE_CMD, IP4PREROUTING, LAN_IFACE, obj->data->mac_src_addr, IP4_FIRE_MARK);
        exec5 = realloc(exec5, strlen(exec5) * sizeof(char) + 1);
        if (file_contain(add_n(exec5), fp) == EXIT_SUCCESS) {

            if (exec_run(del_n(exec5)) != 0)
                log_loc("FAIL: system exec5");
            else
                log_loc("SUCCESS: addClass exec5");

            ex5 = 1;
        }




        /// Deallocate memory
        free(exec1);
        free(exec2);
        free(exec3);
        free(exec11);

        char *exec6 = (char *) malloc(255);

        snprintf(exec6, 255, "%s -I %s -o %s -m mark --mark %d -j DSCP --set-dscp %d", CLASS_IPTABLES_MANGLE_CMD_6,
                 IP6POSTROUTING, WAN_IFACE, IP6_FIRE_MARK, obj->data->dscp_mark);

        //exec6 = realloc(exec6, strlen(exec6) * sizeof(char));

        if (file_contain(add_n(exec6), fp) == EXIT_SUCCESS) {

            if(exec_run(del_n(exec6)) != 0)
                log_loc("FAIL: system exec6");
            else
                log_loc("SUCCESS: system exec6");

            file_close(fp);
            file_write(CLASS_FW_FILENAME, "a", add_n(exec6));
            fp = file_open(CLASS_FW_FILENAME, "r");
        }

        char *exec7 = (char *) malloc(255);
        snprintf(exec7, 255, "%s -I %s -o %s -m mark --mark %d -j DSCP --set-dscp %d", CLASS_IPTABLES_MANGLE_CMD_6,
                 IP6POSTROUTING, LAN_IFACE, IP6_FIRE_MARK, obj->data->dscp_mark);
        exec7 = realloc(exec7, strlen(exec7) * sizeof(char));
        if (file_contain(add_n(exec7), fp) == EXIT_SUCCESS) {

            if(exec_run(del_n(exec7)) != 0)
                log_loc("FAIL: system exec7");
            else
                log_loc("SUCCESS: addClass exec7");

            file_close(fp);
            file_write(CLASS_FW_FILENAME, "a", add_n(exec7));
            fp = file_open(CLASS_FW_FILENAME, "r");
        }

        char *exec8 = (char *) malloc(255);
        snprintf(exec8, 255, "%s -I %s -o %s -m state --state ESTABLISHED,RELATED -j CONNMARK --restore-mark",
                 CLASS_IPTABLES_MANGLE_CMD_6, IP6POSTROUTING, LAN_IFACE);
        exec8 = realloc(exec8, strlen(exec8) * sizeof(char));
        if (file_contain(add_n(exec8), fp) == EXIT_SUCCESS) {

            if(exec_run(del_n(exec8)) != 0)
                log_loc("FAIL: system exec8");
            else
                log_loc("SUCCESS: addClass exec8");

            file_close(fp);
            file_write(CLASS_FW_FILENAME, "a", add_n(exec8));
            fp = file_open(CLASS_FW_FILENAME, "r");
        }



        char *exec12 = (char *) malloc(257);
        snprintf(exec12, 256,
                 "%s -I %s -i %s -m mac --mac-source %s -j DSCP --set-dscp %d",
                 CLASS_IPTABLES_MANGLE_CMD_6, IP6PREROUTING, LAN_IFACE, obj->data->mac_src_addr, obj->data->dscp_mark);
        exec12 = realloc(exec12, strlen(exec12) * sizeof(char) + 1);
        if (file_contain(add_n(exec12), fp) == EXIT_SUCCESS) {

            if (exec_run(del_n(exec12)) != 0)
                log_loc("FAIL: system exec12");
            else
                log_loc("SUCCESS: addClass exec12");

            file_close(fp);
            file_write(CLASS_FW_FILENAME, "a", add_n(exec12));
            fp = file_open(CLASS_FW_FILENAME, "r");
        }

        char *exec9 = (char *) malloc(255);
        snprintf(exec9, 255,
                 "%s -I %s -i %s -m state --state NEW -m mac --mac-source %s -j CONNMARK --save-mark",
                 CLASS_IPTABLES_MANGLE_CMD_6, IP6PREROUTING, LAN_IFACE, obj->data->mac_src_addr);
        exec9 = realloc(exec9, strlen(exec9) * sizeof(char));
        if (file_contain(add_n(exec9), fp) == EXIT_SUCCESS) {

            if(exec_run(del_n(exec9)) != 0)
                log_loc("FAIL: system exec9");
            else
                log_loc("SUCCESS: addClass exec9");

            ex9 = 1;
        }

        char *exec10 = (char *) malloc(257);
        snprintf(exec10, 257,
                 "%s -I %s -i %s -m state --state NEW -m mac --mac-source %s -j MARK --set-mark %d",
                 CLASS_IPTABLES_MANGLE_CMD_6, IP6PREROUTING, LAN_IFACE, obj->data->mac_src_addr, IP6_FIRE_MARK);
        exec10 = realloc(exec10, strlen(exec10) * sizeof(char));
        if (file_contain(add_n(exec10), fp) == EXIT_SUCCESS) {

            if (exec_run(del_n(exec10)) != 0)
                log_loc("FAIL: system exec10");
            else
                log_loc("SUCCESS: addClass exec10");

            ex10 = 1;
        }

        /// Organize String for class
        ulong l = strlen(exec4) + strlen(exec5) + strlen(exec9) + strlen(exec10);
        char *concat = malloc(l + 5);
        snprintf(concat, l + 5, "%s\n%s\n%s\n%s", exec4, exec5, exec9, exec10);
        obj->str = concat;

        if ( ex4 == 1 && ex5 == 1 && ex9 == 1 && ex10 == 1) {
            log_loc("SUCCESS: AddClass All rules are ready to add...");
            file_write_text(CLASS_FW_FILENAME,"a",obj->str, "\n");
        }

        qos_ExpirationClass(obj);
        log_loc("SUCCESS: AddClass make Class persistent");

        /// IPC shared Memory
        struct shm_data *procom;
        int shmid = shmget(0x1234, 1024, 0666 | IPC_CREAT);
        procom = (struct shm_data *) shmat(shmid, (void *) 0, 0);

        procom->parent = getpid();

        // If there is no checker active
        if (procom->check != true) {
            log_loc("SUCCESS: AddClass Expiration checker start");
            expiration_check();
        }
        shmdt(procom);

        /// Deallocate memory
        free(exec4);
        free(exec5);
        free(exec6);
        free(exec7);
        free(exec8);
        free(exec9);
        free(exec10);
        free(exec12);
        log_loc("SUCCESS: AddClass Make execs free");

        /// Integrate qos-firewall file into firewall
        fp = file_open(CLASS_FW_RELOAD_FILENAME, "r");
        if (file_contain(CLASS_FW_FILENAME, fp) == EXIT_SUCCESS) {
            file_close(fp);
            if (file_write(CLASS_FW_RELOAD_FILENAME, "a", add_n(CLASS_FW_FILENAME)) == EXIT_FAILURE) {
                log_loc("FAIL: AddClass set iptables rules via firewall");
                return EXIT_FAILURE;
            } else
                log_loc("SUCCESS: AddClass Firewall Utopia entry done");
        } else
            log_loc("INFO: AddClass Firewall is set up before");

        if (chmod(CLASS_FW_FILENAME, S_IRWXU | S_IRWXG | S_IRWXO) != 0)
            log_loc("FAIL: Cannot change permissions");

    } else {
        log_loc("FAIL: AddClass Not right comps");
    }

    return 0;
}

/**
 * Manifest a classification for a longer time in classification structure /usr/ccsp/qos/class/.
 * @param obj
 * @return EXIT_SUCCESS
 */
int qos_ExpirationClass(const qos_struct *obj) {

    char *fname = malloc(256);
    snprintf(fname, 255, CLASS_PERSITENT_FILENAME"/class_%i", obj->data->id);

    char *clas_file = malloc(strlen(obj->str) + 32);

    /// Checks for an infite classification or with expiration
    if (*obj->data->expiration != '\0') {
        snprintf(clas_file, strlen(obj->str) + 32, "end: %s\n%s", obj->data->expiration, obj->str);
    } else {
        snprintf(clas_file, strlen(obj->str) + 32, "end: %s\n%s", "inf", obj->str);
    }
    file_remove(fname);
    file_touch(fname);
    file_write_text(fname, "a", clas_file, "\n");

    log_loc("SUCCESS: ExpirationClass Make expiration in class_%i persistent");
    free(clas_file);

    return EXIT_SUCCESS;
}

/**
 * Reverse the complete classification structure
 * Main deletion done by Utopia firewall
 * @return
 */
int qos_removeAllClasses() {
    log_loc("INFO: removeAllClasses");
    DIR *dp;
    struct dirent *ep;

    if (!(dp = opendir(CLASS_PERSITENT_FILENAME)))
        log_loc("FAIL: ExpirationChecker No class DIR in /usr/ccsp/qos/class/");

    while ((ep = readdir(dp)) != NULL) { // Get all entries in Dir
        char *fname = malloc(277);
        snprintf(fname, 277, "%s/%s", CLASS_PERSITENT_FILENAME, ep->d_name);

        if (fname[20] == '.')
            continue;

        log_loc("INFO: removeAllClasses done");

        remove(fname);
    }

    closedir(dp);

    //revert_iptables(CLASS_FW_FILENAME);
    remove(CLASS_FW_FILENAME);


    struct shm_data *procom;
    int shmid = shmget(0x1234, 1024, 0666 | IPC_CREAT);
    procom = (struct shm_data *) shmat(shmid, (void *) 0, 0);

    if (procom->child != 0) {
        char *str = malloc(256);
        snprintf(str,256, "INFO: Delete Child Proc %i", procom->child);
        log_loc(str);
        kill(procom->child, 9);
        free(str);
    }

    shmdt(procom);
    shmctl(shmid,IPC_RMID,NULL);

    return EXIT_SUCCESS;
}

/**
 * A function to write logs
 * @param str
 */
void log_loc(char *str) {
    FILE *fp = fopen(LOG_FILE, "a");

    if (fp == NULL) {
        fp = fopen(LOG_FILE, "w");
    }

    if (fp != NULL) {
        get_act_time(&tTime.act_t);
        char *logentry = malloc(strlen(str) + 4 + strlen(get_str_time(tTime.act_t)));
        snprintf(logentry, strlen(str) + 4 + strlen(get_str_time(tTime.act_t)), "%s: %s\n", get_str_time(tTime.act_t), str);
        fwrite(logentry, 1, strlen(logentry), fp);

        fclose(fp);
    }
}

/**
 * Remove a single classification
 * @param id
 * @return
 *
int qos_removeOneClass(uint id) {
    char *str = malloc(256);
    snprintf(str, 256,"INFO: RemoveOneClass no. %i", id);
    log_loc(str);

    qos_removeAllClasses();

    free(str);

    return EXIT_SUCCESS;
}
 */
