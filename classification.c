//
// Created by limberg on 12.01.2022.
//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "classification.h"

#define CLASS_FW_FILENAME "/tmp/qos_rules.sh"

#define CLASS_FW_RELOAD_FILENAME "/etc/utopia/service.d/firewall_log_handle.sh"
#define CLASS_PERSITENT_FILENAME "/usr/ccsp/qos/class"

#define CLASS_IPTABLES_MANGLE_CMD "iptables -t mangle"
#define LOG_FILE "/usr/ccsp/qos/log.txt"

/*
enum class_table
{
    IPTABLES_IPV4 = (1 << 0),
    IPTABLES_IPV6 = (1 << 1),
};
*/

/**
 * A simple, quiet indicator for run a command status after execution
 * @param str
 * @return
 */
int exec_run(char *str) {
    if (system(str) == 0)
        return EXIT_SUCCESS;
    else
        return EXIT_FAILURE;
}

/**
 * A Function to check exsistence of string in firewall file
 * @param comp (char *)
 * @return EXIT_SUCCESS, EXIT_FAILURE
 */
int file_contain(char *comp, FILE *fp) {
    char *line = NULL;
    size_t len = 0;

    if (fp == NULL)
        return EXIT_SUCCESS;

    fseek(fp, 0, SEEK_SET);

    while (getline(&line, &len, fp) != -1) {
        if (strstr(line, comp)) {
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}

FILE* file_open(char *filename, char *mode) {
    FILE *fp = NULL;

    if(!(fp = fopen(filename, mode))) {
        log_loc("FAIL: file openener");
        log_loc(filename);
    }
    return fp;
}

int file_close(FILE *fp) {
    if (fp != NULL) {
        fclose(fp);
        return EXIT_SUCCESS;
    } else
        return EXIT_FAILURE;
}

int file_remove(const char *filename) {
    if (remove(filename))
        return EXIT_SUCCESS;
    else
        return EXIT_FAILURE;
}

int file_touch(char *filename) {
    FILE *fp = file_open(filename, "w");

    if (fp == NULL)
        return EXIT_FAILURE;

    rewind(fp);

    file_close(fp);
    return EXIT_SUCCESS;
}

char * file_read_all(char *filename) {
    FILE *fp = file_open(filename, "r");
    char *line = NULL;
    char *ret = malloc(1024);
    char *tmp = malloc(1);
    size_t len = 0;
    size_t lret = 0;
    tmp = "\0";

    if (fp == NULL)
        return NULL;

    while (getline(&line, &len, fp) != -1) {
        lret = lret + len;

        if (tmp == "\0")
            snprintf(ret, lret, "%s", line);
        else {
            snprintf(ret, lret, "%s%s", tmp, line);
            free(tmp);
        }

        tmp = malloc(lret);
        snprintf(tmp, lret, "%s", ret);
    }

    file_close(fp);

    return ret;
}

int file_write(char *filename, char *mode, char *line) {
    FILE *fp;

    if ((fp = file_open(filename, "r")) != NULL)
        if (file_contain(line, fp) != EXIT_SUCCESS) {
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

char* del_n(char *line) {
    size_t len = strlen(line);

    if (line[len-1] == '\n') {
        char *str = malloc(len - 1);
        snprintf(str, len, "%s", line);
        return str;
    }

    return line;
}

int file_write_text(char *filename, char *mode, char *text, char *delim) {
    char *tmp = malloc(strlen(text)+1);
    snprintf(tmp, strlen(text), "%s", text);

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

int revert_iptables(char *fname) {
    FILE *fp = file_open(fname, "r");

    char *line = NULL;
    size_t len = 0;

    if (fp == NULL)
        return EXIT_FAILURE;

    while (getline(&line, &len, fp) != -1) {
            line[20] = 'D';
            exec_run(del_n(line));
    }

    file_close(fp);
    return EXIT_SUCCESS;
}


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

    return EXIT_SUCCESS;
}

int file_del_text(char *filename, char *text, char *delim){
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

    test_class1->id = 1;
    strcpy(test_class1->chain_name, "postrouting_qos");
    strcpy(test_class1->iface_out, "erouter0");
    strcpy(test_class1->iface_in, "brlan0");
    test_class1->dscp_mark = 32;
    strcpy(test_class1->mac_src_addr, "00:e0:4c:81:c8:41");
    strcpy(test_class1->duration, "02:23:59-26.05.2022");

    test_class2->traffic_class = 2;
    strcpy(test_class2->chain_name, "postrouting_qos");
    strcpy(test_class2->iface_out, "erouter2");
    strcpy(test_class2->iface_in, "brlan1");
    test_class2->dscp_mark = 32;
    strcpy(test_class2->mac_src_addr, "00:e0:4c:81:c8:45");

    if (qos_addClass(test_class1) == -1)
        return EXIT_FAILURE;

    qos_removeAllClasses();

    if (qos_addClass(test_class2) == -1)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}



/**
 * API function
 * checks the data in classification struct from .h file. Then build the dscp_mark iptables in that kind:
 *
 * dmcli eRT addtable Device.QoS.Classification.
 * dmcli eRT setv Device.QoS.Classification.1.SourcePort int -1
 * dmcli eRT setv Device.QoS.Classification.1.SourcePortRangeMax int -1
 * dmcli eRT setv Device.QoS.Classification.1.DestPort int -1
 * dmcli eRT setv Device.QoS.Classification.1.DestPortRangeMax int -1
 * dmcli eRT setv Device.QoS.Classification.1.Protocol int -1
 *
 * dmcli eRT setv Device.QoS.Classification.1.TrafficClass int 2
 * dmcli eRT setv Device.QoS.Classification.1.ChainName string "postrouting_qos"
 *
 * dmcli eRT setv Device.QoS.Classification.1.IfaceOut string "erouter0"
 * dmcli eRT setv Device.QoS.Classification.1.DSCPMark int 32
 * dmcli eRT setv Device.QoS.Classification.1.SourceMACAddress string "00:e0:4c:81:c8:40"
 * dmcli eRT setv Device.QoS.Classification.1.IfaceIn string "brlan0"
 * dmcli eRT setv Device.QoS.Classification.1.Enable bool true
 *
 * The Parameter must be set
 *
 * @param param
 * @return 0 SUCCESS -1 FAIL
 */
int qos_addClass(const struct qos_class *param) {
    qos_struct *obj = initQosClass(param);

    //duration_check(obj->data->duration);

    log_loc("SUCCESS: AddClass Entry AddClass");

    // Check for used Data
    if (
            obj->data->chain_name[0] != '\0' &&
            obj->data->iface_in[0] != '\0' &&
            obj->data->iface_out[0] != '\0' &&
            obj->data->dscp_mark != 0 &&
            obj->data->mac_src_addr[0] != '\0'
            ) {
        log_loc("SUCCESS: AddClass All Classification Comps are there");

        /// Alloc space for command
        char *exec1 = (char *) malloc(255);
        int  ex4 = 0, ex5 = 0; //ex1 = 0, ex2 = 0, ex3 = 0;

        /// Set iptables command in exec
        snprintf(exec1, 255, "%s -I %s -o %s -m mark --mark 4444 -j DSCP --set-dscp %d", CLASS_IPTABLES_MANGLE_CMD,
                 obj->data->chain_name, obj->data->iface_out, obj->data->dscp_mark);
        /// Realloc space
        exec1 = realloc(exec1, strlen(exec1) * sizeof(char));

        FILE *fp = file_open(CLASS_FW_FILENAME, "r");

        if (file_contain(exec1, fp) == EXIT_SUCCESS) {
            system(exec1);
            //ex1 = 1;
        }

        char *exec2 = (char *) malloc(255);
        snprintf(exec2, 255, "%s -I %s -o %s -m mark --mark 4444 -j DSCP --set-dscp %d", CLASS_IPTABLES_MANGLE_CMD,
                 obj->data->chain_name, obj->data->iface_in, obj->data->dscp_mark);
        exec2 = realloc(exec2, strlen(exec2) * sizeof(char));
        if (file_contain(exec2, fp) == EXIT_SUCCESS) {
            system(exec2);
            //ex2 = 1;
        }

        char *exec3 = (char *) malloc(255);
        snprintf(exec3, 255, "%s -I %s -o %s -m state --state ESTABLISHED,RELATED -j CONNMARK --restore-mark",
                 CLASS_IPTABLES_MANGLE_CMD, obj->data->chain_name, obj->data->iface_in);
        exec3 = realloc(exec3, strlen(exec3) * sizeof(char));
        if (file_contain(exec3, fp) == EXIT_SUCCESS) {
            system(exec3);
            //ex3 = 1;
        }

        char *exec4 = (char *) malloc(255);
        snprintf(exec4, 255,
                 "%s -I prerouting_qos -i %s -m state --state NEW -m mac --mac-source %s -j CONNMARK --save-mark",
                 CLASS_IPTABLES_MANGLE_CMD, obj->data->iface_in, obj->data->mac_src_addr);
        exec4 = realloc(exec4, strlen(exec4) * sizeof(char));
        if (file_contain(exec4, fp) == EXIT_SUCCESS) {
            system(exec4);
            ex4 = 1;
        }

        char *exec5 = (char *) malloc(255);
        snprintf(exec5, 255,
                 "%s -I prerouting_qos -i %s -m state --state NEW -m mac --mac-source %s -j MARK --set-mark 4444",
                 CLASS_IPTABLES_MANGLE_CMD, obj->data->iface_in, obj->data->mac_src_addr);
        exec5 = realloc(exec5, strlen(exec5) * sizeof(char));
        if (file_contain(exec5, fp) == EXIT_SUCCESS) {
            system(exec5);
            ex5 = 1;
        }

        ulong l = strlen(exec1) + strlen(exec2) + strlen(exec3) + strlen(exec4) + strlen(exec5);
        char *concat = malloc((int) l + 5);

        if (
                ex4 == 1 &&
                ex5 == 1
                ) {
            log_loc("SUCCESS: AddClass All rules are ready to add...");
            snprintf(concat, l + 6, "%s\n%s\n%s\n%s\n%s\n", exec1, exec2, exec3, exec4, exec5);
            obj->str = concat;
            file_write_text(CLASS_FW_FILENAME,"a",obj->str, "\n");
        }

        if (*obj->data->duration != '\0') {
            qos_DurationClass(obj);
            log_loc("SUCCESS: AddClass make Class persistent");

            // If there is no checker active
            if (tTime.check != true) {
                log_loc("SUCCESS: AddClass Duration checker start");
                duration_check();
            }
        }

        free(exec1);
        free(exec2);
        free(exec3);
        free(exec4);
        free(exec5);
        log_loc("SUCCESS: AddClass Make execs free");

        /// Integrate qos-firewall file into firewall
        if (file_write(CLASS_FW_RELOAD_FILENAME,"a", add_n(CLASS_FW_FILENAME)) == EXIT_FAILURE) {
            log_loc("FAIL: AddClass set iptables rules via firewall");
            return EXIT_FAILURE;
        }

    } else {
        log_loc("FAIL: AddClass Not right comps");
    }

    return 0;
}

/**
 * Manifest a classification for a longer time.
 * @param obj
 * @return
 */
int qos_DurationClass(const qos_struct *obj) {

    char *fname = malloc(256);
    snprintf(fname, 255, CLASS_PERSITENT_FILENAME"/class_%i.dat", obj->data->id);

    char *clas_file = malloc(strlen(obj->str) + 32);
    snprintf(clas_file, strlen(obj->str) + 64, "end: %s\n%s", obj->data->duration, obj->str);

    file_remove(fname);

    file_write(fname, "w", clas_file);

    log_loc("SUCCESS: DurationClass Make duration in class_%i persistent");
    return 0;
}

/**
 * Reverse the complete classification structure off dmcli
 * @return
 */
int qos_removeAllClasses() {
    FILE *fp;
    char *line = NULL;
    size_t len = 0;

    if (!(fp = fopen(CLASS_FW_FILENAME, "r"))) {
        log_loc("FAIL: removeAllClasses Open file "CLASS_FW_FILENAME);
        return -1;
    }

    while (getline(&line, &len, fp) != -1) {
        line[20] = 'D';
        system(line);
    }
    rewind(fp);
    fclose(fp);

    if (!(fp = fopen(CLASS_FW_FILENAME, "w"))) {
        log_loc("FAIL: RemoveAllClasses Open file after Rewind "CLASS_FW_FILENAME);
        return EXIT_FAILURE;
    }
    putc(' ', fp);
    fclose(fp);

    if (remove(CLASS_FW_FILENAME) == -1) {
        log_loc("FAIL: RemoveAllClasses Remove EXIT -1 "CLASS_FW_FILENAME);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

/**
 * Search and destroy on spec line on file and delete it
 * @param com
 * @param file
 * @return
 */
int qos_removeOneClass(char *com, char *file) {
    FILE *fp;
    FILE *tp = fopen(CLASS_PERSITENT_FILENAME"/.tmp.txt", "w");
    char *line = NULL;

    size_t len = 0;

    if (!(fp = fopen(file, "r"))) {
        log_loc("Cannot open file");
        return -1;
    }

    int posL = 0;

    while (getline(&line, &len, fp) != -1) {
        // If there is a iptables command reverse it
        if (strcmp(line, com) == 0 && posL == 0 && strstr(line, "iptables")) {
            line[20] = 'D';
            if (system(line) != 0) {
                log_loc("FAIL: System rev Call fail: ");
                log_loc(line);
            }
            posL++;
        }
        // If there is a end: ...
        else if(line[0] == 'e' && strcmp(line, com) == 0)
            printf("END: line");
        // If there is a id: ...
        else if (line[1] == 'd' && strcmp(line, com) == 0)
            printf("ID: line");
        // It have to be there so write out
        else
            fwrite(line, 1, strlen(line), tp);
    }

    fclose(fp);
    fclose(tp);

    if (remove(file) == -1) {
        return -1;
    }

    // Make tmp to perm file to have a new actual file
    if (!(rename(CLASS_PERSITENT_FILENAME"/.tmp.txt", file))) {
        return -1;
    }

    log_loc("SUCCESS: Remove one ExecLine");

    return 0;
}

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