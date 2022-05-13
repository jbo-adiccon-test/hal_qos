//
// Created by limberg on 12.01.2022.
//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
//#include <limits.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>

#include "classification.h"

#define CLASS_FW_FILENAME "/tmp/qos_rules.sh"

#define CLASS_FW_RELOAD_FILENAME "/etc/utopia/service.d/firewall_log_handle.sh"
#define CLASS_PERSITENT_FILENAME "/usr/ccsp/qos/class"

#define CLASS_IPTABLES_MANGLE_CMD "iptables -t mangle"


/*
void sig_handler(int signum) {
    pid_t pid = getpid();
    printf("Signal: %u", signum);
    if (signum == SIGINT) {
        pid = getpid();
        kill(pid, SIGINT);
    }
}
*/


/*
enum class_table
{
    IPTABLES_IPV4 = (1 << 0),
    IPTABLES_IPV6 = (1 << 1),
};
*/

/**
 * A Function to check exsistence of string in firewall file
 * @param comp (char *)
 * @return EXIT_SUCCESS, EXIT_FAILURE
 */
static int check_firewall_double(char *comp) {
    FILE *fp;
    char *line = NULL;
    size_t len = 0;

    if (!(fp = fopen(CLASS_FW_FILENAME, "a+"))) {
        printf("Cannot open file "CLASS_FW_FILENAME": %s\n", strerror(errno));
        return -1;
    }

    while (getline(&line, &len, fp) != -1) {
        if (strstr(line, comp)) {
            fclose(fp);
            return EXIT_FAILURE;
        }
    }

    fclose(fp);
    return EXIT_SUCCESS;
}

/**
 * If not exsists append qos-firewall file to utopia firewall
 * @return 0 SUCCESS -1 FAIL
 */
static int append_to_fw() {
    FILE *fp;
    char *line = NULL;
    size_t len = 0;

    if (!(fp = fopen(CLASS_FW_RELOAD_FILENAME, "a+"))) {
        printf("Cannot open file "CLASS_FW_RELOAD_FILENAME": %s\n", strerror(errno));
        return -1;
    }

    while (getline(&line, &len, fp) != -1) {
        if (strstr(line, CLASS_FW_FILENAME)) {
            fclose(fp);
            return 0;
        }
    }

    fprintf(fp, "%s\n", CLASS_FW_FILENAME);
    fclose(fp);
    return 0;
}

/**
 * Here the magic takes place. The function deletes all classes for qos. After that the firewall file is opened.
 * The files will be checked and terminates the func if data has no integrity(should be empty if there is only one instance).
 * Write the file and run command
 * @param table
 * @param rule
 * @return status 0 SUCCESS -1 FAIL
 */
static int add_mangle_rule_str(const char *rule) {
    FILE *fp;
    //char *str = rule;

    if (!rule) {
        printf("Invalid arguments\n");
        return -1;
    }

    /// deleting rule before adding to avoid duplicates
    if (!(fp = fopen(CLASS_FW_FILENAME, "a+"))) {
        printf("Cannot open "CLASS_FW_FILENAME": %s\n", strerror(errno));
        return -1;
    }

    /// Check file permissions
    if (chmod(CLASS_FW_FILENAME, S_IRWXU | S_IRWXG | S_IRWXO))
        printf("Cannot change "CLASS_FW_FILENAME" permissions: %s\n", strerror(errno));

    printf("Add lines to firewall: %s", rule);
    fwrite(rule, 1, strlen(rule), fp);
    fclose(fp);

    return 0;
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
    strcpy(test_class1->duration, "16:00:00-09.05.2022");

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
 * A simple, quiet indicator for run a command status after execution
 * @param str
 * @return
 */
int exec_run(char *str) {
    if (system(str))
        return EXIT_SUCCESS;
    else
        return EXIT_FAILURE;
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

    printf("Parameters: %s, %s --> %s, CLASS: %d, MARK: %d", obj->data->alias, obj->data->mac_src_addr,
           obj->data->ip_dst_addr, obj->data->traffic_class, obj->data->dscp_mark);

    // Check for used Data
    if (
            obj->data->chain_name[0] != '\0' &&
            obj->data->iface_in[0] != '\0' &&
            obj->data->iface_out[0] != '\0' &&
            obj->data->dscp_mark != 0 &&
            obj->data->mac_src_addr[0] != '\0'
            ) {
        printf("NEW mark Categ add\n");

        /// Delete all classes before
        //revert_rules();
        //qos_removeAllClasses();

        /// Alloc space for command
        char *exec1 = (char *) malloc(255);
        int  ex4 = 0, ex5 = 0; //ex1 = 0, ex2 = 0, ex3 = 0;

        /// Set iptables command in exec
        snprintf(exec1, 255, "%s -I %s -o %s -m mark --mark 4444 -j DSCP --set-dscp %d", CLASS_IPTABLES_MANGLE_CMD,
                 obj->data->chain_name, obj->data->iface_out, obj->data->dscp_mark);
        /// Realloc space
        exec1 = realloc(exec1, strlen(exec1) * sizeof(char));
        printf("%s \n", exec1);
        if (check_firewall_double(exec1) == EXIT_SUCCESS) {
            system(exec1);
            //ex1 = 1;
        }

        char *exec2 = (char *) malloc(255);
        snprintf(exec2, 255, "%s -I %s -o %s -m mark --mark 4444 -j DSCP --set-dscp %d", CLASS_IPTABLES_MANGLE_CMD,
                 obj->data->chain_name, obj->data->iface_in, obj->data->dscp_mark);
        exec2 = realloc(exec2, strlen(exec2) * sizeof(char));
        printf("%s \n", exec2);
        if (check_firewall_double(exec2) == EXIT_SUCCESS) {
            system(exec2);
            //ex2 = 1;
        }

        char *exec3 = (char *) malloc(255);
        snprintf(exec3, 255, "%s -I %s -o %s -m state --state ESTABLISHED,RELATED -j CONNMARK --restore-mark",
                 CLASS_IPTABLES_MANGLE_CMD, obj->data->chain_name, obj->data->iface_in);
        exec3 = realloc(exec3, strlen(exec3) * sizeof(char));
        printf("%s \n", exec3);
        if (check_firewall_double(exec3) == EXIT_SUCCESS) {
            system(exec3);
            //ex3 = 1;
        }

        char *exec4 = (char *) malloc(255);
        snprintf(exec4, 255,
                 "%s -I prerouting_qos -i %s -m state --state NEW -m mac --mac-source %s -j CONNMARK --save-mark",
                 CLASS_IPTABLES_MANGLE_CMD, obj->data->iface_in, obj->data->mac_src_addr);
        exec4 = realloc(exec4, strlen(exec4) * sizeof(char));
        printf("%s \n", exec4);
        if (check_firewall_double(exec4) == EXIT_SUCCESS) {
            system(exec4);
            ex4 = 1;
        }

        char *exec5 = (char *) malloc(255);
        snprintf(exec5, 255,
                 "%s -I prerouting_qos -i %s -m state --state NEW -m mac --mac-source %s -j MARK --set-mark 4444",
                 CLASS_IPTABLES_MANGLE_CMD, obj->data->iface_in, obj->data->mac_src_addr);
        exec5 = realloc(exec5, strlen(exec5) * sizeof(char));
        printf("%s \n", exec5);
        if (check_firewall_double(exec5) == EXIT_SUCCESS) {
            system(exec5);
            ex5 = 1;
        }

        ulong l = strlen(exec1) + strlen(exec2) + strlen(exec3) + strlen(exec4) + strlen(exec5);
        char *concat = malloc((int) l + 5);

        if (
                ex4 == 1 &&
                ex5 == 1
                ) {
            snprintf(concat, 600, "%s\n%s\n%s\n%s\n%s\n", exec1, exec2, exec3, exec4, exec5);
            obj->str = concat;
            add_mangle_rule_str(obj->str);
        }

        free(exec1);
        free(exec2);
        free(exec3);
        free(exec4);
        free(exec5);

        /// Integrate qos-firewall file into firewall
        if (append_to_fw() == -1) {
            printf("Failed to set iptables rules via firewall");
            return -1;
        }

        if (*obj->data->duration != '\0') {
            //dur_daemon(obj->data->duration);
            qos_persistClass(obj);

            // If there is no checker active
            if (tTime.check != true) {
                duration_check();
            }
        }
        //outoQosClass(obj);
    } else {
        printf("STD QoS Class add");
    }

    return 0;
}

/**
 * Manifest a classification for a longer time.
 * @param obj
 * @return
 */
int qos_persistClass(const qos_struct *obj) {
    FILE *fp;
    char *line = NULL;
    //size_t len = 0;

    char *fname = malloc(256);
    snprintf(fname, 255, CLASS_PERSITENT_FILENAME"/class_%i.dat", obj->data->id);

    if(!remove(fname)) {
        printf("No file %s deletable", fname);
    }

    if (!(fp = fopen(fname, "w"))) {
        printf("Cannot open file "CLASS_PERSITENT_FILENAME": %s\n", strerror(errno));
        return -1;
    }
    line = malloc(256);
    //struct tm t = strtotm(obj->data->duration);
    snprintf(line, 256, "end: %s\n", obj->data->duration);

    // Add the duration string to file
    fwrite(line, 1, strlen(line), fp);
    strcpy(line, "");
    // Add the id of classification to file
    snprintf(line, 256, "id: %i\n", obj->data->id);
    fwrite(line, 1, strlen(line), fp);
    // Add the firewall string
    fwrite(obj->str, 1, strlen(obj->str), fp);
    fclose(fp);
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
        printf("Cannot open file "CLASS_FW_FILENAME": %s\n", strerror(errno));
        return -1;
    }

    while (getline(&line, &len, fp) != -1) {
        line[20] = 'D';
        system(line);
    }
    rewind(fp);
    fclose(fp);

    if (!(fp = fopen(CLASS_FW_FILENAME, "w"))) {
        printf("Cannot open file "CLASS_FW_FILENAME": %s\n", strerror(errno));
        return -1;
    }
    putc(' ', fp);
    fclose(fp);

    if (remove(CLASS_FW_FILENAME) == -1) {
        printf("Failed to remove "CLASS_FW_FILENAME": %s", strerror(errno));
        return -1;
    }

    return 0;
}

/**
 * Search and destroy on spec line on file and delete it
 * @param com
 * @param file
 * @return
 */
int qos_removeOneClass(char *com, char *file) {
    FILE *fp;
    FILE *tp = (fopen(CLASS_PERSITENT_FILENAME"/.tmp.txt", "w")) ? fopen(CLASS_PERSITENT_FILENAME"/.tmp.txt", "w")
                                                                  : NULL;
    char *line = NULL;

    size_t len = 0;

    if (!(fp = fopen(file, "r"))) {
        printf("Cannot open file %s: %s\n", file, strerror(errno));
        return -1;
    }

    int posL = 0;

    while (getline(&line, &len, fp) != -1) {
        // If there is a iptables command reverse it
        if (strcmp(line, com) == 0 && posL == 0 && strstr(line, "iptables")) {
            line[20] = 'D';
            exec_run(line);
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
        printf("Failed to remove %s: %s", file, strerror(errno));
        return -1;
    }

    // Make tmp to perm file to have a new actual file
    rename(CLASS_PERSITENT_FILENAME"/.tmp.txt", file);

    return 0;
}
