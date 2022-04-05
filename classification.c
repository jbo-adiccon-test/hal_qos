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
//#define CLASS_FW_FILENAME "/home/artemisvenari/Codes/Work/qos_rules.sh"

#define CLASS_FW_RELOAD_FILENAME "/etc/utopia/service.d/firewall_log_handle.sh"
//#define CLASS_FW_RELOAD_FILENAME "/home/artemisvenari/Codes/Work/firewall_log_handle.sh"

//#define CLASS_DATA_ALLOC "/home/artemisvenari/Codes/Work/structure.dat"

#define CLASS_IPTABLES_MANGLE_CMD "iptables -t mangle"

void sig_handler(int signum) {
    pid_t pid = getpid();
    printf("Signal: %u", signum);
    if (signum == SIGINT) {
        pid = getpid();
        kill(pid, SIGINT);
    }
}

void dur_daemon(const char *fin) {
    //runtime t;
    int range = atoi(fin);

    //if (!time(&t.cur)){
    //    perror("TIME fail");
    //}

    if (fork() == 0) {
        perror("time_daemon");

        signal(SIGINT, sig_handler);


        //time(&t.end);
        //t.diff_t = difftime(t.cur, t.end);
        sleep(range);
        qos_removeAllClasses();
        sig_handler(SIGINT);
    }
}

/*
enum class_table
{
    IPTABLES_IPV4 = (1 << 0),
    IPTABLES_IPV6 = (1 << 1),
};
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
 * Runs iptables delete commands from qos-rules
 * @return SUCCESS 0 FAIL -1
 */
/*
static int revert_rules(){
   FILE *fp = NULL;
   size_t len = 0;
   char *line = NULL;
   /// deleting rule before adding to avoid duplicates
   if (!(fp = fopen(CLASS_FW_FILENAME, "a+")))
   {
       printf("Cannot open "CLASS_FW_FILENAME": %s\n", strerror(errno));
       return -1;
   }
   /// Check file permissions
   if (chmod(CLASS_FW_FILENAME, S_IRWXU | S_IRWXG | S_IRWXO))
       printf("Cannot change "CLASS_FW_FILENAME" permissions: %s\n", strerror(errno));
   while (getline(&line, &len, fp) != -1) {
       /// run command in shell
       line[20] = 'D';
       if (system(line)) {
           printf("Failed to execute [%s]\n", line);
       }
   }
   fclose(fp);
   return 0;
}
*/

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

    //fprintf(fp, "%s", rule);
    fwrite(rule, 1, strlen(rule), fp);


    /// run command in shell
    //if (system(exec))
    //{
    //    printf("Failed to execute [%s]\n", exec);
    //}

    fclose(fp);

    return 0;
}

/**
 * A Type to alloc the qos class in an type
 */
typedef struct {
    const struct qos_class *data;
    size_t size;
    char *str;
} qos_struct;

int qos_removeOneClass() {
    printf("To Remove One Class... TESTTESTTESTTESTTESTTEST");
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

    test_class1->port_dst_range_start = -1;
    test_class1->port_dst_range_end = -1;
    test_class1->port_src_range_start = -1;
    test_class1->port_src_range_end = -1;
    test_class1->protocol = -1;
    test_class1->traffic_class = 2;
    strcpy(test_class1->chain_name, "postrouting_qos");
    strcpy(test_class1->iface_out, "erouter0");
    strcpy(test_class1->iface_in, "brlan0");
    test_class1->dscp_mark = 32;
    strcpy(test_class1->mac_src_addr, "00:e0:4c:81:c8:41");
    strcpy(test_class1->duration, "50");

    test_class2->port_dst_range_start = -1;
    test_class2->port_dst_range_end = -1;
    test_class2->port_src_range_start = -1;
    test_class2->port_src_range_end = -1;
    test_class2->protocol = -1;
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

    printf("Parameters: %s, %s --> %s, CLASS: %d, MARK: %d", obj->data->alias, obj->data->ip_src_addr,
           obj->data->ip_dst_addr, obj->data->traffic_class, obj->data->dscp_mark);

    if (obj->data->port_src_range_end == -1 &&
        obj->data->port_src_range_start == -1 &&
        obj->data->port_dst_range_end == -1 &&
        obj->data->port_dst_range_start == -1 &&
        obj->data->protocol == -1 &&
        obj->data->traffic_class != 0 &&
        obj->data->chain_name[0] != '\0' &&
        obj->data->iface_in[0] != '\0' &&
        obj->data->iface_out[0] != '\0' &&
        obj->data->dscp_mark != 0
            ) {
        printf("NEW mark Categ add\n");

        /// Delete all classes before
        //revert_rules();
        //qos_removeAllClasses();

        /// Alloc space for command
        char *exec1 = (char *) malloc(255);
        int ex1 = 0, ex2 = 0, ex3 = 0, ex4 = 0, ex5 = 0;

        /// Set iptables command in exec
        snprintf(exec1, 255, "%s -I %s -o %s -m mark --mark 4444 -j DSCP --set-dscp %d", CLASS_IPTABLES_MANGLE_CMD,
                 obj->data->chain_name, obj->data->iface_out, obj->data->dscp_mark);
        /// Realloc space
        exec1 = realloc(exec1, strlen(exec1) * sizeof(char));
        printf("%s \n", exec1);
        if (check_firewall_double(exec1) == EXIT_SUCCESS) {
            system(exec1);
            ex1 = 1;
        }

        char *exec2 = (char *) malloc(255);
        snprintf(exec2, 255, "%s -I %s -o %s -m mark --mark 4444 -j DSCP --set-dscp %d", CLASS_IPTABLES_MANGLE_CMD,
                 obj->data->chain_name, obj->data->iface_in, obj->data->dscp_mark);
        exec2 = realloc(exec2, strlen(exec2) * sizeof(char));
        printf("%s \n", exec2);
        if (check_firewall_double(exec2) == EXIT_SUCCESS) {
            system(exec2);
            ex2 = 1;
        }

        char *exec3 = (char *) malloc(255);
        snprintf(exec3, 255, "%s -I %s -o %s -m state --state ESTABLISHED,RELATED -j CONNMARK --restore-mark",
                 CLASS_IPTABLES_MANGLE_CMD, obj->data->chain_name, obj->data->iface_in);
        exec3 = realloc(exec3, strlen(exec3) * sizeof(char));
        printf("%s \n", exec3);
        if (check_firewall_double(exec3) == EXIT_SUCCESS) {
            system(exec3);
            ex3 = 1;
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
                ex1 == 1 &&
                ex2 == 1 &&
                ex3 == 1 &&
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
        free(concat);

        /// Integrate qos-firewall file into firewall
        if (append_to_fw() == -1) {
            printf("Failed to set iptables rules via firewall");
            return -1;
        }

        if (*obj->data->duration != '\0') {
            dur_daemon(obj->data->duration);
        }
        //outoQosClass(obj);
    } else {
        printf("STD QoS Class add");
    }

    return 0;
}

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