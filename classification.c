//
// Created by limberg on 12.01.2022.
//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/stat.h>
#include <errno.h>

#include "classification.h"

#define CLASS_MASK_IPV4 32
#define CLASS_MASK_IPV6 128

#define CLASS_FW_FILENAME "/tmp/qos_rules.sh"
#define CLASS_FW_DEBUG "/home/tester/qos_rules.sh"
#define CLASS_FW_RELOAD_FILENAME "/etc/utopia/service.d/firewall_log_handle.sh"
#define CLASS_FW_RELOAD_DEBUG "/home/tester/firewall_log_handle.sh"
#define CLASS_IPTABLES_MANGLE_CMD "iptables -t mangle"

enum class_table
{
    IPTABLES_IPV4 = (1 << 0),
    IPTABLES_IPV6 = (1 << 1),
};

/**
 * If not exsists append qos-firewall file to utopia firewall
 * @return 0 SUCCESS -1 FAIL
 */
static int append_to_fw()
{
    FILE *fp;
    char *line = NULL;
    size_t len = 0;

    if (!(fp = fopen(CLASS_FW_RELOAD_FILENAME, "a+")))
    {
        printf("Cannot open file "CLASS_FW_RELOAD_FILENAME": %s\n", strerror(errno));
        return -1;
    }

    while (getline(&line, &len, fp) != -1)
    {
        if (strstr(line, CLASS_FW_FILENAME))
            return 0;
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
static int add_mangle_rule_str(enum class_table table, const char *rule)
{
    FILE *fp = NULL;
    char add_opt = (char) 'I';
    //char del_opt = (char) 'X';
    size_t len = 0;
    char *line = NULL;

    /// Delete all classes before
    qos_removeAllClasses();

    if (!rule)
    {
        printf("Invalid arguments\n");
        return -1;
    }

    /// deleting rule before adding to avoid duplicates
    if (!(fp = fopen(CLASS_FW_FILENAME, "a+")))
    {
        printf("Cannot open "CLASS_FW_FILENAME": %s\n", strerror(errno));
        return -1;
    }

    /// Check file permissions
    if (chmod(CLASS_FW_FILENAME, S_IRWXU | S_IRWXG | S_IRWXO))
        printf("Cannot change "CLASS_FW_FILENAME" permissions: %s\n", strerror(errno));

    while (getline(&line, &len, fp) != -1)
    {
        if (strstr(line, rule))
        {
            fclose(fp);
            return 0;
        }
    }

    /// alloc space for rule command
    char *tmp = (char *) malloc(255);
    char *exec = (char *) malloc(255);
    strcpy(tmp, rule);
    /// append newline
    snprintf(exec, strlen(tmp) + 5,"%s\n", tmp);
    /// realloc space for exec
    exec = realloc(exec, strlen(exec)* sizeof( char ));

    exec[20] = add_opt;
    fprintf(fp, "%s", exec);

    /// run command in shell
    if (system(exec))
    {
        printf("Failed to execute [%s]\n", exec);
    }

    free(tmp);
    free(exec);
    fclose(fp);

    return 0;
}

/**
 * A Type to alloc the qos class in an type
 */
typedef struct
{
    const struct qos_class *data;
    size_t size;
} qos_struct;

/**
 * Allocates the data of qos_class
 * @param class
 * @return qos_struct of class
 */
qos_struct initQosClass(const struct qos_class *class)
{

    qos_struct *data = malloc(sizeof(qos_struct));

    data->size = sizeof(qos_struct);
    data->data = malloc(sizeof(struct qos_class));
    data->data = class;
    return *data;
}

/**
 * Sets the space free of qos_struct
 * @param class
 * @return 0 SUCCESS -1 FAIL
 */
int dealloc_testclass(qos_struct *class)
{
    if(!class)
        return -1;

    free(class);
    return 0;
}

/**
 * Test main func with a debug struct in main to add an set to add (pseudo) classification
 * @return 0 SUCCESS -1 FAIL
 */
int main()
{
    struct qos_class *test_class = malloc(sizeof(struct qos_class));

    test_class->port_dst_range_start = -1;
    test_class->port_dst_range_end = -1;
    test_class->port_src_range_start = -1;
    test_class->port_src_range_end = -1;

    test_class->protocol = -1;

    test_class->traffic_class = 2;
    strcpy(test_class->chain_name, "postrouting_qos");
    strcpy(test_class->iface_out, "erouter0");
    strcpy(test_class->iface_in, "brlan0");
    test_class->dscp_mark = 32;

    strcpy(test_class->mac_src_addr, "00:e0:4c:81:c8:40");

    if(qos_addClass(test_class) == -1)
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
int qos_addClass(const struct qos_class *param)
{
    qos_struct obj = initQosClass(param);

    printf("Parameters: %d, %s, %d", obj.data->dscp_mark, obj.data->mac_src_addr, obj.data->traffic_class);

    if (obj.data->port_src_range_end == -1 &&
        obj.data->port_src_range_start == -1 &&
        obj.data->port_dst_range_end == -1 &&
        obj.data->port_dst_range_start == -1 &&
        obj.data->protocol == -1 &&
        obj.data->traffic_class != 0 &&
        obj.data->chain_name[0] != '\0' &&
        obj.data->iface_in[0] != '\0' &&
        obj.data->iface_out[0] != '\0' &&
        obj.data->dscp_mark != 0
            )
    {
        printf("NEW mark Categ add");

        /// Alloc space for command
        char *exec1 = (char *) malloc(255);
        /// Set iptables command in exec
        snprintf(exec1, 255, "%s -I %s -o %s -m mark --mark 4444 -j DSCP --set-dscp %d", CLASS_IPTABLES_MANGLE_CMD, obj.data->chain_name, obj.data->iface_out, obj.data->dscp_mark);
        /// Realloc space
        exec1 = realloc(exec1, strlen(exec1)* sizeof(char ));
        printf("%s \n", exec1);
        //system(exec1);
        /// Input exec into firewall and iptables
        add_mangle_rule_str(IPTABLES_IPV4, exec1);
        /// dealloc space
        free(exec1);

        char *exec2 = (char *) malloc(255);
        snprintf(exec2, 255, "%s -I %s -o %s -m mark --mark 4444 -j DSCP --set-dscp %d", CLASS_IPTABLES_MANGLE_CMD, obj.data->chain_name, obj.data->iface_in, obj.data->dscp_mark);
        exec2 = realloc(exec2, strlen(exec2)* sizeof(char ));
        printf("%s \n", exec2);
        add_mangle_rule_str(IPTABLES_IPV4, exec2);
        free(exec2);

        char *exec3 = (char *) malloc(255);
        snprintf(exec3, 255, "%s -I %s -o %s -m state --state ESTABLISHED,RELATED -j CONNMARK --restore-mark", CLASS_IPTABLES_MANGLE_CMD, obj.data->chain_name, obj.data->iface_in);
        exec3 = realloc(exec3, strlen(exec3) * sizeof(char ));
        printf("%s \n", exec3);
        //system(exec3);
        add_mangle_rule_str(IPTABLES_IPV4, exec3);
        free(exec3);

        char *exec4 = (char *) malloc(255);
        snprintf(exec4, 255, "%s -I %s -o %s -m state --state NEW -m mac --mac-source %s -j CONNMARK --save-mark", CLASS_IPTABLES_MANGLE_CMD, obj.data->chain_name, obj.data->iface_in, obj.data->mac_src_addr);
        exec4 = realloc(exec4, strlen(exec4) * sizeof(char ));
        printf("%s \n", exec4);
        //system(exec4);
        add_mangle_rule_str(IPTABLES_IPV4, exec4);
        free(exec4);

        char *exec5 = (char *) malloc(255);
        snprintf(exec5, 200, "%s -I %s -o %s -m state --state NEW -m mac --mac-source %s -j MARK --set-mark 4444", CLASS_IPTABLES_MANGLE_CMD, obj.data->chain_name, obj.data->iface_in, obj.data->mac_src_addr);
        printf("%s \n", exec5);
        //system(exec5);
        add_mangle_rule_str(IPTABLES_IPV4, exec5);
        free(exec5);

        /// Integrate qos-firewall file into firewall
        if(!append_to_fw()) {
            printf("Failed to set iptables rules via firewall");
            return -1;
        }
    } else {
        printf("STD QoS Class add");
    }

    return 0;
}

int qos_removeAllClasses()
{
    if (remove(CLASS_FW_FILENAME) == -1)
    {
        printf("Failed to remove "CLASS_FW_FILENAME": %s", strerror(errno));
        return -1;
    }

    return 0;
}
