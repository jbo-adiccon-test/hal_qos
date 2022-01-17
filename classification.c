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

static int get_ip_version(const struct qos_class *param, uint8_t *table)
{
    struct in_addr tmp4 = {};
    struct in6_addr tmp6 = {};

    if (!param || !table) {
        printf("Invalid input parameters\n");
        return -1;
    }

    if ((!param->ip_src_addr[0] && param->ip_src_mask) ||
        (!param->ip_dst_addr[0] && param->ip_dst_mask))
    {
        printf("Invalid IP parameters\n");
        return -1;
    }

    *table = IPTABLES_IPV4 | IPTABLES_IPV6;

    if (param->ip_src_addr[0])
    {
        if (inet_pton(AF_INET, param->ip_src_addr, &tmp4) == 1)
        {
            if (param->ip_src_mask < 0 || param->ip_src_mask > CLASS_MASK_IPV4)
            {
                printf("Invalid IP mask: %d\n", param->ip_src_mask);
                return -1;
            }

            *table &= ~IPTABLES_IPV6;
        }
        else if (inet_pton(AF_INET6, param->ip_src_addr, &tmp6) == 1)
        {
            if (param->ip_src_mask < 0 || param->ip_src_mask > CLASS_MASK_IPV6)
            {
                printf("Invalid IP mask: %d\n", param->ip_src_mask);
                return -1;
            }
            *table &= ~IPTABLES_IPV4;
        }
        else
        {
            printf("Invalid IP address: %s\n", param->ip_src_addr);
            return -1;
        }
    }

    if (param->ip_dst_addr[0])
    {
        if (inet_pton(AF_INET, param->ip_dst_addr, &tmp4) == 1)
        {
            if (param->ip_dst_mask < 0 || param->ip_dst_mask > CLASS_MASK_IPV4)
            {
                printf("Invalid IP mask: %d\n", param->ip_dst_mask);
                return -1;
            }

            *table &= ~IPTABLES_IPV6;
        }
        else if (inet_pton(AF_INET6, param->ip_dst_addr, &tmp6) == 1)
        {
            if (param->ip_dst_mask < 0 || param->ip_dst_mask > CLASS_MASK_IPV6)
            {
                printf("Invalid IP mask: %d\n", param->ip_dst_mask);
                return -1;
            }

            *table &= ~IPTABLES_IPV4;
        }
        else
        {
            printf("Invalid IP address: %s\n", param->ip_dst_addr);
            return -1;
        }
    }

    if (!(*table & IPTABLES_IPV4) && !(*table & IPTABLES_IPV6))
        return -1;

    return 0;
}

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

static int add_mangle_rule_str(enum class_table table, const char *rule)
{
    FILE *fp = NULL;
    char add_opt = (char) 'I';
    char del_opt = (char) 'X';
    size_t len = 0;
    char *line = NULL;

    if (!rule)
    {
        printf("Invalid arguments\n");
        return -1;
    }

    if (system(rule))
    {
        printf("Failed to execute [%s]\n", rule);
    }

    //deleting rule before adding to avoid duplicates
    if (!(fp = fopen(CLASS_FW_FILENAME, "a+")))
    {
        printf("Cannot open "CLASS_FW_FILENAME": %s\n", strerror(errno));
        return -1;
    }

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

    char *tmp = (char *) malloc(255);
    strcpy(tmp, rule);

    tmp[20] = del_opt;
    fprintf(fp, "%s", tmp);

    tmp[20] = add_opt;
    fprintf(fp, "%s", tmp);

    free(tmp);
    fclose(fp);

    return 0;
}

/**
 * A Type to alloc the qos class in an heap elem
 */
typedef struct
{
    const struct qos_class *data;
    size_t size;
} qos_struct;

/**
 * Allocates the data of qos_class
 * @param class
 * @return
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
 * @return
 */
int dealloc_testclass(qos_struct *class)
{
    if(!class)
        return -1;

    free(class);
    return 0;
}

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

        char *exec1 = (char *) malloc(255);
        snprintf(exec1, 255, "%s -I %s -o %s -m mark --mark 4444 -j DSCP --set-dscp %d", CLASS_IPTABLES_MANGLE_CMD, obj.data->chain_name, obj.data->iface_out, obj.data->dscp_mark);
        exec1 = realloc(exec1, strlen(exec1)* sizeof(char ));
        printf("%s \n", exec1);
        //system(exec1);
        add_mangle_rule_str(IPTABLES_IPV4, exec1);
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
