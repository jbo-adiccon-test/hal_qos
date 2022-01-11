/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2021 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/stat.h>
#include <errno.h>

#include "classification.h"

#define CLASS_MARK_CHECK_MASK 0xFFFFFFFF
#define CLASS_RULE_SIZE 255
#define CLASS_SHIFT_QUEUE 0
#define CLASS_SHIFT_COUNTER 8
#define CLASS_SHIFT_FWD 12
#define CLASS_MASK_IPV4 32
#define CLASS_MASK_IPV6 128
#define CLASS_PROTO_TCP 6
#define CLASS_PROTO_UDP 17
#define CLASS_TARGET_MARK "MARK"
#define CLASS_TARGET_DSCP "DSCP"
#define CLASS_TARGET_NAME_SIZE 32
#define CLASS_CMD_SIZE 20
#define CLASS_FW_FILENAME "/tmp/qos_rules.sh"
#define CLASS_FW_RELOAD_FILENAME "/etc/utopia/service.d/firewall_log_handle.sh"
#define CLASS_IPTABLES_MANGLE_CMD "iptables -t mangle"
#define CLASS_IP6TABLES_MANGLE_CMD "ip6tables -t mangle"

#define CLASS_MASK_QUEUE (0xFF << CLASS_SHIFT_QUEUE)
#define CLASS_MASK_COUNTER (0x0F << CLASS_SHIFT_COUNTER)
#define CLASS_MASK_FWD (0xFF << CLASS_SHIFT_FWD)

enum class_table
{
    IPTABLES_IPV4 = (1 << 0),
    IPTABLES_IPV6 = (1 << 1),
};

struct iptables_target
{
    char type[CLASS_TARGET_NAME_SIZE];
    union
    {
        struct
        {
            char action[CLASS_TARGET_NAME_SIZE];
            uint32_t value;
            uint32_t mask;
        } mark;
        struct
        {
            uint32_t value;
        } dscp;
    } obj;
};

static void build_mangle_rule(char *rule, enum class_table table, const char *chain,
    const struct qos_class *param, const struct iptables_target *target)
{
    int len = 0;

    len = snprintf(rule, CLASS_RULE_SIZE, "-A %s", chain);

    if (param->iface_in[0])
        len += snprintf(&rule[len], CLASS_RULE_SIZE - len, " -i %s", param->iface_in);

    if (param->iface_out[0])
        len += snprintf(&rule[len], CLASS_RULE_SIZE - len, " -o %s", param->iface_out);

    if (param->ip_dst_addr[0])
    {
        len += snprintf(&rule[len], CLASS_RULE_SIZE - len, " -d %s", param->ip_dst_addr);

        if ((table == IPTABLES_IPV4 && param->ip_dst_mask > 0 &&
                param->ip_dst_mask < CLASS_MASK_IPV4) ||
                (table == IPTABLES_IPV6 && param->ip_dst_mask > 0 &&
                param->ip_dst_mask < CLASS_MASK_IPV6))
        {
            len += snprintf(&rule[len], CLASS_RULE_SIZE - len, "/%d", param->ip_dst_mask);
        }
    }

    if (param->ip_src_addr[0])
    {
        len += snprintf(&rule[len], CLASS_RULE_SIZE - len, " -s %s", param->ip_src_addr);

        if ((table == IPTABLES_IPV4 && param->ip_src_mask > 0 &&
                param->ip_src_mask < CLASS_MASK_IPV4) ||
                (table == IPTABLES_IPV6 && param->ip_src_mask > 0 &&
                param->ip_src_mask < CLASS_MASK_IPV6))
        {
            len += snprintf(&rule[len], CLASS_RULE_SIZE - len, "/%d", param->ip_src_mask);
        }
    }

    if (param->protocol > 0)
        len += snprintf(&rule[len], CLASS_RULE_SIZE - len, " -p %d", param->protocol);

    if (param->protocol == CLASS_PROTO_TCP || param->protocol == CLASS_PROTO_UDP)
    {
        if (param->port_src_range_start > 0)
        {
            len += snprintf(&rule[len], CLASS_RULE_SIZE - len, " --sport %d",
                param->port_src_range_start);

            if (param->port_src_range_end > param->port_src_range_start)
            {
                len += snprintf(&rule[len], CLASS_RULE_SIZE - len, ":%d",
                    param->port_src_range_end);
            }
        }

        if (param->port_dst_range_start > 0)
        {
            len += snprintf(&rule[len], CLASS_RULE_SIZE - len, " --dport %d",
                param->port_dst_range_start);

            if (param->port_dst_range_end > param->port_src_range_start)
            {
                len += snprintf(&rule[len], CLASS_RULE_SIZE - len, ":%d",
                    param->port_dst_range_end);
            }
        }
    }

    if (param->mac_src_addr[0])
        len += snprintf(&rule[len], CLASS_RULE_SIZE - len, " -m mac --mac-source %s",
            param->mac_src_addr);

    if (param->tcp_flags == 1)
        len += snprintf(&rule[len], CLASS_RULE_SIZE - len, " -p tcp --tcp-flags SYN,ACK,FIN,RST ACK");

    if (param->tcp_psh == 1)
        len += snprintf(&rule[len], CLASS_RULE_SIZE - len, " -p tcp --tcp-flags ALL PSH");

    if (!strcmp(target->type, CLASS_TARGET_MARK))
    {
        if (!strcmp(target->obj.mark.action, "--set-class"))
        {
            len += snprintf(&rule[len], CLASS_RULE_SIZE - len, " -j CLASSIFY %s 1:1%u",
                target->obj.mark.action, param->traffic_class);
        }
    }
    else if (!strcmp(target->type, CLASS_TARGET_DSCP))
        len += snprintf(&rule[len], CLASS_RULE_SIZE - len, " -j DSCP --set-dscp %d", target->obj.dscp.value);
    else
        len += snprintf(&rule[len], CLASS_RULE_SIZE - len, " -j %s", target->type);

    rule[CLASS_RULE_SIZE - 1] = '\0';
    printf("%s\n", rule);
    return;
}

static int add_mangle_rule_str(enum class_table table, const char *rule)
{
    FILE *fp = NULL;
    char add_opt = 'A', del_opt = 'D';
    size_t len = 0;
    char *line = NULL;
    char cmd[CLASS_CMD_SIZE] = CLASS_IPTABLES_MANGLE_CMD;
    char buf[CLASS_RULE_SIZE + 20] = {};

    if (!rule)
    {
        printf("Invalid arguments\n");
        return -1;
    }

    if (table == IPTABLES_IPV6)
        sprintf(cmd, CLASS_IP6TABLES_MANGLE_CMD);

    sprintf(buf, "%s %s\n", cmd, rule);

    if (system(buf))
    {
        printf("Failed to execute [%s]\n", buf);
    }

    //deleting rule before adding to avoid duplicates
    if (buf[strlen(cmd) + 2] == 'N')
    {
        add_opt = 'N';
        del_opt = 'X';
    }

    if (!(fp = fopen(CLASS_FW_FILENAME, "a+")))
    {
        printf("Cannot open "CLASS_FW_FILENAME": %s\n", strerror(errno));
        return -1;
    }

    if (chmod(CLASS_FW_FILENAME, S_IRWXU | S_IRWXG | S_IRWXO))
        printf("Cannot change "CLASS_FW_FILENAME" permissions: %s\n", strerror(errno));

    while (getline(&line, &len, fp) != -1)
    {
        if (strstr(line, buf))
        {
            fclose(fp);
            return 0;
        }
    }

    buf[strlen(cmd) + 2] = del_opt;
    fprintf(fp, "%s", buf);
    buf[strlen(cmd) + 2] = add_opt;
    fprintf(fp, "%s", buf);
    fclose(fp);

    return 0;
}

static int add_mangle_chain(enum class_table table, const char *chain)
{
    char rule[CLASS_RULE_SIZE] = {};

    if (!chain)
    {
        printf("Invalid arguments\n");
        return -1;
    }

    snprintf(rule, CLASS_RULE_SIZE - 1, "-N %s", chain);
    rule[CLASS_RULE_SIZE - 1] = '\0';

    if (add_mangle_rule_str(table, rule))
    {
        printf("Failed to add mangle rule\n");
        return -1;
    }

    return 0;
}

static void init_target(struct iptables_target *target, const char *type)
{
    if (target)
    {
        memset(target, 0, sizeof(*target));

        if (type)
        {
            strncpy(target->type, type, CLASS_TARGET_NAME_SIZE - 1);
            target->type[CLASS_TARGET_NAME_SIZE - 1] = '\0';
        }
    }
}

static void init_target_mark(struct iptables_target *target, uint32_t value, uint32_t mask)
{
    if (target)
    {
        init_target(target, CLASS_TARGET_MARK);
        strncpy(target->obj.mark.action, "--set-class", CLASS_TARGET_NAME_SIZE - 1);
        target->obj.mark.action[CLASS_TARGET_NAME_SIZE - 1] = '\0';
        target->obj.mark.value = value;
        target->obj.mark.mask = mask;
    }
}

static int add_mangle_rule(enum class_table table, const char *chain,
    const struct qos_class *param, const struct iptables_target *target)
{
    char rule[CLASS_RULE_SIZE] = {};

    if (!chain || !param || !target)
    {
        printf("Invalid arguments\n");
        return -1;
    }

    build_mangle_rule(rule, table, chain, param, target);

    rule[CLASS_RULE_SIZE - 1] = '\0';

    if (add_mangle_rule_str(table, rule))
    {
        printf("Failed to add mangle rule\n");
        return -1;
    }

    return 0;
}

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

static int init_rules_with_chain(const struct qos_class *param, uint8_t table)
{
    struct iptables_target target = {};
    char chain_name[CLASS_TARGET_NAME_SIZE] = {};
    uint32_t mark = 0, mask = 0;

    snprintf(chain_name, CLASS_TARGET_NAME_SIZE - 1, "CLASS%d", param->id);
    chain_name[CLASS_TARGET_NAME_SIZE - 1] = '\0';

    if ((table & IPTABLES_IPV4) && add_mangle_chain(IPTABLES_IPV4, chain_name))
    {
        printf("Failed adding mangle chain: %s\n", chain_name);
        return -1;
    }

    if ((table & IPTABLES_IPV6) && add_mangle_chain(IPTABLES_IPV6, chain_name))
    {
        printf("Failed adding mangle chain: %s\n", chain_name);
        return -1;
    }

    if (param->dscp_mark > -1 && param->dscp_mark < 64)
    {
        init_target(&target, CLASS_TARGET_DSCP);
        target.obj.dscp.value = param->dscp_mark;

        if ((table & IPTABLES_IPV4) && add_mangle_rule(IPTABLES_IPV4, chain_name, param, &target))
        {
            printf("Failed adding mangle rule to DSCP\n");
            return -1;
        }

        if ((table & IPTABLES_IPV6) && add_mangle_rule(IPTABLES_IPV6, chain_name, param, &target))
        {
            printf("Failed adding mangle rule to DSCP\n");
            return -1;
        }
    }

    init_target_mark(&target, mark, mask);

    if ((table & IPTABLES_IPV4) && add_mangle_rule(IPTABLES_IPV4, chain_name, param, &target))
    {
        printf("Failed adding mangle rule to mark\n");
        return -1;
    }

    if ((table & IPTABLES_IPV6) && add_mangle_rule(IPTABLES_IPV6, chain_name, param, &target))
    {
        printf("Failed adding mangle rule to mark\n");
        return -1;
    }

    init_target(&target, chain_name);

    if ((table & IPTABLES_IPV4) && add_mangle_rule(IPTABLES_IPV4, param->chain_name, param, &target))
    {
        printf("Failed adding mangle rule to target\n");
        return -1;
    }

    if ((table & IPTABLES_IPV6) && add_mangle_rule(IPTABLES_IPV6, param->chain_name, param, &target))
    {
        printf("Failed adding mangle rule to target\n");
        return -1;
    }

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

int qos_addClass2(const struct qos_class *param)
{
    uint8_t table = 0;

    if (!param)
    {
        printf("qos_addClass failed: bad parameter\n");
        return -1;
    }

    if (get_ip_version(param, &table))
    {
        printf("Failed to get IP version\n");
        return -1;
    }

    if (param->dscp_mark > -1 && param->dscp_mark < 64 && init_rules_with_chain(param, table))
    {
        printf("Failed to init chain\n");
        return -1;
    }
    else
    {
        struct iptables_target target = {};
        uint32_t mark = 0, mask = 0;

        init_target_mark(&target, mark, mask);

        if ((table & IPTABLES_IPV4) && add_mangle_rule(IPTABLES_IPV4,
            param->chain_name, param, &target))
        {
            printf("Failed to add rule\n");
            return -1;
        }

        if ((table & IPTABLES_IPV6) && add_mangle_rule(IPTABLES_IPV6,
                param->chain_name, param, &target))
        {
            printf("Failed to add rule\n");
            return -1;
        }
    }

    if (append_to_fw())
    {
        printf("Failed to set iptables rules via firewall");
        return -1;
    }

    return 0;
}

/**
 * A Type to alloc the qos class in an heap elem
 */
typedef struct
{
    struct qos_class *data;
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

    free(class->data);
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
        //printf("%s --> %lu\n", exec1, strlen(exec1));
        system(exec1);
        free(exec1);

        char *exec2 = (char *) malloc(255);
        snprintf(exec2, 255, "%s -I %s -o %s -m mark --mark 4444 -j DSCP --set-dscp %d", CLASS_IPTABLES_MANGLE_CMD, obj.data->chain_name, obj.data->iface_in, obj.data->dscp_mark);
        exec2 = realloc(exec2, strlen(exec2)* sizeof(char ));
        //printf("%s --> %lu\n", exec2, strlen(exec2));
        system(exec2);
        free(exec2);

        char *exec3 = (char *) malloc(255);
        snprintf(exec3, 255, "%s -I %s -o %s -m state --state ESTABLISHED,RELATED -j CONNMARK --restore-mark", CLASS_IPTABLES_MANGLE_CMD, obj.data->chain_name, obj.data->iface_in);
        exec3 = realloc(exec3, strlen(exec3) * sizeof(char ));
        //printf("%s --> %lu\n", exec3, strlen(exec3));
        system(exec3);
        free(exec3);

        char *exec4 = (char *) malloc(255);
        snprintf(exec4, 255, "%s -I %s -o %s -m state --state NEW -m mac --mac-source %s -j CONNMARK --save-mark", CLASS_IPTABLES_MANGLE_CMD, obj.data->chain_name, obj.data->iface_in, obj.data->mac_src_addr);
        exec4 = realloc(exec4, strlen(exec4) * sizeof(char ));
        //printf("%s --> %lu\n", exec4, strlen(exec4));
        system(exec4);
        free(exec4);

        char *exec5 = (char *) malloc(255);
        snprintf(exec5, 200, "%s -I %s -o %s -m state --state NEW -m mac --mac-source %s -j MARK --set-mark 4444", CLASS_IPTABLES_MANGLE_CMD, obj.data->chain_name, obj.data->iface_in, obj.data->mac_src_addr);
        //printf("%s --> %lu\n", exec5, strlen(exec5));
        system(exec5);
        free(exec5);

        if(!append_to_fw()) {
            printf("Failed to set iptables rules via firewall");
            return -1;
        }
    } else {
        printf("STD QoS Class add");
        //qos_addClass2(param);
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
