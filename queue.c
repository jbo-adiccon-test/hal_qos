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
#include "stdlib.h"

#include "queue.h"

#define QUEUE_DEFAULT_BANDWIDTH 20000
#define QUEUE_TOTAL_WEIGHT 12
#define QUEUE_TRAFFIC_CLASS_MASK 0xFF

static int queue_exists =  0;
static int index_wrr = 0;

int qos_addQueue(int index, struct qos_queue *queue)
{
    char buf[512] = {0};
    unsigned shaping_rate = queue->shaping_rate != -1 ? queue->shaping_rate :
        QUEUE_DEFAULT_BANDWIDTH;

    // initial classes
    if (!index && !queue_exists)
    {
        sprintf(buf, "tc qdisc add dev %s root handle 1: prio bands 8 priomap "
            "5 7 7 7 5 7 0 0 5 5 5 5 5 5 5 5", queue->device_name);

        if (system(buf))
        {
            printf("Execution failed: [%s]\n", buf);
            return -1;
        }
        printf("Added initial classes to device %s\n",  queue->device_name);
    }

    if (queue->alg == QUEUE_ALG_SP)
    {
        int curr_index = (index + 1) * 100;

        sprintf(buf, "tc qdisc add dev %s parent 1:%u handle %u htb",
            queue->device_name, queue->priority, curr_index);

        if (system(buf))
        {
            printf("Execution failed: [%s]\n", buf);
            return -1;
        }

        sprintf(buf, "tc class add dev %s parent %u: classid %u:%u htb rate %.2fkbps ceil %2.fkbps",
            queue->device_name, curr_index, curr_index, queue->priority,
            (double)shaping_rate, (double)shaping_rate);

        if (system(buf))
        {
            printf("Execution failed: [%s]\n", buf);
            return -1;
        }

        sprintf(buf, "tc qdisc add dev %s parent %u:%u sfq", queue->device_name,
            curr_index, queue->priority);

        if (system(buf))
        {
            printf("Execution failed: [%s]\n", buf);
            return -1;
        }

        for (unsigned i = 0; i < queue->class_size; i++)
        {
            sprintf(buf, "tc filter add dev %s parent 1: protocol ip prio 1 handle 0x%x/0x%x fw flowid 1:%u",
                queue->device_name, queue->class_list[i], QUEUE_TRAFFIC_CLASS_MASK,
                queue->priority);

            if (system(buf))
            {
                printf("Execution failed: [%s]\n", buf);
                return -1;
            }
        }

        printf("[%d] Added QUEUE_ALG_SP queue to device %s\n", __LINE__, queue->device_name);
    }
    else if (queue->alg == QUEUE_ALG_WRR)
    {
        if (!index_wrr)
        {
            sprintf(buf, "tc qdisc add dev %s parent 1:%u handle 10 htb",
                queue->device_name, index + 1);

            if (system(buf))
            {
                printf("Execution failed: [%s]\n", buf);
                return -1;
            }

            sprintf(buf, "tc class add dev %s parent 10: classid 10:1 htb rate %2.fkbps ceil %.2fkbps",
                queue->device_name, (double)shaping_rate, (double)shaping_rate);

            if (system(buf))
            {
                printf("Execution failed: [%s]\n", buf);
                return -1;
            }
        }

        sprintf(buf, "tc class add dev %s parent 10:1 classid 10:%u htb rate %.2fkbps ceil %.2fkbps",
            queue->device_name, index_wrr + 10, (double)shaping_rate / QUEUE_TOTAL_WEIGHT *
            queue->weight, (double)shaping_rate);

        if (system(buf))
        {
            printf("Execution failed: [%s]\n", buf);
            return -1;
        }

        sprintf(buf, "tc qdisc add dev %s parent 10:%u handle %u: sfq",
            queue->device_name, index_wrr + 10, (index_wrr + 2) * 10);

        if (system(buf))
        {
            printf("Execution failed: [%s]\n", buf);
            return -1;
        }

        for (unsigned i = 0; i < queue->class_size; i++)
        {
            sprintf(buf, "tc filter add dev %s parent 10: protocol ip handle 0x%x/0x%x fw flowid 10:%u",
                queue->device_name, queue->class_list[i], QUEUE_TRAFFIC_CLASS_MASK,
                index_wrr + 10);

            if (system(buf))
            {
                printf("Execution failed: [%s]\n", buf);
                return -1;
            }
        }

        printf("[%d] Added QUEUE_ALG_WRR queue to device %s\n", __LINE__, queue->device_name);
        index_wrr++;
    }

    queue_exists = 1;
    return 0;
}

int qos_removeQueue(struct qos_queue *queue)
{
    char buf[512] = {0};

    if (!queue_exists)
    {
        printf("No active queues\n");
        return 0;
    }

    sprintf(buf, "tc qdisc del dev %s root", queue->device_name);

    if (system(buf))
    {
        printf("Execution failed: [%s]\n", buf);
        return -1;
    }

    printf("Stopped queues on %s\n", queue->device_name);

    index_wrr = 0;
    return 0;
}
