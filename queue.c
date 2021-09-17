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

#define QUEUE_DEFAULT_BANDWIDTH 2
#define QUEUE_TOTAL_WEIGHT 12
#define QUEUE_TRAFFIC_CLASS_MASK 0xFF
#define QUEUE_MAX 8
#define QUEUE_DEFAULT_CEIL 20
#define QUEUE_DEFAULT_BE_RATE 1

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
        sprintf(buf, "tc qdisc add dev %s root handle 1:0 htb default 18", queue->device_name);

        if (system(buf))
        {
            printf("Execution failed: [%s]\n", buf);
            return -1;
        }

        sprintf(buf, "tc class add dev %s parent 1:0 classid 1:1 htb rate %uMbit",
            queue->device_name, shaping_rate);

        if (system(buf))
        {
            printf("Execution failed: [%s]\n", buf);
            return -1;
        }

        sprintf(buf, "tc class add dev %s parent 1:1 classid 1:18 htb prio "
            "7 rate %uMbit ceil %uMbit", queue->device_name, QUEUE_DEFAULT_BE_RATE,
            QUEUE_DEFAULT_CEIL);

        if (system(buf))
        {
            printf("Execution failed: [%s]\n", buf);
            return -1;
        }

        sprintf(buf, "tc qdisc add dev %s parent 1:18 sfq" , queue->device_name);

        if (system(buf))
        {
            printf("Execution failed: [%s]\n", buf);
            return -1;
        }

        printf("Added initial classes to device %s\n",  queue->device_name);
    }

    sprintf(buf, "tc class add dev %s parent 1:1 classid 1:1%u htb prio "
        "%u rate %uMbit ceil %uMbit", queue->device_name, queue->priority,
        queue->priority - 1, shaping_rate, QUEUE_DEFAULT_CEIL);

    if (system(buf))
    {
        printf("Execution failed: [%s]\n", buf);
        return -1;
    }

    sprintf(buf, "tc qdisc add dev %s parent 1:1%u sfq" , queue->device_name,
        queue->priority);

    if (system(buf))
    {
        printf("Execution failed: [%s]\n", buf);
        return -1;
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
