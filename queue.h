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

#ifndef __QOS_QUEUE_HAL_H__
#define __QOS_QUEUE_HAL_H__

#include <net/if.h>

#define QUEUE_MAX_TC 16

enum queue_alg { QUEUE_ALG_SP, QUEUE_ALG_WRR };

struct qos_queue
{
    // Interface name
    char device_name[IFNAMSIZ];
    // tc algorithm: QUEUE_ALG_SP (strict priority) or QUEUE_ALG_WRR (weighted
    // round robin)
    int alg;
    // Queue priority: lower number -> higher priopity
    unsigned priority;
    // Queue weight for QUEUE_ALG_WRR algorithms
    int weight;
    // Queue rate in kbps
    unsigned shaping_rate;
    // Number of elements in class_list
    unsigned class_size;
    // List of traffic classes related to the queue
    int class_list[QUEUE_MAX_TC];
};

// Adds queue & shaping
int qos_addQueue(int index, struct qos_queue *queue);
// Removes ALL queues & shaping
int qos_removeQueue(struct qos_queue *queue);

#endif
