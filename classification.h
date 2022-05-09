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

#pragma once
#ifndef __QOS_CLASSIFICATION_HAL_H__
#define __QOS_CLASSIFICATION_HAL_H__

#include <net/if.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include "timehandler.h"

#define CLASS_MAC_SIZE 18
#define CLASS_CHAIN_NAME_SIZE 16

struct qos_class
{
    // Unique ID
    unsigned id;
    // Traffic class of the rule
    int traffic_class;
    // Chain: PREROUTING, INPUT, FORWARD, OUTPUT, POSTROUTING
    char chain_name[CLASS_CHAIN_NAME_SIZE];
    // DSCP mark value
    int dscp_mark;
    // Input interface
    char iface_in[IFNAMSIZ];
    // Output interface
    char iface_out[IFNAMSIZ];
    // Source IP
    char ip_src_addr[INET6_ADDRSTRLEN];
    // Source IP mask
    int ip_src_mask;
    // Destination IP
    char ip_dst_addr[INET6_ADDRSTRLEN];
    // Destination IP mask
    int ip_dst_mask;
    // Protocol
    int protocol;
    // Start of source port range 
    int port_src_range_start;
    // End of source port range
    int port_src_range_end;
    // Start of destination port range
    int port_dst_range_start;
    // End of destination port range
    int port_dst_range_end;
    // Source mac
    char mac_src_addr[CLASS_MAC_SIZE];
    // --tcp-flags SYN,ACK,FIN,RST ACK except PSH
    int tcp_flags;
    // --tcp-flags ALL PSH
    int tcp_psh;

    char duration[64];

    char alias[255];
};

/**
 * A Type to alloc the qos class in an type
 */
typedef struct {
    const struct qos_class *data;
    size_t size;
    char *str;
} qos_struct;

int qos_addClass(const struct qos_class *param);

int qos_removeAllClasses();

int qos_removeOneClass(char *com, char *file);

int qos_persistClass(const qos_struct *obj);


struct interval {
    time_t cur, end;
    double diff_t;
};
typedef struct interval runtime;


void dur_daemon(const char *fin);
#endif
