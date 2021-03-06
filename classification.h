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

struct qos_class
{
    // Unique ID
    unsigned id;
    // DSCP mark value
    int dscp_mark;
    // Source mac
    char mac_src_addr[CLASS_MAC_SIZE];
    char expiration[64];
   
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
//int qos_removeOneClass(uint id);

int qos_ExpirationClass(const qos_struct *obj);

void log_loc(char *str);

int file_write_text(char *filename, char *mode, char *text, char *delim);
int file_write(char *filename, char *mode, char *line);
int file_touch(char *filename);
int file_remove(const char *filename);
int file_close(FILE *fp);
FILE* file_open(char *filename, char *mode);
int file_contain(char *comp, FILE *fp);
int file_del_text(char *filename, char *text, char *delim);
char * file_read_all(char *filename);

int revert_iptables(char *fname);

char* add_n(char *line);
char* del_n(char *line);
int file_del(char *filename, char *text);
int exec_run(char *str);
#endif
