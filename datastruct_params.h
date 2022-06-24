//
// Created by limberg on 20.06.2022.
//
/**
 * A Header to define Information for iptables calls
 * Those are hard coded to compile time, which means they have to be known
 */

#ifndef HAL_QOS_DATASTRUCT_PARAMS_H
#define HAL_QOS_DATASTRUCT_PARAMS_H

// Chains of iptables
#define IP4POSTROUTING      "postrouting_qos"
#define IP4PREROUTING       "prerouting_qos"
#define IP6POSTROUTING      "postrouting_qos"
#define IP6PREROUTING       "PREROUTING"

// Interfaces for LAN/WAN Interfaces
#define WAN_IFACE           "erouter0"
#define LAN_IFACE           "brlan0"

#define IP4_FIRE_MARK       4444
#define IP6_FIRE_MARK       4444

#endif //HAL_QOS_DATASTRUCT_PARAMS_H
