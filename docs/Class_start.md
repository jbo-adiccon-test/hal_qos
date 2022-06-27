# Intro: 

This is an in information how to add an new classification and how it works. This description shows parts of the API and the functionality of the code.

# What do we need?
Simply said, there have to be an RDK workaround and a ccsp-qos modul. Which combines the ccsp-qos core modul and the hal layer to one program in RDK. To make it possible to develope switchable hal layers there is an API from ccsp-qos.  


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

The struct qos_class holds the data for a single classification. this classification is nothing else than a bunch of iptables linked into the firewall, in the RDK case its utopia.

Second struct qos_struct handles data internally. One part is a qos_class from above. 
  
The ccsp-qos modul calls qos_addClass() or qos_removeAllClasses() to communicate with its hal-qos part.

# Where to start?
The hal-qos entrypoint to start/add a classification is qos_addclass() in classification.c. This function gets *param a Pointer of qos_class that holds the data to the information for a classification. First this qos_class gone be integrated into a qos_struct. The *str part stay empty for now and is important later.
  Now the data is in a local shell to handle the expection on the classification.

# Checks and Strings

## Init a building process

After the data fixation, the consistency of data will be checked

    if (
        obj->data->dscp_mark != 0 &&
        obj->data->mac_src_addr[0] != '\0'
    ) {
    log_loc("SUCCESS: AddClass All Classification Comps are there");

For that the DSCP Mark have to be checked for 0. The data field have to be a value from 1 to 64. To handle down and upstream the value have to be 34,36,38. Our tests used 36.
Parallel MAC address is checked for emptiness also.

## File for firewall
Now the firewall file will be prepared. 

    FILE *fp = file_open(CLASS_FW_FILENAME, "r");

    if (fp == NULL) {
        file_touch(CLASS_FW_FILENAME);
        fp = file_open(CLASS_FW_FILENAME, "r");
    }

Opening a file for the firewall.

    #define CLASS_FW_FILENAME "/tmp/qos_rules.sh"

This file is later link to the firewall. If the firewall file isn't there actual, it's gone be constructed. 

## String is power
The firewall file is ready to get feed. Now strings gone be constructed for it.

### Standard string
The kind of string build is always the same, so here is an example:

    /// Alloc space for command
    char *exec1 = (char *) malloc(255);

    /// Set iptables command in exec
    snprintf(exec1, 255, "%s -I %s -o %s -m mark --mark %d -j DSCP --set-dscp %d", CLASS_IPTABLES_MANGLE_CMD,
                 IP4POSTROUTING, WAN_IFACE, IP4_FIRE_MARK, obj->data->dscp_mark);
    /// Realloc space
    exec1 = realloc(exec1, strlen(exec1) * sizeof(char));

    if (file_contain(add_n(exec1), fp) == EXIT_SUCCESS) {

        if(exec_run(del_n(exec1)) != 0)
                log_loc("FAIL: system exec1");
            else
                log_loc("SUCCESS: system exec1");

        file_close(fp);
        file_write(CLASS_FW_FILENAME, "a", add_n(exec1));
        fp = file_open(CLASS_FW_FILENAME, "r");
    }

First a string or char array will be defined by allocating space. After this the needed iptables command is concated out of the qos_class data and constance we defined before like content of datastruct_params.h.

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

When the string is ready, a reallocation follows. To avoid double entries, the file gone be checked for existence already. If there is no string like this. The iptables command will be executed, to get an effect emidatly. And it will be written to firewall file. All string are build like this 12 times in a row 

    iptables -t mangle -I postrouting_qos -o $IFWAN -m mark --mark 4444 -j DSCP --set-dscp 36
    iptables -t mangle -I postrouting_qos -o $IFLAN -m mark --mark 4444 -j DSCP --set-dscp 36
    iptables -t mangle -I postrouting_qos -o $IFLAN -m state --state ESTABLISHED,RELATED -j CONNMARK --restore-mark
    iptables -t mangle -I prerouting_qos -i $IFLAN -m mac --mac-source $PRIOMAC -j DSCP --set-dscp 36
    iptables -t mangle -I prerouting_qos -i $IFLAN -m state --state NEW -m mac --mac-source $PRIOMAC -j CONNMARK --save-mark
    iptables -t mangle -I prerouting_qos -i $IFLAN -m state --state NEW -m mac --mac-source $PRIOMAC -j MARK --set-mark 4444
    ip6tables -t mangle -I postrouting_qos -o $IFWAN -m mark --mark 4444 -j DSCP --set-dscp 36
    ip6tables -t mangle -I postrouting_qos -o $IFLAN -m mark --mark 4444 -j DSCP --set-dscp 36
    ip6tables -t mangle -I postrouting_qos -o $IFLAN -m state --state ESTABLISHED,RELATED -j CONNMARK --restore-mark
    ip6tables -t mangle -I prerouting_qos -i $IFLAN -m mac --mac-source $PRIOMAC -j DSCP --set-dscp 36
    ip6tables -t mangle -I prerouting_qos -i $IFLAN -m state --state NEW -m mac --mac-source $PRIOMAC -j CONNMARK --save-mark
    ip6tables -t mangle -I prerouting_qos -i $IFLAN -m state --state NEW -m mac --mac-source $PRIOMAC -j MARK --set-mark 4444

### Handle strings
Obviously there are two kinds of iptables. The difference of IPv4 and IPv6 isn't interesting at the moment. More interesting is to spit in iptables for all classifications, means these are always the same. And the second kind which classification for real per MAC address. 
This one we save into qos_struct->str. 

    /// Organize String for class
    ulong l = strlen(exec4) + strlen(exec5) + strlen(exec9) + strlen(exec10);
    char *concat = malloc(l + 5);
    snprintf(concat, l + 5, "%s\n%s\n%s\n%s", exec4, exec5, exec9, exec10);
    obj->str = concat;

    if ( ex4 == 1 && ex5 == 1 && ex9 == 1 && ex10 == 1) {
        log_loc("SUCCESS: AddClass All rules are ready to add...");
        file_write_text(CLASS_FW_FILENAME,"a",obj->str, "\n");
    }

After this firewall file will be written.  
And a file for the classification information and expiration will be written containing the important iptables and expiration infos.

    qos_ExpirationClass(obj);

Now the time phase starts, read in the section for this.

At the end, the real firewall linkage have to be done, for this add a line to utopia firewall.


    /// Integrate qos-firewall file into firewall
    fp = file_open(CLASS_FW_RELOAD_FILENAME, "r");
    if (file_contain(CLASS_FW_FILENAME, fp) == EXIT_SUCCESS) {
    file_close(fp);
      if (file_write(CLASS_FW_RELOAD_FILENAME, "a", add_n(CLASS_FW_FILENAME)) == EXIT_FAILURE) {
        log_loc("FAIL: AddClass set iptables rules via firewall");
        return EXIT_FAILURE;
      } else
        log_loc("SUCCESS: AddClass Firewall Utopia entry done");
      } else
        log_loc("INFO: AddClass Firewall is set up before");

      if (chmod(CLASS_FW_FILENAME, S_IRWXU | S_IRWXG | S_IRWXO) != 0)
        log_loc("FAIL: Cannot change permissions");
      } else {
        log_loc("FAIL: AddClass Not right comps");
    }

It's really important to add the right permissions to the firewall file.