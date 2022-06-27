# Intro

This is an in information how to add a queue and how it works. This description shows parts of the API and the functional recepi to construct a cake queue out of hal-qos.

## API
The queue API that connects the ccsp-qos and hal-qos contains two functions. 

    // Adds queue & shaping
    int qos_addQueue(int index, struct qos_queue *queue);
    // Removes ALL queues & shaping
    int qos_removeQueue(struct qos_queue *queue);

obviously addQueue is for add/start a queue. We use cake queueing.
There is a data struct in queue like classification either. 

    struct qos_queue
    {
        // Interface name
        char device_name[IFNAMSIZ];

        unsigned bandwidth;
        char alias[256];

        int class_list[QUEUE_MAX_TC];
    };


