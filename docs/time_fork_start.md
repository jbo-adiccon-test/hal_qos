# Time communication

## Where to start?

A classification starts in classification.c to handle the time component a time checker is parallel integrated to that. There challenges handling time component properly. First of all, running more than one instance of the fork that handles time.

## Classification starts time

To handle time after the classification.c finished a fork will be started, but there is a need to communicate with its child and later started classification instances. For this IPC shared memory is used. 

    /// IPC shared Memory
    struct shm_data *procom;
    int shmid = shmget(0x1234, 1024, 0666 | IPC_CREAT);
    procom = (struct shm_data *) shmat(shmid, (void *) 0, 0);

    procom->parent = getpid();


