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

A struct out of timehandler.h for IPC named shm_data is used to avoid doubled starts.
It contains two PIDs, the mother and child Process, if existing. And binary for indicating whether time process is started.
Both side mother and child can handle the data in it.
So if no child existing a child handler will be started. Now timehandler.c will be entered. On this side before a fork spawns, the IPC memory will be entered. After this a fork will be spawned.

    if (fork() == 0) {
    ...
    if (!procom->check)
        return;

    procom->child = getpid();

And there is a check for an existing already. It's named procom->check. And the child PID will be collected. So if there is a need to kill it will be dumped to log.

Now the check loop starts...
