# Checking time for obsolete entries

## Point of view

After the fork of time is started and the need of handling is clarified, the real check loop begins. 
First of all the data we got is a tTime struct of t_time, that holds two tm structs named act_t and tar_t. That symbolises the actual time and the target time.

## The Time procedure

First of all act_t of tTime gets filled and several struct to handle Directory position.

    get_act_time(&tTime.act_t);
    DIR *dp;
    struct dirent *ep;

After that, the directory to classification handling will be opened and pass through.
This path named:

    #define CLASS_PERSITENT_FILENAME "/usr/ccsp/qos/class"

This pass through process means that every file in CLASS_PERSITENT_FILENAME will be checked for actuality except the hidden files (starting with . example: .FILENAME)


    while ((ep = readdir(dp)) != NULL) { // Get all entries in Dir
        char *fname = malloc(512);
        snprintf(fname, 512, "%s/%s", CLASS_PERSITENT_FILENAME, ep->d_name);

The filename will be checked by a time handler function named 

    if (time_handler(fname) == EXIT_SUCCESS)

This function extracts the end time out of the file and pipes it into tar_t. If its end value equals inf no action is needed. Otherwise, the act_t to tar_t will be compared. In case of act_t further than tar_t the classification is obsolete. The function returns EXIT_SUCCESS and classification will be disabled.

    char *str = malloc(512);
    snprintf(str, 512, "%s%i%s", "dmcli eRT setv Device.QoS.Classification.", id,
    ".Enable bool \"false\"");
    exec_run(str);

Now the process tidies up and goes for sleep for a time of 15 seconds. But this time is randomly chosen. 
