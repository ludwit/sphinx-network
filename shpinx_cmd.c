#include "shpinx.h"

/* address of message destination */
ipv6_addr_t dest_addr;

/* event for sending a message */
event_send sphinx_send;

/* parse user input */
int sphinx_cmd(int argc, char **argv)
{ 
    if (argc == 2) {
        if (strcmp(argv[1], "start") == 0) {
            if (sphinx_pid) {
                puts("sphinx: thread already running");
                return 1;
            }
            if (sphinx_start() < 0) {
                puts("sphinx: can't start server");
                return 1;
            }
            return 0;
        }
        if (strcmp(argv[1], "stop") == 0) {
            if (!sphinx_pid) {
                puts("sphinx: no thread running");
                return 1;
            }
            
            event_t sphinx_stop = { .handler = handle_stop };
            event_post(&sphinx_queue, &sphinx_stop);

            if (thread_kill_zombie(sphinx_pid) != 1) {
                puts("error: can't stop thread");
                return 1;
            }

            sphinx_pid = 0;
            puts("sphinx: thread stopped"); 
            return 0;
        }
    }
    
    if (argc == 4 && strcmp(argv[1], "send") == 0) {

        if (!sphinx_pid) {
            puts("error: sphinx not running\nusage: sphinx start");
            return 1;
        }

        /* parse destinaiton addr */
        if (ipv6_addr_from_buf(&dest_addr, argv[2], strlen(argv[2])) == NULL) {
            puts("error: ipv6 address malformed");
            return 1;
        }

        /* check data length */
        if (strlen(argv[3]) > PAYLOAD_SIZE) {
            printf("error: data input too big\nPAYLOAD_SIZE = %d\n", PAYLOAD_SIZE);
            return 1;
        }

        /* set event for sendig a message */
        sphinx_send = (event_send) {.handler = handle_send, .transmit_count = 0, .dest_addr = dest_addr, .data = argv[3], .data_len = strlen(argv[3])};

        event_post(&sphinx_queue, (event_t *) &sphinx_send);


        return 0;
    }

    puts("sphinx: invalid command");
    puts("usage: sphinx [start|stop]");
    puts("usage: sphinx send <addr> <data>");

    return 1;

}

SHELL_COMMAND(sphinx, "send and receive anonymous messages", sphinx_cmd);