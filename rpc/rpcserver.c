/**
 * References:
 *
 * http://www.cs.rutgers.edu/~pxk/417/notes/sockets/udp.html
 * http://stackoverflow.com/questions/9778806/serializing-a-class-with-a-pointer-in-c
 * http://stackoverflow.com/questions/504810/how-do-i-find-the-current-machines-full-hostname-in-c-hostname-and-domain-info
 *
 * Coding Style:
 *
 * http://www.cs.swarthmore.edu/~newhall/unixhelp/c_codestyle.html
 */

#include "cpuminer-config.h"
#include <stdio.h>
#include "rpc_types.h"
#include <stdlib.h>
#include "miner.h"

int ret_int;
return_type r;

return_type stop_rpc(const int nparams, arg_type* a) {
    exit(0);
}

return_type get_num_processors_rpc(const int nparams, arg_type* a) {
    if(nparams != 0) {
        /* Error! */
        r.return_val = NULL;
        r.return_size = 0;
        return r;
    }
    ret_int = get_num_processors();
    r.return_val = (void *)(&ret_int);
    r.return_size = sizeof(int);

    return r;
}

void start_rpc_server() {
    register_procedure("stop", 0, stop_rpc);
    register_procedure("get_num_processors", 0, get_num_processors_rpc);

    launch_server();
}
