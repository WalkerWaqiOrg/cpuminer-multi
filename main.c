#include "cpuminer_lib.h"
#include <stdio.h>
#include "miner.h"
#include "cpuminer_lib.h"

int main(int argc, char *argv[]) {
    start_miner_internal(argc, argv, NULL);
    monitor_miner_exit_internal();
    return 0;
}
