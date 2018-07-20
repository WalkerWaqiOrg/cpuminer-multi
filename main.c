#include "cpuminer_lib.h"
#include <stdio.h>
#include "miner.h"

extern int start_miner_internal(int argc, char *argv[]);

int main(int argc, char *argv[]) {
    return start_miner_internal(argc, argv);
}
