#include "cpuminer_lib.h"
#include <pthread.h>
#include "miner.h"

extern int start_miner_internal(int argc, char *argv[]);
extern void stop_miner_internal();

struct param_t {
    int argc;
    char **argv;
};

struct thr_info *thread = NULL;
struct param_t param;

static void *start_thread(void *userdata) {
    struct param_t *param = (struct param_t *)userdata;
    start_miner_internal(param->argc, param->argv);
    return NULL;
}

int start_miner(int argc, char *argv[]) {
    if (thread) {
        return 1; // already started
    }
    thread = calloc(1, sizeof(thr_info));
    thread->id = 100;
    thread->q = tq_new();

    param.argc = argc;
    param.argv = argv;
    pthread_create(&thread->pth, NULL, start_thread, &param);

    return 0;
}

void stop_miner() {
    if (thread) {
        stop_miner_internal();
        pthread_join(thread->pth, NULL);
        free(thread);
        thread = NULL;
    }
}
