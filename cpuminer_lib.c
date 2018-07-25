#include "cpuminer_lib.h"
#include <pthread.h>
#include <unistd.h>
#include "miner.h"

struct thr_info *thread = NULL;

static void *monitor_thread(void *userdata) {
    monitor_miner_exit_internal();
    return NULL;
}

int start_miner(int argc, char *argv[], MINER_STATE_CHANGED miner_state_changed_func) {
    if (thread) {
        return 1; // already started
    }

    int ret = start_miner_internal(argc, argv, miner_state_changed_func);
    if (ret) {
        applog(LOG_INFO, "Start miner failed!");
        stop_miner_internal();
        monitor_miner_exit_internal();
        return ret;
    }

    thread = calloc(1, sizeof(thr_info));
    thread->id = 100;
    thread->q = tq_new();
    ret = pthread_create(&thread->pth, NULL, monitor_thread, NULL);

    return ret;
}

void stop_miner() {
    if (thread) {
        stop_miner_internal();
        pthread_join(thread->pth, NULL);
        free(thread);
        thread = NULL;
    }
}

int get_num_processors() {
    int result = 1;
#if defined(WIN32)
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	result = sysinfo.dwNumberOfProcessors;
#elif defined(_SC_NPROCESSORS_CONF)
	result = sysconf(_SC_NPROCESSORS_CONF);
#elif defined(CTL_HW) && defined(HW_NCPU)
	int req[] = {CTL_HW, HW_NCPU};
	size_t len = sizeof(num_processors);
	sysctl(req, 2, &num_processors, &len, NULL, 0);
#else
	result = 1;
#endif
    return result;
}
