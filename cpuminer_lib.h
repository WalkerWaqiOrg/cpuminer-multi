#ifndef __CPUMINER_LIB_H__
#define __CPUMINER_LIB_H__

#ifdef __cplusplus
extern "C" {
#endif

/* call back func type: MINER_STATE_CHANGED
param:
  state:
    connected = 0
    disconnected = 1
*/
typedef void (*MINER_STATE_CHANGED)(int state);

int start_miner(int argc, char *argv[], MINER_STATE_CHANGED miner_state_changed_func);
void stop_miner();
int get_num_processors();

#ifdef __cplusplus
}
#endif

#endif /* __CPUMINER_LIB_H__ */
