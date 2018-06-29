#include <stdint.h>

int fast_aesb_single_round(const uint8_t *in, uint8_t*out, const uint8_t *expandedKey) {};
int fast_aesb_pseudo_round_mut(uint8_t *val, uint8_t *expandedKey) {};
uint64_t mul128(uint64_t multiplier, uint64_t multiplicand, uint64_t* product_hi) {};
int scanhash_heavy(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
                            uint32_t max_nonce, uint64_t *hashes_done) {};
int scanhash_scrypt(int thr_id, uint32_t *pdata,
                            unsigned char *scratchbuf, const uint32_t *ptarget,
                            uint32_t max_nonce, uint64_t *hashes_done, int N) {};
int scanhash_sha256d(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
                            uint32_t max_nonce, uint64_t *hashes_done) {};
int scanhash_skein(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
                            uint32_t max_nonce, uint64_t *hashes_done) {};
unsigned char *scrypt_buffer_alloc(int N) {};
void sha256d(unsigned char *hash, const unsigned char *data, int len) {};

