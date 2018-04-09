// Copyright (c) 2012-2013 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Modified for CPUminer by Lucas Jones

#include "cpuminer-config.h"
#include "miner.h"
#include "crypto/oaes_lib.h"
#include "crypto/c_keccak.h"
#include "crypto/c_groestl.h"
#include "crypto/c_blake256.h"
#include "crypto/c_jh.h"
#include "crypto/c_skein.h"
#include "crypto/int-util.h"
#include "crypto/hash-ops.h"

#define MEMORY         (1 << 21) /* 2 MiB */
#define MEMORY_NEW     (1 << 24) // 16MB scratchpad
#define ITER           (1 << 20)
#define AES_BLOCK_SIZE  16
#define AES_KEY_SIZE    32 /*16*/
#define INIT_SIZE_BLK   8
#define INIT_SIZE_BYTE (INIT_SIZE_BLK * AES_BLOCK_SIZE)


typedef struct {
	unsigned long long data[4];
} FourInt64;


#include <emmintrin.h>

#if defined(_MSC_VER)
#include <intrin.h>
#include <windows.h>
#define STATIC
#define INLINE __inline
#if !defined(RDATA_ALIGN16)
#define RDATA_ALIGN16 __declspec(align(16))
#endif
#elif defined(__MINGW32__)
#include <intrin.h>
#include <windows.h>
#define STATIC static
#define INLINE inline
#if !defined(RDATA_ALIGN16)
#define RDATA_ALIGN16 __attribute__ ((aligned(16)))
#endif
#else
#include <sys/mman.h>
#define STATIC static
#define INLINE inline
#if !defined(RDATA_ALIGN16)
#define RDATA_ALIGN16 __attribute__ ((aligned(16)))
#endif
#endif

#if defined(__INTEL_COMPILER)
#define ASM __asm__
#elif !defined(_MSC_VER)
#define ASM __asm__
#else
#define ASM __asm
#endif

#define TOTALBLOCKS (MEMORY / AES_BLOCK_SIZE)

#define U64(x) ((uint64_t *) (x))
#define R128(x) ((__m128i *) (x))

#define state_index(x) (((*((uint64_t *)x) >> 4) & (TOTALBLOCKS - 1)) << 4)
#if defined(_MSC_VER)
#if !defined(_WIN64)
#define __mul() lo = mul128(c[0], b[0], &hi);
#else
#define __mul() lo = _umul128(c[0], b[0], &hi);
#endif
#else
#if defined(__x86_64__)
#define __mul() ASM("mulq %3\n\t" : "=d"(hi), "=a"(lo) : "%a" (c[0]), "rm" (b[0]) : "cc");
#else
#define __mul() lo = mul128(c[0], b[0], &hi);
#endif
#endif

#define pre_aes() \
  j = state_index(a); \
  _c = _mm_load_si128(R128(&hp_state[j])); \
  _a = _mm_load_si128(R128(a)); \

/*
 * An SSE-optimized implementation of the second half of CryptoNight step 3.
 * After using AES to mix a scratchpad value into _c (done by the caller),
 * this macro xors it with _b and stores the result back to the same index (j) that it
 * loaded the scratchpad value from.  It then performs a second random memory
 * read/write from the scratchpad, but this time mixes the values using a 64
 * bit multiply.
 * This code is based upon an optimized implementation by dga.
 */
#define post_aes() \
  _mm_store_si128(R128(c), _c); \
  _b = _mm_xor_si128(_b, _c); \
  _mm_store_si128(R128(&hp_state[j]), _b); \
  j = state_index(c); \
  p = U64(&hp_state[j]); \
  b[0] = p[0]; b[1] = p[1]; \
  __mul(); \
  a[0] += hi; a[1] += lo; \
  p = U64(&hp_state[j]); \
  p[0] = a[0];  p[1] = a[1]; \
  a[0] ^= b[0]; a[1] ^= b[1]; \
  _b = _c; \

#if defined(_MSC_VER)
#define THREADV __declspec(thread)
#else
#define THREADV __thread
#endif


THREADV uint8_t *hp_state = NULL;
THREADV int hp_allocated = 0;
THREADV FourInt64 *hp_state_new = NULL;
THREADV int hp_allocated_new = 0;

#if defined(_MSC_VER)
#define cpuid(info,x)    __cpuidex(info,x,0)
#else
void cpuid(int CPUInfo[4], int InfoType)
{
    ASM __volatile__
    (
    "cpuid":
        "=a" (CPUInfo[0]),
        "=b" (CPUInfo[1]),
        "=c" (CPUInfo[2]),
        "=d" (CPUInfo[3]) :
            "a" (InfoType), "c" (0)
        );
}
#endif


#define VARIANT1_1(p) \
  do if (variant > 0) \
  { \
    uint8_t tmp = ((const uint8_t*)p)[11]; \
    uint8_t tmp1 = (tmp>>4)&1, tmp2 = (tmp>>5)&1, tmp3 = tmp1^tmp2; \
    uint8_t tmp0 = nonce_flag ? tmp3 : tmp1 + 1; \
    ((uint8_t*)p)[11] = (tmp & 0xef) | (tmp0<<4); \
  } while(0)

#define VARIANT1_2(p) VARIANT1_1(p)
#define VARIANT1_INIT() \
  if (variant > 0 && len < 43) \
  { \
    fprintf(stderr, "Cryptonight variants need at least 43 bytes of data"); \
    _exit(1); \
  } \
  const uint8_t nonce_flag = variant > 0 ? ((const uint8_t*)input)[39] & 0x01 : 0

#pragma pack(push, 1)
union cn_slow_hash_state {
	union hash_state hs;
	struct {
		uint8_t k[64];
		uint8_t init[INIT_SIZE_BYTE];
	};
};
#pragma pack(pop)

static void do_blake_hash(const void* input, size_t len, char* output) {
    blake256_hash((uint8_t*)output, input, len);
}

void do_groestl_hash(const void* input, size_t len, char* output) {
    groestl(input, len * 8, (uint8_t*)output);
}

static void do_jh_hash(const void* input, size_t len, char* output) {
    int r = jh_hash(HASH_SIZE * 8, input, 8 * len, (uint8_t*)output);
    assert(SUCCESS == r);
}

static void do_skein_hash(const void* input, size_t len, char* output) {
    int r = c_skein_hash(8 * HASH_SIZE, input, 8 * len, (uint8_t*)output);
    assert(SKEIN_SUCCESS == r);
}

static void (* const extra_hashes[4])(const void *, size_t, char *) = {
    do_blake_hash, do_groestl_hash, do_jh_hash, do_skein_hash
};

extern int aesb_single_round(const uint8_t *in, uint8_t*out, const uint8_t *expandedKey);
extern int aesb_pseudo_round(const uint8_t *in, uint8_t *out, const uint8_t *expandedKey);

static inline size_t e2i(const uint8_t* a) {
    return (*((uint64_t*) a) / AES_BLOCK_SIZE) & (MEMORY / AES_BLOCK_SIZE - 1);
}

static void mul(const uint8_t* a, const uint8_t* b, uint8_t* res) {
    ((uint64_t*) res)[1] = mul128(((uint64_t*) a)[0], ((uint64_t*) b)[0], (uint64_t*) res);
}

static void mul_sum_xor_dst(const uint8_t* a, uint8_t* c, uint8_t* dst) {
    uint64_t hi, lo = mul128(((uint64_t*) a)[0], ((uint64_t*) dst)[0], &hi) + ((uint64_t*) c)[1];
    hi += ((uint64_t*) c)[0];

    ((uint64_t*) c)[0] = ((uint64_t*) dst)[0] ^ hi;
    ((uint64_t*) c)[1] = ((uint64_t*) dst)[1] ^ lo;
    ((uint64_t*) dst)[0] = hi;
    ((uint64_t*) dst)[1] = lo;
}

static void sum_half_blocks(uint8_t* a, const uint8_t* b) {
    uint64_t a0, a1, b0, b1;

    a0 = SWAP64LE(((uint64_t*) a)[0]);
    a1 = SWAP64LE(((uint64_t*) a)[1]);
    b0 = SWAP64LE(((uint64_t*) b)[0]);
    b1 = SWAP64LE(((uint64_t*) b)[1]);
    a0 += b0;
    a1 += b1;
    ((uint64_t*) a)[0] = SWAP64LE(a0);
    ((uint64_t*) a)[1] = SWAP64LE(a1);
}

static inline void copy_block(uint8_t* dst, const uint8_t* src) {
    ((uint64_t*) dst)[0] = ((uint64_t*) src)[0];
    ((uint64_t*) dst)[1] = ((uint64_t*) src)[1];
}

static void swap_blocks(uint8_t* a, uint8_t* b) {
    size_t i;
    uint8_t t;
    for (i = 0; i < AES_BLOCK_SIZE; i++) {
        t = a[i];
        a[i] = b[i];
        b[i] = t;
    }
}

static inline void xor_blocks(uint8_t* a, const uint8_t* b) {
    ((uint64_t*) a)[0] ^= ((uint64_t*) b)[0];
    ((uint64_t*) a)[1] ^= ((uint64_t*) b)[1];
}

static inline void xor_blocks_dst(const uint8_t* a, const uint8_t* b, uint8_t* dst) {
    ((uint64_t*) dst)[0] = ((uint64_t*) a)[0] ^ ((uint64_t*) b)[0];
    ((uint64_t*) dst)[1] = ((uint64_t*) a)[1] ^ ((uint64_t*) b)[1];
}

/**
 * @brief uses cpuid to determine if the CPU supports the AES instructions
 * @return true if the CPU supports AES, false otherwise
 */

STATIC INLINE int force_software_aes(void)
{
  static int use = -1;

  if (use != -1)
    return use;

  const char *env = getenv("MONERO_USE_SOFTWARE_AES");
  if (!env) {
    use = 0;
  }
  else if (!strcmp(env, "0") || !strcmp(env, "no")) {
    use = 0;
  }
  else {
    use = 1;
  }
  return use;
}

STATIC INLINE int check_aes_hw(void)
{
    int cpuid_results[4];
    static int supported = -1;

    if(supported >= 0)
        return supported;

    cpuid(cpuid_results,1);
    return supported = cpuid_results[2] & (1 << 25);
}

struct cryptonight_ctx {
    uint8_t long_state[MEMORY];
    union cn_slow_hash_state state;
    uint8_t text[INIT_SIZE_BYTE];
    uint8_t a[AES_BLOCK_SIZE];
    uint8_t b[AES_BLOCK_SIZE];
    uint8_t c[AES_BLOCK_SIZE];
    uint8_t aes_key[AES_KEY_SIZE];
    oaes_ctx* aes_ctx;
};

void slow_hash_allocate_state(void)
{
    if(hp_state != NULL)
        return;

#if defined(_MSC_VER) || defined(__MINGW32__)
    SetLockPagesPrivilege(GetCurrentProcess(), TRUE);
    hp_state = (uint8_t *) VirtualAlloc(hp_state, MEMORY, MEM_LARGE_PAGES |
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#else
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
  defined(__DragonFly__)
    hp_state = mmap(0, MEMORY, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANON, 0, 0);
#else
    hp_state = mmap(0, MEMORY, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, 0, 0);
#endif
    if(hp_state == MAP_FAILED)
        hp_state = NULL;
#endif
    hp_allocated = 1;
    if(hp_state == NULL)
    {
        hp_allocated = 0;
        hp_state = (uint8_t *) malloc(MEMORY);
    }
}
void slow_hash_free_state(void)
{
    if(hp_state == NULL)
        return;

    if(!hp_allocated)
        free(hp_state);
    else
    {
#if defined(_MSC_VER) || defined(__MINGW32__)
        VirtualFree(hp_state, MEMORY, MEM_RELEASE);
#else
        munmap(hp_state, MEMORY);
#endif
    }

    hp_state = NULL;
    hp_allocated = 0;
}

void slow_hash_allocate_state_new(void)
{
    if(hp_state_new != NULL)
        return;

#if defined(_MSC_VER) || defined(__MINGW32__)
    SetLockPagesPrivilege(GetCurrentProcess(), TRUE);
    hp_state_new = (FourInt64 *) VirtualAlloc(hp_state_new, MEMORY_NEW, MEM_LARGE_PAGES |
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#else
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
  defined(__DragonFly__)
    hp_state_new = mmap(0, MEMORY_NEW, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANON, 0, 0);
#else
    hp_state_new = mmap(0, MEMORY_NEW, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, 0, 0);
#endif
    if(hp_state_new == MAP_FAILED)
        hp_state_new = NULL;
#endif
    hp_allocated_new = 1;
    if(hp_state_new == NULL)
    {
        hp_allocated_new = 0;
        hp_state_new = (FourInt64 *) malloc(MEMORY_NEW);
    }
}

void slow_hash_free_state_new(void)
{
    if(hp_state_new == NULL)
        return;

    if(!hp_allocated_new)
        free(hp_state_new);
    else
    {
#if defined(_MSC_VER) || defined(__MINGW32__)
        VirtualFree(hp_state_new, MEMORY_NEW, MEM_RELEASE);
#else
        munmap(hp_state_new, MEMORY_NEW);
#endif
    }

    hp_state_new = NULL;
    hp_allocated_new = 0;
}

void cn_slow_hash(const void *data, size_t length, char *hash)
{
    RDATA_ALIGN16 uint8_t expandedKey[240];  /* These buffers are aligned to use later with SSE functions */

    uint8_t text[INIT_SIZE_BYTE];
    RDATA_ALIGN16 uint64_t a[2];
    RDATA_ALIGN16 uint64_t b[2];
    RDATA_ALIGN16 uint64_t c[2];
    union cn_slow_hash_state state;
    __m128i _a, _b, _c;
    uint64_t hi, lo;

    size_t i, j;
    uint64_t *p = NULL;
    oaes_ctx *aes_ctx = NULL;
    int useAes = !force_software_aes() && check_aes_hw();



    // this isn't supposed to happen, but guard against it for now.
    if(hp_state == NULL)
        slow_hash_allocate_state();
    if(hp_state_new == NULL)
        slow_hash_allocate_state_new();
    memset(hp_state_new, 0, MEMORY_NEW);

    /* CryptoNight Step 1:  Use Keccak1600 to initialize the 'state' (and 'text') buffers from the data. */

    hash_process(&state.hs, data, length);
    memcpy(text, state.init, INIT_SIZE_BYTE);

    /* CryptoNight Step 2:  Iteratively encrypt the results from Keccak to fill
     * the 2MB large random access buffer.
     */


    {
        aes_ctx = (oaes_ctx *) oaes_alloc();
        oaes_key_import_data(aes_ctx, state.hs.b, AES_KEY_SIZE);
        for(i = 0; i < MEMORY / INIT_SIZE_BYTE; i++)
        {
            for(j = 0; j < INIT_SIZE_BLK; j++)
                aesb_pseudo_round(&text[AES_BLOCK_SIZE * j], &text[AES_BLOCK_SIZE * j], aes_ctx->key->exp_data);

            memcpy(&hp_state[i * INIT_SIZE_BYTE], text, INIT_SIZE_BYTE);
        }
    }

    U64(a)[0] = U64(&state.k[0])[0] ^ U64(&state.k[32])[0];
    U64(a)[1] = U64(&state.k[0])[1] ^ U64(&state.k[32])[1];
    U64(b)[0] = U64(&state.k[16])[0] ^ U64(&state.k[48])[0];
    U64(b)[1] = U64(&state.k[16])[1] ^ U64(&state.k[48])[1];

    /* CryptoNight Step 3:  Bounce randomly 1,048,576 times (1<<20) through the mixing buffer,
     * using 524,288 iterations of the following mixing function.  Each execution
     * performs two reads and writes from the mixing buffer.
     */

    _b = _mm_load_si128(R128(b));
    // Two independent versions, one with AES, one without, to ensure that
    // the useAes test is only performed once, not every iteration.

    {
        for(i = 0; i < ITER / 2; i++)
        {
            pre_aes();
            aesb_single_round((uint8_t *) &_c, (uint8_t *) &_c, (uint8_t *) &_a);
            post_aes();

			//New Code begin
			hp_state_new[c[0]%(512*1024)].data[0]=a[0];
			hp_state_new[c[0]%(512*1024)].data[1]=a[1];
			hp_state_new[c[0]%(512*1024)].data[2]=b[0];
			hp_state_new[c[0]%(512*1024)].data[3]=b[1];
			//New Code end
        }
    }

    /* CryptoNight Step 4:  Sequentially pass through the mixing buffer and use 10 rounds
     * of AES encryption to mix the random data back into the 'text' buffer.  'text'
     * was originally created with the output of Keccak1600. */

    memcpy(text, state.init, INIT_SIZE_BYTE);

    {
        oaes_key_import_data(aes_ctx, &state.hs.b[32], AES_KEY_SIZE);
        for(i = 0; i < MEMORY / INIT_SIZE_BYTE; i++)
        {
            for(j = 0; j < INIT_SIZE_BLK; j++)
            {
                xor_blocks(&text[j * AES_BLOCK_SIZE], &hp_state[i * INIT_SIZE_BYTE + j * AES_BLOCK_SIZE]);
                aesb_pseudo_round(&text[AES_BLOCK_SIZE * j], &text[AES_BLOCK_SIZE * j], aes_ctx->key->exp_data);
            }
        }
        oaes_free((OAES_CTX **) &aes_ctx);
    }

	//New Code begin
	FourInt64 Y;
	Y.data[3]=Y.data[2]=Y.data[1]=Y.data[0]=0xcbf29ce484222325ULL;
	for(int i=0; i<512*1024; i++) {
		Y.data[3]=(Y.data[3]*0x100000001b3ULL)^hp_state_new[i].data[3];
		Y.data[2]=(Y.data[2]*0x100000001b3ULL)^hp_state_new[i].data[2];
		Y.data[1]=(Y.data[1]*0x100000001b3ULL)^hp_state_new[i].data[1];
		Y.data[0]=(Y.data[0]*0x100000001b3ULL)^hp_state_new[i].data[0];
	}
	text[8*0+0]^=((Y.data[0]>>(8*0))&0xFF);
	text[8*0+1]^=((Y.data[0]>>(8*1))&0xFF);
	text[8*0+2]^=((Y.data[0]>>(8*2))&0xFF);
	text[8*0+3]^=((Y.data[0]>>(8*3))&0xFF);
	text[8*0+4]^=((Y.data[0]>>(8*4))&0xFF);
	text[8*0+5]^=((Y.data[0]>>(8*5))&0xFF);
	text[8*0+6]^=((Y.data[0]>>(8*6))&0xFF);
	text[8*0+7]^=((Y.data[0]>>(8*7))&0xFF);

	text[8*1+0]^=((Y.data[1]>>(8*0))&0xFF);
	text[8*1+1]^=((Y.data[1]>>(8*1))&0xFF);
	text[8*1+2]^=((Y.data[1]>>(8*2))&0xFF);
	text[8*1+3]^=((Y.data[1]>>(8*3))&0xFF);
	text[8*1+4]^=((Y.data[1]>>(8*4))&0xFF);
	text[8*1+5]^=((Y.data[1]>>(8*5))&0xFF);
	text[8*1+6]^=((Y.data[1]>>(8*6))&0xFF);
	text[8*1+7]^=((Y.data[1]>>(8*7))&0xFF);

	text[8*2+0]^=((Y.data[2]>>(8*0))&0xFF);
	text[8*2+1]^=((Y.data[2]>>(8*1))&0xFF);
	text[8*2+2]^=((Y.data[2]>>(8*2))&0xFF);
	text[8*2+3]^=((Y.data[2]>>(8*3))&0xFF);
	text[8*2+4]^=((Y.data[2]>>(8*4))&0xFF);
	text[8*2+5]^=((Y.data[2]>>(8*5))&0xFF);
	text[8*2+6]^=((Y.data[2]>>(8*6))&0xFF);
	text[8*2+7]^=((Y.data[2]>>(8*7))&0xFF);

	text[8*3+0]^=((Y.data[3]>>(8*0))&0xFF);
	text[8*3+1]^=((Y.data[3]>>(8*1))&0xFF);
	text[8*3+2]^=((Y.data[3]>>(8*2))&0xFF);
	text[8*3+3]^=((Y.data[3]>>(8*3))&0xFF);
	text[8*3+4]^=((Y.data[3]>>(8*4))&0xFF);
	text[8*3+5]^=((Y.data[3]>>(8*5))&0xFF);
	text[8*3+6]^=((Y.data[3]>>(8*6))&0xFF);
	text[8*3+7]^=((Y.data[3]>>(8*7))&0xFF);

	//New Code end

    /* CryptoNight Step 5:  Apply Keccak to the state again, and then
     * use the resulting data to select which of four finalizer
     * hash functions to apply to the data (Blake, Groestl, JH, or Skein).
     * Use this hash to squeeze the state array down
     * to the final 256 bit hash output.
     */

    memcpy(state.init, text, INIT_SIZE_BYTE);
    hash_permutation(&state.hs);
    extra_hashes[state.hs.b[0] & 3](&state, 200, hash);
}

void cryptonight_hash(void* output, const void* input, size_t input_len)
{
        int variant = 0;
        int len = input_len;	
	cn_slow_hash((const void *)input, input_len, (char *)output);
	return; 
	
	
	
    struct cryptonight_ctx *ctx = alloca(sizeof(struct cryptonight_ctx));
    hash_process(&ctx->state.hs, (const uint8_t*) input, len);
    memcpy(ctx->text, ctx->state.init, INIT_SIZE_BYTE);
    memcpy(ctx->aes_key, ctx->state.hs.b, AES_KEY_SIZE);
    ctx->aes_ctx = (oaes_ctx*) oaes_alloc();
    size_t i, j;
	 

    VARIANT1_INIT();

    oaes_key_import_data(ctx->aes_ctx, ctx->aes_key, AES_KEY_SIZE);
    for (i = 0; i < MEMORY / INIT_SIZE_BYTE; i++) {
        for (j = 0; j < INIT_SIZE_BLK; j++) {
            aesb_pseudo_round(&ctx->text[AES_BLOCK_SIZE * j],
                    &ctx->text[AES_BLOCK_SIZE * j],
                    ctx->aes_ctx->key->exp_data);
        }
        memcpy(&ctx->long_state[i * INIT_SIZE_BYTE], ctx->text, INIT_SIZE_BYTE);
    }

    for (i = 0; i < 16; i++) {
        ctx->a[i] = ctx->state.k[i] ^ ctx->state.k[32 + i];
        ctx->b[i] = ctx->state.k[16 + i] ^ ctx->state.k[48 + i];
    }

    for (i = 0; i < ITER / 2; i++) {
        /* Dependency chain: address -> read value ------+
         * written value <-+ hard function (AES or MUL) <+
         * next address  <-+
         */
		 
        /* Iteration 1 */
       j = e2i(ctx->a);
       aesb_single_round(&ctx->long_state[j * AES_BLOCK_SIZE], ctx->c, ctx->a);
       xor_blocks_dst(ctx->c, ctx->b, &ctx->long_state[j * AES_BLOCK_SIZE]);
  	   VARIANT1_1((uint8_t*)&ctx->long_state[j * AES_BLOCK_SIZE]);
        /* Iteration 2 */
        mul_sum_xor_dst(ctx->c, ctx->a,
                &ctx->long_state[e2i(ctx->c) * AES_BLOCK_SIZE]);
       copy_block(ctx->b, ctx->c);
  	   VARIANT1_2((uint8_t*)
                &ctx->long_state[e2i(ctx->c) * AES_BLOCK_SIZE]);
    }

    memcpy(ctx->text, ctx->state.init, INIT_SIZE_BYTE);
    oaes_key_import_data(ctx->aes_ctx, &ctx->state.hs.b[32], AES_KEY_SIZE);
    for (i = 0; i < MEMORY / INIT_SIZE_BYTE; i++) {
        for (j = 0; j < INIT_SIZE_BLK; j++) {
            xor_blocks(&ctx->text[j * AES_BLOCK_SIZE],
                    &ctx->long_state[i * INIT_SIZE_BYTE + j * AES_BLOCK_SIZE]);
            aesb_pseudo_round(&ctx->text[j * AES_BLOCK_SIZE],
                    &ctx->text[j * AES_BLOCK_SIZE],
                    ctx->aes_ctx->key->exp_data);
        }
    }
    memcpy(ctx->state.init, ctx->text, INIT_SIZE_BYTE);
    hash_permutation(&ctx->state.hs);
    /*memcpy(hash, &state, 32);*/
    extra_hashes[ctx->state.hs.b[0] & 3](&ctx->state, 200, output);
    oaes_free((OAES_CTX **) &ctx->aes_ctx);
}

void cryptonight_fast_hash(const char* input, char* output, uint32_t len) {
    union hash_state state;
    hash_process(&state, (const uint8_t*) input, len);
    memcpy(output, &state, HASH_SIZE);
}

void cryptonight_hash_ctx(void* output, const void* input, size_t len, struct cryptonight_ctx* ctx) {


	cn_slow_hash((const void *)input, len, (char *)output);
}

void cryptonight_hash_ctx_aes_ni(void* output, const void* input, size_t len, struct cryptonight_ctx* ctx) {


	cn_slow_hash((const void *)input, len, (char *)output);

}

int scanhash_cryptonight(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
                uint32_t max_nonce, uint64_t *hashes_done) {
        uint32_t *nonceptr = (uint32_t*) (((char*)pdata) + 39);
        uint32_t n = *nonceptr - 1;
        const uint32_t first_nonce = n + 1;
        const uint32_t Htarg = ptarget[7];
        uint32_t hash[HASH_SIZE / 4] __attribute__((aligned(32)));

        struct cryptonight_ctx *ctx = (struct cryptonight_ctx*)malloc(sizeof(struct cryptonight_ctx));

        if (aes_ni_supported) {
                do {
                        *nonceptr = ++n;
                        cryptonight_hash_ctx_aes_ni(hash, pdata, 76, ctx);
                        if (unlikely(hash[7] < ptarget[7])) {
                                *hashes_done = n - first_nonce + 1;
                                free(ctx);
                                return true;
                        }
                } while (likely((n <= max_nonce && !work_restart[thr_id].restart)));
        } else {
                do {
                        *nonceptr = ++n;
                        cryptonight_hash_ctx(hash, pdata, 76, ctx);
                        if (unlikely(hash[7] < ptarget[7])) {
                                *hashes_done = n - first_nonce + 1;
                                free(ctx);
                                return true;
                        }
                } while (likely((n <= max_nonce && !work_restart[thr_id].restart)));
        }

        free(ctx);
        *hashes_done = n - first_nonce + 1;
        return 0;
}
