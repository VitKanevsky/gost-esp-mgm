/*
 * GOST R 34.12-2015 (Kuznyechik) cipher.
 *
 * Copyright (c) 2018 Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

#include <linux/crypto.h>
#include <linux/module.h>
#include <linux/version.h>
#include <asm/unaligned.h>
#include <asm/byteorder.h>

#include <crypto/hash.h>
#include <crypto/algapi.h>
#include <crypto/skcipher.h>

#include <crypto/scatterwalk.h>

#include <crypto/internal/aead.h>
#include <crypto/internal/simd.h>
#include <crypto/internal/skcipher.h>
#include <asm/fpu/api.h>

#include "kuztable.h"

#define KUZNYECHIK_KEY_SIZE	32
#define KUZNYECHIK_BLOCK_SIZE	16

#define KUZNYECHIK_ALIGN	16
#define KUZNYECHIK_ALIGN_ATTR __attribute__ ((__aligned__(KUZNYECHIK_ALIGN)))

#define MGM_KUZNYECHIKESP_IV_SIZE 8

//#define DEBUG_OUTPUT

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
static inline void crypto_xor_cpy(u8 *dst, const u8 *src1, const u8 *src2,
				  unsigned int size)
{
	memcpy(dst, src1, size);
	crypto_xor(dst, src2, size);
}
#endif

#define KUZNYECHIK_SUBKEYS_SIZE (16 * 10)

struct crypto_kuznyechik_ctx {
    u8 key[KUZNYECHIK_SUBKEYS_SIZE];    // 160
    u8 dekey[KUZNYECHIK_SUBKEYS_SIZE];  // 160
};

static void S(u8 *a, const u8 *b)
{
	a[0] = pi[b[0]];
	a[1] = pi[b[1]];
	a[2] = pi[b[2]];
	a[3] = pi[b[3]];
	a[4] = pi[b[4]];
	a[5] = pi[b[5]];
	a[6] = pi[b[6]];
	a[7] = pi[b[7]];
	a[8] = pi[b[8]];
	a[9] = pi[b[9]];
	a[10] = pi[b[10]];
	a[11] = pi[b[11]];
	a[12] = pi[b[12]];
	a[13] = pi[b[13]];
	a[14] = pi[b[14]];
	a[15] = pi[b[15]];
}

static void Sinv(u8 *a, const u8 *b)
{
	a[0] = pi_inv[b[0]];
	a[1] = pi_inv[b[1]];
	a[2] = pi_inv[b[2]];
	a[3] = pi_inv[b[3]];
	a[4] = pi_inv[b[4]];
	a[5] = pi_inv[b[5]];
	a[6] = pi_inv[b[6]];
	a[7] = pi_inv[b[7]];
	a[8] = pi_inv[b[8]];
	a[9] = pi_inv[b[9]];
	a[10] = pi_inv[b[10]];
	a[11] = pi_inv[b[11]];
	a[12] = pi_inv[b[12]];
	a[13] = pi_inv[b[13]];
	a[14] = pi_inv[b[14]];
	a[15] = pi_inv[b[15]];
}

static void Linv(u8 *a, const u8 *b)
{
	memcpy(a, &kuz_table_inv[0][b[0] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[1][b[1] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[2][b[2] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[3][b[3] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[4][b[4] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[5][b[5] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[6][b[6] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[7][b[7] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[8][b[8] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[9][b[9] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[10][b[10] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[11][b[11] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[12][b[12] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[13][b[13] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[14][b[14] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[15][b[15] * 16], KUZNYECHIK_BLOCK_SIZE);
}

static void LSX(u8 *a, const u8 *b, const u8 *c)
{
	u8 t[16];

	memcpy(t, &kuz_table[0][(b[0] ^ c[0]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[1][(b[1] ^ c[1]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[2][(b[2] ^ c[2]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[3][(b[3] ^ c[3]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[4][(b[4] ^ c[4]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[5][(b[5] ^ c[5]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[6][(b[6] ^ c[6]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[7][(b[7] ^ c[7]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[8][(b[8] ^ c[8]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[9][(b[9] ^ c[9]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[10][(b[10] ^ c[10]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[11][(b[11] ^ c[11]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[12][(b[12] ^ c[12]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[13][(b[13] ^ c[13]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[14][(b[14] ^ c[14]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor_cpy(a, t, &kuz_table[15][(b[15] ^ c[15]) * 16], KUZNYECHIK_BLOCK_SIZE);
}

static void XLiSi(u8 *a, const u8 *b, const u8 *c)
{
	u8 t[16];

	memcpy(t, &kuz_table_inv_LS[0][b[0] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[1][b[1] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[2][b[2] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[3][b[3] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[4][b[4] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[5][b[5] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[6][b[6] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[7][b[7] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[8][b[8] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[9][b[9] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[10][b[10] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[11][b[11] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[12][b[12] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[13][b[13] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[14][b[14] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[15][b[15] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor_cpy(a, t, c, 16);
}

static void subkey(u8 *out, const u8 *key, unsigned int i)
{
	u8 test[16];

	LSX(test, key+0, kuz_key_table[i + 0]);
	crypto_xor_cpy(out+16, test, key + 16, 16);
	LSX(test, out+16, kuz_key_table[i + 1]);
	crypto_xor_cpy(out+0, test, key + 0, 16);
	LSX(test, out+0, kuz_key_table[i + 2]);
	crypto_xor(out+16, test, 16);
	LSX(test, out+16, kuz_key_table[i + 3]);
	crypto_xor(out+0, test, 16);
	LSX(test, out+0, kuz_key_table[i + 4]);
	crypto_xor(out+16, test, 16);
	LSX(test, out+16, kuz_key_table[i + 5]);
	crypto_xor(out+0, test, 16);
	LSX(test, out+0, kuz_key_table[i + 6]);
	crypto_xor(out+16, test, 16);
	LSX(test, out+16, kuz_key_table[i + 7]);
	crypto_xor(out+0, test, 16);
}

static int kuznyechik_set_key(struct crypto_tfm *tfm, const u8 *in_key, unsigned int key_len)
{
	struct crypto_kuznyechik_ctx *ctx = crypto_tfm_ctx(tfm);
	unsigned int i;

	if (key_len != KUZNYECHIK_KEY_SIZE) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
		u32 *flags = &tfm->crt_flags;
		*flags |= CRYPTO_TFM_RES_BAD_KEY_LEN;
#endif
		return -EINVAL;
	};

	memcpy(ctx->key, in_key, 32);
	subkey(ctx->key + 32, ctx->key, 0);
	subkey(ctx->key + 64, ctx->key + 32, 8);
	subkey(ctx->key + 96, ctx->key + 64, 16);
	subkey(ctx->key + 128, ctx->key + 96, 24);
	for (i = 0; i < 10; i++)
		Linv(ctx->dekey + 16 * i, ctx->key + 16 * i);

	return 0;
}

static void kuznyechik_encrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	const struct crypto_kuznyechik_ctx *ctx = crypto_tfm_ctx(tfm);
	u8 temp[KUZNYECHIK_BLOCK_SIZE];

	LSX(temp, ctx->key + 16 * 0, in);
	LSX(temp, ctx->key + 16 * 1, temp);
	LSX(temp, ctx->key + 16 * 2, temp);
	LSX(temp, ctx->key + 16 * 3, temp);
	LSX(temp, ctx->key + 16 * 4, temp);
	LSX(temp, ctx->key + 16 * 5, temp);
	LSX(temp, ctx->key + 16 * 6, temp);
	LSX(temp, ctx->key + 16 * 7, temp);
	LSX(temp, ctx->key + 16 * 8, temp);
	crypto_xor_cpy(out, ctx->key + 16 * 9, temp, 16);
}

static void kuznyechik_decrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	const struct crypto_kuznyechik_ctx *ctx = crypto_tfm_ctx(tfm);
	u8 temp[KUZNYECHIK_BLOCK_SIZE];

	S(temp, in);
	XLiSi(temp, temp, ctx->dekey + 16 * 9);
	XLiSi(temp, temp, ctx->dekey + 16 * 8);
	XLiSi(temp, temp, ctx->dekey + 16 * 7);
	XLiSi(temp, temp, ctx->dekey + 16 * 6);
	XLiSi(temp, temp, ctx->dekey + 16 * 5);
	XLiSi(temp, temp, ctx->dekey + 16 * 4);
	XLiSi(temp, temp, ctx->dekey + 16 * 3);
	XLiSi(temp, temp, ctx->dekey + 16 * 2);
	XLiSi(temp, temp, ctx->dekey + 16 * 1);
	Sinv(out, temp);
	crypto_xor(out, ctx->key + 16 * 0, 16);
}

#ifdef DEBUG_OUTPUT
static void hexdump(const char * prefix,  unsigned char *buf, unsigned int len)
{
    print_hex_dump(KERN_CONT, prefix, DUMP_PREFIX_OFFSET,
            16, 1,
            buf, len, false);
}
#endif

static void kuznyechik_encrypt_block_internal(struct crypto_kuznyechik_ctx *ctx, const u8 *in, u8 *out)
{
    u8 temp[KUZNYECHIK_BLOCK_SIZE];

    LSX(temp, ctx->key + 16 * 0, in);
    LSX(temp, ctx->key + 16 * 1, temp);
    LSX(temp, ctx->key + 16 * 2, temp);
    LSX(temp, ctx->key + 16 * 3, temp);
    LSX(temp, ctx->key + 16 * 4, temp);
    LSX(temp, ctx->key + 16 * 5, temp);
    LSX(temp, ctx->key + 16 * 6, temp);
    LSX(temp, ctx->key + 16 * 7, temp);
    LSX(temp, ctx->key + 16 * 8, temp);
    crypto_xor_cpy(out, ctx->key + 16 * 9, temp, 16);
}


static struct crypto_alg kuznyechik_alg = {
    .cra_name           =	"kuznyechik",
	.cra_driver_name	=	"kuznyechik-generic",
	.cra_priority		=	100,
    .cra_flags          =	CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize		=	KUZNYECHIK_BLOCK_SIZE,
	.cra_ctxsize		=	sizeof(struct crypto_kuznyechik_ctx),
    .cra_module         =	THIS_MODULE,
	.cra_u			=	{
		.cipher = {
			.cia_min_keysize	= KUZNYECHIK_KEY_SIZE,
			.cia_max_keysize	= KUZNYECHIK_KEY_SIZE,
            .cia_setkey         = kuznyechik_set_key,
			.cia_encrypt		= kuznyechik_encrypt,
			.cia_decrypt		= kuznyechik_decrypt
		}
	}
};

//---------------------------------------




#define GOST_ESP_MGM_KUZNYECHIK_SALT_LEN  12



typedef union {
    u8 b[16];
    u64 q[2];
    u32 d[4];
    u16 w[8];
} kuznyechik_w128_t;

typedef union {
    u8 b[32];
    u64 q[4];
    u32 d[8];
    u16 w[16];
    kuznyechik_w128_t k[2];
} kuznyechik_w256_t;

typedef struct {
    kuznyechik_w256_t k;
} kuznyechik_key_t;

#define KUZNYECHIK_ROUND_KEYS_COUNT 10

typedef struct {
    kuznyechik_w128_t k[KUZNYECHIK_ROUND_KEYS_COUNT];
} kuznyechik_round_keys_t;

typedef enum {
    mgm_associated_data = 0,
    mgm_main_data,
} mgm_state_t;

typedef struct {
//    struct crypto_kuznyechik_ctx kuznyechik_key KUZNYECHIK_ALIGN_ATTR; // c in orig gost_kuznyechik_cipher_ctx_mgm
    kuznyechik_w128_t partial_buffer;
    kuznyechik_w128_t mgm_iv;              /// nonce
    kuznyechik_w128_t mgm_partial_buffer;  /// Rest of associated data
    unsigned char tag[16];                  /// MAC - intermediate state
    unsigned char final_tag[16];            /// MAC - final state

    kuznyechik_w128_t original_iv;

    mgm_state_t mgm_state;                  /// associated_data/plain text
    size_t ad_length;
    size_t taglen;                          /// MAC length


    unsigned int num;
    int encrypting;
} gost_kuznyechik_cipher_ctx_mgm;


/* This data is stored at the end of the crypto_tfm struct.
 * It's a type of per "session" data storage location.
 * This needs to be 16 byte aligned.
 */
struct gost_esp_mgmkuznyechik_ctx {
    /**
     * @brief key
     */
    u8 key[32] KUZNYECHIK_ALIGN_ATTR;

    /**
     * Derived Message Key key from "key"
     */
    u8 K_msg[32] KUZNYECHIK_ALIGN_ATTR;

    struct crypto_kuznyechik_ctx kuznyechik_key KUZNYECHIK_ALIGN_ATTR;

    u8 salt[12];

    u64 iv64_with_zeroed_pnum;

    gost_kuznyechik_cipher_ctx_mgm  mgm_ctx KUZNYECHIK_ALIGN_ATTR;
};




#define KUZNYECHIK_BLOCK_SIZE  16

static void gf128_mul_uint64(uint64_t *result, uint64_t *arg1, uint64_t *arg2)
{
    int i = 0, n = 0;
    uint64_t t, s0, s1;
    uint64_t z[2];

    s0 = cpu_to_be64(arg1[1]); // __bswap_64( arg1[1]);
    s1 = cpu_to_be64(arg1[0]);  //__bswap_64( arg1[0]);

    memset(z, 0, sizeof(uint64_t) * 2);

    /* lower half */
    t = cpu_to_be64(arg2[1]); // __bswap_64(arg2[1]);

    for (i = 0; i < 64; i++) {
        if (t & 0x1) {
            z[0] ^= s0;
            z[1] ^= s1;
        }
        t >>= 1;
        n = s1 >> 63;
        s1 <<= 1;
        s1 ^= (s0 >> 63);
        s0 <<= 1;
        if (n)
            s0 ^= 0x87;
    }

    /* upper half */
    t = cpu_to_be64(arg2[0]); //__bswap_64(arg2[0]);

    for (i = 0; i < 63; i++) {
        if (t & 0x1) {
            z[0] ^= s0;
            z[1] ^= s1;
        }
        t >>= 1;
        n = s1 >> 63;
        s1 <<= 1;
        s1 ^= (s0 >> 63);
        s0 <<= 1;
        if (n)
            s0 ^= 0x87;
    }

    if (t & 0x1) {
        z[0] ^= s0;
        z[1] ^= s1;
    }

    result[0] = be64_to_cpu(z[1]); // __bswap_64(z[1]);
    result[1] = be64_to_cpu(z[0]); // __bswap_64(z[0]);
}

void inc_counter(unsigned char *counter, size_t counter_bytes)
{
    unsigned char c;
    unsigned int n = counter_bytes;

    do {
        --n;
        c = counter[n];
        ++c;
        counter[n] = c;
        if (c)
            return;
    } while (n);
}

/* increment counter (128-bit int) by 1 */
static void ctr128_inc(unsigned char *counter)
{
    inc_counter(counter, 16);
}

//#if UINTPTR_MAX == 0xffffffff
//#define KUZNYECHIK_BITS 32
//#elif UINTPTR_MAX == 0xffffffffffffffff
#define KUZNYECHIK_BITS 64
//#endif

#define KUZNYECHIK_MAX_BITS 128

#define KUZNYECHIK_BIT_PARTS_8 (KUZNYECHIK_MAX_BITS / 8)
#define KUZNYECHIK_BIT_PARTS_16 (KUZNYECHIK_MAX_BITS / 16)
#define KUZNYECHIK_BIT_PARTS_32 (KUZNYECHIK_MAX_BITS / 32)
#define KUZNYECHIK_BIT_PARTS_64 (KUZNYECHIK_MAX_BITS / 64)

#define KUZNYECHIK_BIT_PARTS (KUZNYECHIK_MAX_BITS / KUZNYECHIK_BITS)
#define KUZNYECHIK_MAX_BIT_PARTS (KUZNYECHIK_MAX_BITS / KUZNYECHIK_MIN_BITS)

#define KUZNYECHIK_ACCESS_128_VALUE_8(key, part) ((key).b[(part)])
#define KUZNYECHIK_ACCESS_128_VALUE_16(key, part) ((key).w[(part)])
#define KUZNYECHIK_ACCESS_128_VALUE_32(key, part) ((key).d[(part)])
#define KUZNYECHIK_ACCESS_128_VALUE_64(key, part) ((key).q[(part)])

#if(KUZNYECHIK_BITS == 32)
#define KUZNYECHIK_ACCESS_128_VALUE KUZNYECHIK_ACCESS_128_VALUE_32
#elif(KUZNYECHIK_BITS == 64)
#define KUZNYECHIK_ACCESS_128_VALUE KUZNYECHIK_ACCESS_128_VALUE_64
#endif

static inline void kuznyechik_copy128(kuznyechik_w128_t* to, const kuznyechik_w128_t* from) {
    int i;
    for (i = 0; i < KUZNYECHIK_BIT_PARTS; i++) {
        KUZNYECHIK_ACCESS_128_VALUE(*to, i) = KUZNYECHIK_ACCESS_128_VALUE(*from, i);
    }
}

static inline void kuznyechik_append128(kuznyechik_w128_t* x, const kuznyechik_w128_t* y) {
        int i;
    for (i = 0; i < KUZNYECHIK_BIT_PARTS; i++) {
        KUZNYECHIK_ACCESS_128_VALUE(*x, i) ^= KUZNYECHIK_ACCESS_128_VALUE(*y, i);
    }
}

static inline void kuznyechik_plus128(kuznyechik_w128_t* result, const kuznyechik_w128_t* x,
                                               const kuznyechik_w128_t* y) {
    kuznyechik_copy128(result, x);
    kuznyechik_append128(result, y);
}

int gost_kuznyechik_cipher_do_mgm(struct gost_esp_mgmkuznyechik_ctx *ctx,   /*gost_kuznyechik_cipher_ctx_mgm *c,*/
                                   unsigned char *out,
                                   const unsigned char *in,
                                   size_t inl)
{
    unsigned char *iv = ctx->mgm_ctx.original_iv.b; // EVP_CIPHER_CTX_iv_noconst(ctx);
    const unsigned char *current_in = in;

    unsigned char *current_out = out;
    kuznyechik_w128_t *currentInputBlock;
    kuznyechik_w128_t *currentOutputBlock;
    unsigned int n = ctx->mgm_ctx.num;
    size_t lasted;
    size_t i;

    size_t blocks = inl / KUZNYECHIK_BLOCK_SIZE;
    int rest_len = n % KUZNYECHIK_BLOCK_SIZE;
    kuznyechik_w128_t h;

    kuznyechik_w128_t *iv_buffer = (kuznyechik_w128_t *) iv;
    kuznyechik_w128_t tmp;
    int encrypting = ctx->mgm_ctx.encrypting;

    /* ======== Here we deal with associated data =========== */
    if (out == 0 && ctx->mgm_ctx.mgm_state == mgm_associated_data) {
        if (n == 0) {
            kuznyechik_encrypt_block_internal(&ctx->kuznyechik_key,ctx->mgm_ctx.mgm_iv.b, ctx->mgm_ctx.partial_buffer.b);
            // kuznyechik_encrypt_block_(&c->c.encrypt_round_keys, &c->mgm_iv, &c->partial_buffer, &c->c.buffer);
            memcpy(&ctx->mgm_ctx.mgm_iv, &ctx->mgm_ctx.partial_buffer, KUZNYECHIK_BLOCK_SIZE);
        }

        if (rest_len != 0) {
            /* Finalize partial_data */
            if (inl + rest_len < KUZNYECHIK_BLOCK_SIZE) {
                memcpy(ctx->mgm_ctx.partial_buffer.b + rest_len, current_in, inl);
                n += inl;
                ctx->mgm_ctx.num = n;
                return 1;
            } else {
                memcpy(ctx->mgm_ctx.mgm_partial_buffer.b + rest_len, current_in, KUZNYECHIK_BLOCK_SIZE - rest_len);
                kuznyechik_encrypt_block_internal(&ctx->kuznyechik_key, ctx->mgm_ctx.mgm_iv.b, h.b );
                //     kuznyechik_encrypt_block_(&c->c.encrypt_round_keys, &c->mgm_iv, &h, &c->c.buffer);
                inc_counter(ctx->mgm_ctx.mgm_iv.b, 8);

                /* Galois multiply Hi * Ai */
                gf128_mul_uint64(tmp.q, h.q, ctx->mgm_ctx.mgm_partial_buffer.q);

                /* XOR to c->tag */
                kuznyechik_plus128(&h, (kuznyechik_w128_t *) ctx->mgm_ctx.tag, &tmp);
                kuznyechik_copy128((kuznyechik_w128_t *) ctx->mgm_ctx.tag, &h);

                current_in += KUZNYECHIK_BLOCK_SIZE - rest_len;
                inl -= (KUZNYECHIK_BLOCK_SIZE - rest_len);
                n += KUZNYECHIK_BLOCK_SIZE - rest_len;
            }
        }

        while (inl >= KUZNYECHIK_BLOCK_SIZE) {
            currentInputBlock = (kuznyechik_w128_t *) current_in;
            kuznyechik_encrypt_block_internal(&ctx->kuznyechik_key, ctx->mgm_ctx.mgm_iv.b, h.b );
            //  kuznyechik_encrypt_block_(&c->c.encrypt_round_keys, &c->mgm_iv, &h, &c->c.buffer);
            inc_counter(ctx->mgm_ctx.mgm_iv.b, 8);

            /* Galois multiply */
            gf128_mul_uint64(tmp.q, h.q, currentInputBlock->q);

            /* XOR to c->tag */
            kuznyechik_plus128(&h, (kuznyechik_w128_t *)ctx->mgm_ctx.tag, &tmp);
            kuznyechik_copy128((kuznyechik_w128_t *) ctx->mgm_ctx.tag, &h);

            current_in += KUZNYECHIK_BLOCK_SIZE;
            inl -= KUZNYECHIK_BLOCK_SIZE;
            n += KUZNYECHIK_BLOCK_SIZE;
        }

        if (inl > 0) {
            memcpy(ctx->mgm_ctx.mgm_partial_buffer.b, current_in, inl);
            n += inl;
        }

        ctx->mgm_ctx.num = n;
        return 1;
    }

    if (out == 0 && in != 0 && inl != 0 && ctx->mgm_ctx.mgm_state == mgm_main_data) {
        return 0;
    }

    if (out != 0 && ctx->mgm_ctx.mgm_state == mgm_associated_data) {
        memset(ctx->mgm_ctx.mgm_partial_buffer.b + rest_len, 0,
               KUZNYECHIK_BLOCK_SIZE - rest_len);

        kuznyechik_encrypt_block_internal(&ctx->kuznyechik_key,ctx->mgm_ctx.mgm_iv.b, h.b );
        //kuznyechik_encrypt_block_(&c->c.encrypt_round_keys, &c->mgm_iv, &h, &c->c.buffer);
        inc_counter(ctx->mgm_ctx.mgm_iv.b, 8);

        /* Galois multiply Hi * Ai */
        gf128_mul_uint64(tmp.q, h.q, ctx->mgm_ctx.mgm_partial_buffer.q);

        /* XOR to c->tag */
        kuznyechik_plus128(&h, (kuznyechik_w128_t *) ctx->mgm_ctx.tag, &tmp);
        kuznyechik_copy128((kuznyechik_w128_t *) ctx->mgm_ctx.tag, &h);

        /* We finish processing associated data */
        /* Pad rest of mgm_partial_buffer */
        /* Process last block */
        ctx->mgm_ctx.ad_length = n;
        n = 0;
        rest_len = 0;
        ctx->mgm_ctx.num = 0;
        ctx->mgm_ctx.mgm_state = mgm_main_data;
    }

/* ======== Here we deal with main data =========== */
    if (n == 0) {

        /* actual IV derived from nonce */
        kuznyechik_encrypt_block_internal(&ctx->kuznyechik_key,iv_buffer->b ,ctx->mgm_ctx.partial_buffer.b );
        //kuznyechik_encrypt_block_(&c->c.encrypt_round_keys, iv_buffer, &c->partial_buffer, &c->c.buffer);
        memcpy(iv, ctx->mgm_ctx.partial_buffer.b, KUZNYECHIK_BLOCK_SIZE);
    }

    while (rest_len && inl) {
        *(current_out++) = *(current_in++) ^ ctx->mgm_ctx.partial_buffer.b[rest_len];

        if (encrypting)
            ctx->mgm_ctx.partial_buffer.b[rest_len] = *(current_out - 1);
        else
            ctx->mgm_ctx.partial_buffer.b[rest_len] = *(current_in - 1);

        --inl;
        n++;
        rest_len++;
        if (rest_len == KUZNYECHIK_BLOCK_SIZE) {
            rest_len = 0;
            kuznyechik_encrypt_block_internal(&ctx->kuznyechik_key,ctx->mgm_ctx.mgm_iv.b, h.b );
            //kuznyechik_encrypt_block_(&c->c.encrypt_round_keys, &c->mgm_iv,&h, &c->c.buffer);
            inc_counter(ctx->mgm_ctx.mgm_iv.b, 8);
            /* Galois multiply Hi * Ai */
            gf128_mul_uint64(tmp.q, h.q, ctx->mgm_ctx.partial_buffer.q);

            /* XOR to c->tag */
            kuznyechik_plus128(&h, (kuznyechik_w128_t *) ctx->mgm_ctx.tag, &tmp);
            kuznyechik_copy128((kuznyechik_w128_t *) ctx->mgm_ctx.tag, &h);
        }
    }

    // full parts
    for (i = 0; i < blocks; i++) {
        kuznyechik_encrypt_block_internal(&ctx->kuznyechik_key, ctx->mgm_ctx.mgm_iv.b, h.b );
        //kuznyechik_encrypt_block_(&c->c.encrypt_round_keys, &c->mgm_iv, &h, &c->c.buffer);
        inc_counter(ctx->mgm_ctx.mgm_iv.b, 8);

        currentInputBlock = (kuznyechik_w128_t *) current_in;
        currentOutputBlock = (kuznyechik_w128_t *) current_out;
        kuznyechik_encrypt_block_internal(&ctx->kuznyechik_key,iv_buffer->b, ctx->mgm_ctx.partial_buffer.b );
        //kuznyechik_encrypt_block_(&c->c.encrypt_round_keys, iv_buffer, &c->partial_buffer, &c->c.buffer);
        kuznyechik_plus128(&tmp, &ctx->mgm_ctx.partial_buffer, currentInputBlock);

        if (encrypting) {
            kuznyechik_copy128(currentOutputBlock, &tmp);

            /* Galois multiply Hi * Ai */
            gf128_mul_uint64(tmp.q, h.q, currentOutputBlock->q);

            /* XOR to c->tag */
            kuznyechik_plus128(&h, (kuznyechik_w128_t *) ctx->mgm_ctx.tag, &tmp);
            kuznyechik_copy128((kuznyechik_w128_t *) ctx->mgm_ctx.tag, &h);
        } else {
            kuznyechik_w128_t tmpin;
            kuznyechik_copy128(&tmpin, currentInputBlock);
            kuznyechik_copy128(currentOutputBlock, &tmp);

            /* Galois multiply Hi * Ai */
            gf128_mul_uint64(tmp.q, h.q, tmpin.q);

            /* XOR to c->tag */
            kuznyechik_plus128(&h, (kuznyechik_w128_t *) ctx->mgm_ctx.tag, &tmp);
            kuznyechik_copy128((kuznyechik_w128_t *) ctx->mgm_ctx.tag, &h);
        }

        ctr128_inc(iv_buffer->b);
        current_in += KUZNYECHIK_BLOCK_SIZE;
        current_out += KUZNYECHIK_BLOCK_SIZE;
        n += KUZNYECHIK_BLOCK_SIZE;
    }

    ctx->mgm_ctx.num = n;

    // last part
    lasted = inl - blocks * KUZNYECHIK_BLOCK_SIZE;
    if (lasted > 0) {
        currentInputBlock = (kuznyechik_w128_t *) current_in;
        currentOutputBlock = (kuznyechik_w128_t *) current_out;
        kuznyechik_encrypt_block_internal(&ctx->kuznyechik_key,iv_buffer->b, ctx->mgm_ctx.partial_buffer.b );
        //kuznyechik_encrypt_block_(&c->c.encrypt_round_keys, iv_buffer, &c->partial_buffer, &c->c.buffer);
        for (i = 0; i < lasted; i++) {
            if (encrypting) {
                currentOutputBlock->b[i] = ctx->mgm_ctx.partial_buffer.b[i] ^ currentInputBlock->b[i];
                ctx->mgm_ctx.partial_buffer.b[i] = currentOutputBlock->b[i];
            } else {
                unsigned char in = currentInputBlock->b[i];
                currentOutputBlock->b[i] = ctx->mgm_ctx.partial_buffer.b[i] ^ currentInputBlock->b[i];
                ctx->mgm_ctx.partial_buffer.b[i] = in;
            }
        }
        ctx->mgm_ctx.num = n + i;
        ctr128_inc(iv_buffer->b);
    }

    /* Final step */
    if (in == 0 && inl == 0) {
        unsigned char len_buf[16];
        uint64_t a_len = 0, p_len = 0;

        if (rest_len != 0) {
            memset(ctx->mgm_ctx.partial_buffer.b + rest_len, 0, KUZNYECHIK_BLOCK_SIZE - rest_len);
            kuznyechik_encrypt_block_internal(&ctx->kuznyechik_key, ctx->mgm_ctx.mgm_iv.b, h.b );
//            kuznyechik_encrypt_block_(&c->c.encrypt_round_keys, &c->mgm_iv, &h, &c->c.buffer);
            inc_counter(ctx->mgm_ctx.mgm_iv.b, 8);
            /* Galois multiply Hi * Ai */
            gf128_mul_uint64(tmp.q, h.q, ctx->mgm_ctx.partial_buffer.q);

            /* XOR to c->tag */
            kuznyechik_plus128(&h, (kuznyechik_w128_t *) ctx->mgm_ctx.tag, &tmp);
            kuznyechik_copy128((kuznyechik_w128_t *) ctx->mgm_ctx.tag, &h);
        }

        a_len = ctx->mgm_ctx.ad_length << 3;
        p_len = (ctx->mgm_ctx.mgm_state == mgm_associated_data) ? 0 : n << 3;

        a_len = cpu_to_be64(a_len);
        p_len = cpu_to_be64(p_len);

        memset(len_buf, 0, 16);

        memcpy(len_buf, &a_len, sizeof(a_len));
        memcpy(len_buf + sizeof(a_len), &p_len, sizeof(p_len));
        kuznyechik_encrypt_block_internal(&ctx->kuznyechik_key,ctx->mgm_ctx.mgm_iv.b, h.b );

        /* Galois multiply Hi * Ai */
        gf128_mul_uint64(tmp.q, h.q, (uint64_t *)len_buf);

        /* XOR to c->tag */
        kuznyechik_plus128(&h, (kuznyechik_w128_t *) ctx->mgm_ctx.tag, &tmp);
        kuznyechik_copy128((kuznyechik_w128_t *) ctx->mgm_ctx.tag, &h);

        /* Final tag calculation */
        kuznyechik_encrypt_block_internal(&ctx->kuznyechik_key, ctx->mgm_ctx.tag, ctx->mgm_ctx.final_tag);
        return 1;
    }

    return (int)inl;
}


void kuznyechik_mgm_init(struct gost_esp_mgmkuznyechik_ctx *ctx, u8 *iv, const u8 *aad, unsigned long aad_len)
{
    memset(&ctx->mgm_ctx.partial_buffer.b, 0, 16); // kuznyechik_zero128(&c->partial_buffer);
    memset(ctx->mgm_ctx.tag, 0, 16);

    ctx->mgm_ctx.mgm_state = 0;   /// associated_data/plain text
    ctx->mgm_ctx.num = 0;
    ctx->mgm_ctx.taglen = 12;

    if (iv) {
        memcpy(ctx->mgm_ctx.mgm_iv.b, iv, 16);
        *(unsigned char *)(ctx->mgm_ctx.mgm_iv.b) |= 0x80; // set 1 st bit to 1
        memcpy(ctx->mgm_ctx.original_iv.b, iv, 16);
    }

    if (aad_len) {
        gost_kuznyechik_cipher_do_mgm(ctx, NULL, aad, aad_len);
    }
}



void kuznyechik_mgm_enc_update(struct gost_esp_mgmkuznyechik_ctx *ctx, u8 *out, const u8 *in, unsigned long plaintext_len)
{
#ifdef DEBUG_OUTPUT
    hexdump("kuznyechik_mgm_enc_update in:", in, plaintext_len );
#endif
    gost_kuznyechik_cipher_do_mgm(ctx, out, in, plaintext_len);
#ifdef DEBUG_OUTPUT
    hexdump("kuznyechik_mgm_enc_update out:", out, plaintext_len );
#endif
}

void kuznyechik_mgm_dec_update(struct gost_esp_mgmkuznyechik_ctx *ctx, u8 *out, const u8 *in, unsigned long ciphertext_len)
{
#ifdef DEBUG_OUTPUT
    hexdump("kuznyechik_mgm_dec_update in:", in, ciphertext_len );
#endif
    gost_kuznyechik_cipher_do_mgm(ctx, out, in, ciphertext_len);
#ifdef DEBUG_OUTPUT
    hexdump("kuznyechik_mgm_dec_update out:", out, ciphertext_len );
#endif
}

void kuznyechik_mgm_finalize(struct gost_esp_mgmkuznyechik_ctx *ctx)
{
    gost_kuznyechik_cipher_do_mgm(ctx, 0, 0, 0);
}



static inline struct gost_esp_mgmkuznyechik_ctx * gost_esp_mgmkuznyechik_ctx_get(struct crypto_aead *tfm)
{
    unsigned long align = KUZNYECHIK_ALIGN;

    if (align <= crypto_tfm_ctx_alignment())
        align = 1;
    return PTR_ALIGN(crypto_aead_ctx(tfm), align);
}



static int calc_hash(struct crypto_ahash *tfm,
                     const u8* key, size_t key_len,
                     const u8* in, size_t in_len,
                     u8 * out, size_t out_len)
{
    struct scatterlist sg[8];

    struct ahash_request *req;
    struct crypto_wait wait;
    int ret = -ENOMEM;
    size_t digest_size = crypto_ahash_digestsize(tfm);

    crypto_init_wait(&wait);

    req = ahash_request_alloc(tfm, GFP_KERNEL);
    if (!req) {
        pr_err("kuznyechik_mgm_esp: hash: Failed to allocate request\n");
        goto out_noreq;
    }
    ahash_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, crypto_req_done, &wait);

    ret = -EINVAL;

    memset(out, 0, digest_size);

    sg_init_one(&sg[0], in, in_len);

    crypto_ahash_clear_flags(tfm, ~0);

    ret = crypto_ahash_setkey(tfm, key, key_len);
    if (ret) {
        pr_err("kuznyechik_mgm_esp: hash: setkey failed. ret=%d\n", ret);
        goto out;
    }

    ahash_request_set_crypt(req, sg, out, in_len);

    ret = crypto_wait_req(crypto_ahash_digest(req), &wait);
    if (ret) {
        pr_err("kuznyechik_mgm_esp: hash: digest failed: ret=%d\n", -ret);
        goto out;
    }

    ret = 0;

out:
    ahash_request_free(req);
out_noreq:
    return ret;
}



int gost_kdftree2012_256(unsigned char *keyout, size_t keyout_len,
                         const unsigned char *key, size_t keylen,
                         const unsigned char *label, size_t label_len,
                         const unsigned char *seed, size_t seed_len,
                         const size_t representation)
{
    int iters, i = 0;
    int ret = -ENOMEM;
    unsigned char zero = 0;

    struct crypto_ahash *tfm;
    unsigned char *len_ptr = NULL;
    u8 * in;
    u8 * in_ptr;
    size_t in_len = 0;

    uint32_t len_repr = htonl(keyout_len * 8);  // htonl( 256 )

    size_t len_repr_len = 4;

    if ((keyout_len == 0) || (keyout_len % 32 != 0)) {
        return 0;
    }


    tfm = crypto_alloc_ahash("hmac(streebog256)", 0, 0);

    if (IS_ERR(tfm)) {
        pr_err("kuznyechik_mgm_esp: gost_kdftree2012_256: hash: Failed to load transform: %ld\n", PTR_ERR(tfm));
        return PTR_ERR(tfm);
    }

    iters = keyout_len / 32; // 1

    len_ptr = (unsigned char *)&len_repr;
    while (*len_ptr == 0) {
        len_ptr++;
        len_repr_len--;
    }

    for (i = 1; i <= iters; i++) {
        uint32_t iter_net = htonl(i);
        unsigned char *rep_ptr = ((unsigned char *)&iter_net) + (4 - representation);

        in_len = representation + label_len + 1 + seed_len + len_repr_len;

        in = kmalloc( in_len,  GFP_KERNEL);
        if (!in) {
            goto out;
        }

        in_ptr = in;
        memcpy(in_ptr, rep_ptr, representation); in_ptr += representation;
        memcpy(in_ptr, label, label_len); in_ptr += label_len;
        memcpy(in_ptr, &zero, 1); in_ptr += 1;
        memcpy(in_ptr, seed, seed_len); in_ptr += seed_len;
        memcpy(in_ptr, len_ptr, len_repr_len);

        calc_hash(tfm, key, keylen, in, in_len, keyout, keyout_len );

        kfree(in);
    }
    ret = 0;

out:
    crypto_free_ahash(tfm);

    return ret;
}


/**
 * @brief calc_K_msg_from_key
 * @param u8* key - master key buf of 32 bytes
 * @param iv      - iv received
 *
                          1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |      i1       |               i2              |      i3       |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |   i3 (cont)   |                     pnum                      |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                            Figure 1: IV Format
   @param u64 stored_iv  - old iv
   @param u8* k_msg      - buffer for store k_msg (at least 32 bytes)
 * @return 0 - USE OLD k_msg
 *         1 - New k_msg generated and stored in k_msg.
 */
static int calc_K_msg_from_key(struct gost_esp_mgmkuznyechik_ctx *ctx, const u8 * iv)
{
    u8* key;
    u_char hmac[32];

    unsigned char label1[6] = {'l','e','v','e','l','1' };
    unsigned char label2[6] = {'l','e','v','e','l','2' };
    unsigned char label3[6] = {'l','e','v','e','l','3' };

    u16 i1, i2, i3;

    // Calculation of K_msg from K, i1,i1,i3,pnum
    u64 iv64_with_zeroed_pnum = *(u64*)iv & 0x000000ffffffffff;

    if (iv64_with_zeroed_pnum == ctx->iv64_with_zeroed_pnum) {
        return 0;
    }

    i1 = *(iv) << 8;
    i2 = ((u16)(*(iv + 2)) << 8) | *(iv + 1);
    i3 = ((u16)(*(iv + 4)) << 8) | *(iv + 3);

    key = kmalloc(32,  GFP_KERNEL);
    memcpy(key, ctx->key, 32);

    gost_kdftree2012_256(hmac, 32, key,   32, label1, 6, (const unsigned char*)&i1, 2, 1);

    memcpy((void*)key, hmac, 32);
    gost_kdftree2012_256(hmac, 32, key,  32, label2, 6, (const unsigned char*)&i2, 2, 1);

    memcpy((void*)key, hmac, 32);
    gost_kdftree2012_256(hmac, 32, key,  32, label3, 6, (const unsigned char*)&i3, 2, 1);
    memcpy(ctx->K_msg, hmac, 32);

#ifdef DEBUG_OUTPUT
    hexdump("Calc K_msg:", ctx->K_msg, 32 );
#endif

    ctx->iv64_with_zeroed_pnum = iv64_with_zeroed_pnum;
    kfree(key);

    return 1;
}



// Сюда передается конкатенированный ключ и salt (12 байт)
static int gost_esp_mgmkuznyechik_set_key(struct crypto_aead *aead, const u8 *key, unsigned int key_len)
{
    struct gost_esp_mgmkuznyechik_ctx *ctx = gost_esp_mgmkuznyechik_ctx_get(aead);

#ifdef DEBUG_OUTPUT
    printk(KERN_INFO "gost_esp_mgmkuznyechik_set_key key_len: %d\n", key_len);
    hexdump("key:", key, key_len );
#endif

    if (key_len != KUZNYECHIK_KEY_SIZE + GOST_ESP_MGM_KUZNYECHIK_SALT_LEN) {
        printk(KERN_ERR "kuznyechik_mgm_esp: gost_esp_mgmkuznyechik_set_key: key_len invalid\n");
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
        u32 *flags = &aead->base.crt_flags;
        *flags |= CRYPTO_TFM_RES_BAD_KEY_LEN;
#endif
        return -EINVAL;
    }

    memcpy(ctx->key, key, key_len);

    ctx->iv64_with_zeroed_pnum = 0xffffff0000000000;

    memcpy(ctx->salt, key + key_len - GOST_ESP_MGM_KUZNYECHIK_SALT_LEN, GOST_ESP_MGM_KUZNYECHIK_SALT_LEN);

    return 0;
}



static int gost_esp_mgmkuznyechik_set_authsize(struct crypto_aead *tfm, unsigned int authsize)
{
#ifdef DEBUG_OUTPUT
    printk(KERN_INFO "gost_esp_mgmkuznyechik_set_authsize key_len: %d\n", authsize);

#endif
    switch (authsize) {
    case 8:
    case 12:
    case 16:
        break;
    default:
        return -EINVAL;
    }

    return 0;
}



/* 4.2.  Initialization Vector Format
 * Each message protected by the defined transforms must contain
   Initialization Vector (IV).  The IV has a size of 64 bits and
   consists of the four fields, three of which are i1, i2 and i3
   parameters that determine the particular leaf key this message was
   protected with (see Section 4.1), and the fourh is a counter,
   representing the message number for this key.

                          1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |      i1       |               i2              |      i3       |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |   i3 (cont)   |                     pnum                      |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                            Figure 1: IV Format

   where:

   o  i1 (1 octet), i2 (2 octets), i3 (2 octets) - parameters,
      determining the particular key used to protect this message;
      2-octets parameters are integers in network byte order

   o  pnum (3 octets) - message counter in network byte order for the
      leaf key protecting this message; up to 2^24 messages may be
      protected using a single leaf key

      в req->iv - 64 bit   iv   received from ipsec  ()
 */


static int gost_esp_mgmkuznyechik_encrypt(struct aead_request *req)
{
    unsigned int i;
    unsigned long auth_tag_len;
    u8 *iv;

    struct scatter_walk dst_sg_walk = {};

    unsigned long left = req->cryptlen;
    unsigned long len, srclen, dstlen;

    struct scatter_walk assoc_sg_walk;
    struct scatter_walk src_sg_walk;

    struct scatterlist src_start[2];
    struct scatterlist dst_start[2];
    struct scatterlist *src_sg;
    struct scatterlist *dst_sg;

    u8 *src, *dst, *assoc;
    u8 *assocmem = NULL;
    u8 authTag[16];

    struct crypto_aead *tfm = crypto_aead_reqtfm(req);
    struct gost_esp_mgmkuznyechik_ctx *ctx = gost_esp_mgmkuznyechik_ctx_get(tfm);

//    u8 nonce_buf[16 + (KUZNYECHIK_ALIGN - 8)] __aligned(8);
//    u8 *nonce = PTR_ALIGN(&nonce_buf[0], KUZNYECHIK_ALIGN);

    u8 nonce_buf[16];
    u8 *nonce = nonce_buf;  // Заготовка для align

    if (req->assoclen != 16) {
        return -EINVAL;
    }

    ctx->mgm_ctx.encrypting = 1;

//-----
#ifdef DEBUG_OUTPUT
    printk(KERN_INFO "gost_esp_mgmkuznyechik_encrypt req->assoclen: %d req->cryptlen: %d\n", req->assoclen, req->cryptlen);
#endif

    auth_tag_len = crypto_aead_authsize(tfm);


    /* Linearize assoc, if not already linear */
    if (req->src->length >= req->assoclen && req->src->length && (!PageHighMem(sg_page(req->src)) ||
            req->src->offset + req->src->length <= PAGE_SIZE)) {
        scatterwalk_start(&assoc_sg_walk, req->src);
        assoc = scatterwalk_map(&assoc_sg_walk);
    } else {
        /* assoc can be any length, so must be on heap */
        assocmem = kmalloc(req->assoclen, GFP_ATOMIC);
        if (unlikely(!assocmem)) {
            return -ENOMEM;
        }
        assoc = assocmem;

        scatterwalk_map_and_copy(assoc, req->src, 0, req->assoclen, 0);
    }

    iv = assoc + 8; // !!!!

    if (calc_K_msg_from_key(ctx, iv) == 1) {
        memcpy(ctx->kuznyechik_key.key, ctx->K_msg,  32);
        subkey(ctx->kuznyechik_key.key + 32,  ctx->kuznyechik_key.key, 0);
        subkey(ctx->kuznyechik_key.key + 64,  ctx->kuznyechik_key.key + 32, 8);
        subkey(ctx->kuznyechik_key.key + 96,  ctx->kuznyechik_key.key + 64, 16);
        subkey(ctx->kuznyechik_key.key + 128, ctx->kuznyechik_key.key + 96, 24);
        for (i = 0; i < 10; i++) {
            Linv(ctx->kuznyechik_key.dekey + 16 * i, ctx->kuznyechik_key.key + 16 * i);
        }
    }


#ifdef DEBUG_OUTPUT
    hexdump("gost_esp_mgmkuznyechik_encrypt assoc:", assoc, req->assoclen );
    hexdump("gost_esp_mgmkuznyechik_encrypt iv:", iv, 8 );
#endif

    if (left) {
        src_sg = scatterwalk_ffwd(src_start, req->src, req->assoclen);
        scatterwalk_start(&src_sg_walk, src_sg);
        if (req->src != req->dst) {
            dst_sg = scatterwalk_ffwd(dst_start, req->dst, req->assoclen);
            scatterwalk_start(&dst_sg_walk, dst_sg);
        }
    }


/* 4.3.1.  MGM Nonce Format for "Kuznyechik" based Transforms

   For transforms based on "Kuznyechik" cipher
   (ENCR_KUZNYECHIK_MGM_KTREE and ENCR_KUZNYECHIK_MGM_MAC_KTREE) the ICN
   consists of a zero octet, a 24-bit message counter and a 96-bit
   secret salt, that is fixed for SA and is not transmitted.

                          1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |     zero      |                     pnum                      |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     |                             salt                              |
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

         Figure 2: Nonce format for "Kuznyechik" based transforms

   where:

   o  zero (1 octet) - set to 0

   o  pnum (3 octets) - the counter for the messages protected by the
      given leaf key; this field MUST be equal to the pnum field in the
      IV

   o  salt (12 octets) - secret salt
 * */
    *nonce = 0;
    *(nonce+1) = iv[5]; // iv[5-7] - pnum
    *(nonce+2) = iv[6];
    *(nonce+3) = iv[7];

    memcpy((nonce + 4), ctx->salt,  GOST_ESP_MGM_KUZNYECHIK_SALT_LEN);

    // Далее nonce используется как iv для собственно mgm_encrypt
    // Для mgm_encrypt нужно
    // key -  ctx->K_msg
    // iv  -  nonce
    // aad -  assoc
#ifdef DEBUG_OUTPUT
    hexdump("gost_esp_mgmkuznyechik_encrypt nonce:", nonce, 16 );
#endif

    kuznyechik_mgm_init(ctx, nonce, assoc, 8 /* assoclen*/);

    if (req->src != req->dst) {
        while (left) {
            src = scatterwalk_map(&src_sg_walk);
            dst = scatterwalk_map(&dst_sg_walk);
            srclen = scatterwalk_clamp(&src_sg_walk, left);
            dstlen = scatterwalk_clamp(&dst_sg_walk, left);
            len = min(srclen, dstlen);
            if (len) {
                kuznyechik_mgm_enc_update(ctx, dst, src, len);
            }
            left -= len;

            scatterwalk_unmap(src);
            scatterwalk_unmap(dst);
            scatterwalk_advance(&src_sg_walk, len);
            scatterwalk_advance(&dst_sg_walk, len);
            scatterwalk_done(&src_sg_walk, 0, left);
            scatterwalk_done(&dst_sg_walk, 1, left);
        }
    } else {
        // req->src == req->dst inplace encryption
        while (left) {
            dst = src = scatterwalk_map(&src_sg_walk);
            len = scatterwalk_clamp(&src_sg_walk, left);
            if (len) {
                kuznyechik_mgm_enc_update(ctx, src, src, len);
            }
            left -= len;
            scatterwalk_unmap(src);
            scatterwalk_advance(&src_sg_walk, len);
            scatterwalk_done(&src_sg_walk, 1, left);
        }
    }
    kuznyechik_mgm_finalize(ctx);
    memcpy(authTag, ctx->mgm_ctx.final_tag, auth_tag_len);

    if (!assocmem) {
        scatterwalk_unmap(assoc);
    } else {
        kfree(assocmem);
    }

    /* Copy in the authTag */
    scatterwalk_map_and_copy(authTag, req->dst, req->assoclen + req->cryptlen, auth_tag_len, 1);
#ifdef DEBUG_OUTPUT
    hexdump("auth_tag:", authTag, auth_tag_len );
#endif
    return 0;
}



static int gost_esp_mgmkuznyechik_decrypt(struct aead_request *req)
{
    unsigned int i;
    unsigned long auth_tag_len;
    u8 *iv;
    unsigned long len, srclen, dstlen;
    unsigned long left;

    struct scatter_walk assoc_sg_walk;
    struct scatter_walk src_sg_walk;

    struct scatterlist src_start[2];
    struct scatterlist dst_start[2];
    struct scatterlist *src_sg;
    struct scatterlist *dst_sg;

    u8 *src, *dst, *assoc;
    u8 *assocmem = NULL;
    u8 authTag[16];
    struct scatter_walk dst_sg_walk = {};


    struct crypto_aead *tfm = crypto_aead_reqtfm(req);
    struct gost_esp_mgmkuznyechik_ctx*ctx = gost_esp_mgmkuznyechik_ctx_get(tfm);

    u8 nonce_buf[16];
    u8 *nonce = nonce_buf;  // Заготовка для align

    u8 authTagMsg[16];

#ifdef DEBUG_OUTPUT
    printk(KERN_INFO "gost_esp_mgmkuznyechik_decrypt req->assoclen: %d req->cryptlen: %d\n", req->assoclen, req->cryptlen);
#endif

    if (req->assoclen != 16) {
        return -EINVAL;
    }
    ctx->mgm_ctx.encrypting = 0;

    auth_tag_len = crypto_aead_authsize(tfm);

    left = req->cryptlen - auth_tag_len;

    /* Linearize assoc, if not already linear */
    if (req->src->length >= req->assoclen && req->src->length && (!PageHighMem(sg_page(req->src)) ||
            req->src->offset + req->src->length <= PAGE_SIZE)) {
        scatterwalk_start(&assoc_sg_walk, req->src);
        assoc = scatterwalk_map(&assoc_sg_walk);
    } else {
        /* assoc can be any length, so must be on heap */
        assocmem = kmalloc(req->assoclen, GFP_ATOMIC);
        if (unlikely(!assocmem)) {
            return -ENOMEM;
        }
        assoc = assocmem;

        scatterwalk_map_and_copy(assoc, req->src, 0, req->assoclen, 0);
    }

    iv = assoc + 8;

    if (calc_K_msg_from_key(ctx, iv) == 1) {
        memcpy(ctx->kuznyechik_key.key, ctx->K_msg,  32);
        subkey(ctx->kuznyechik_key.key + 32,  ctx->kuznyechik_key.key, 0);
        subkey(ctx->kuznyechik_key.key + 64,  ctx->kuznyechik_key.key + 32, 8);
        subkey(ctx->kuznyechik_key.key + 96,  ctx->kuznyechik_key.key + 64, 16);
        subkey(ctx->kuznyechik_key.key + 128, ctx->kuznyechik_key.key + 96, 24);
        for (i = 0; i < 10; i++) {
            Linv(ctx->kuznyechik_key.dekey + 16 * i, ctx->kuznyechik_key.key + 16 * i);
        }
    }


#ifdef DEBUG_OUTPUT
    hexdump("gost_esp_mgmkuznyechik_decrypt assoc:", assoc, req->assoclen );
    hexdump("gost_esp_mgmkuznyechik_decrypt iv:", iv, 8 );
#endif

    if (left) {
        src_sg = scatterwalk_ffwd(src_start, req->src, req->assoclen);
        scatterwalk_start(&src_sg_walk, src_sg);
        if (req->src != req->dst) {
            dst_sg = scatterwalk_ffwd(dst_start, req->dst, req->assoclen);
            scatterwalk_start(&dst_sg_walk, dst_sg);
        }
    }


    *nonce = 0;
    *(nonce+1) = iv[5]; // iv[5-7] - pnum
    *(nonce+2) = iv[6];
    *(nonce+3) = iv[7];

    memcpy((nonce + 4), ctx->salt,  GOST_ESP_MGM_KUZNYECHIK_SALT_LEN);

    // Далее nonce используется как iv для собственно mgm_encrypt
#ifdef DEBUG_OUTPUT
    hexdump("gost_esp_mgmkuznyechik_encrypt nonce:", nonce, 16 );
#endif

    kuznyechik_mgm_init(ctx, nonce, assoc, 8 /* assoclen*/);

    if (req->src != req->dst) {
        while (left) {
            src = scatterwalk_map(&src_sg_walk);
            dst = scatterwalk_map(&dst_sg_walk);
            srclen = scatterwalk_clamp(&src_sg_walk, left);
            dstlen = scatterwalk_clamp(&dst_sg_walk, left);
            len = min(srclen, dstlen);
            if (len) {
                kuznyechik_mgm_dec_update(ctx, dst, src, len);
            }
            left -= len;

            scatterwalk_unmap(src);
            scatterwalk_unmap(dst);
            scatterwalk_advance(&src_sg_walk, len);
            scatterwalk_advance(&dst_sg_walk, len);
            scatterwalk_done(&src_sg_walk, 0, left);
            scatterwalk_done(&dst_sg_walk, 1, left);
        }
    } else {
        // req->src == req->dst inplace encryption
        while (left) {
            dst = src = scatterwalk_map(&src_sg_walk);
            len = scatterwalk_clamp(&src_sg_walk, left);
            if (len) {
                kuznyechik_mgm_dec_update(ctx, src, src, len);
            }
            left -= len;
            scatterwalk_unmap(src);
            scatterwalk_advance(&src_sg_walk, len);
            scatterwalk_done(&src_sg_walk, 1, left);
        }
    }
//    mgm_tfm->finalize(ctx, data, authTag, auth_tag_len);
    kuznyechik_mgm_finalize(ctx/*, authTag, auth_tag_len*/);
    memcpy(authTag, ctx->mgm_ctx.final_tag, auth_tag_len);

    if (!assocmem) {
        scatterwalk_unmap(assoc);
    } else {
        kfree(assocmem);
    }

    /* Copy out original authTag */
    scatterwalk_map_and_copy(authTagMsg, req->src, req->assoclen + req->cryptlen - auth_tag_len, auth_tag_len, 0);

#ifdef DEBUG_OUTPUT
    hexdump("auth_tag:", authTagMsg, auth_tag_len );
#endif

    // Compare calculated  tag with passed in tag.
    return crypto_memneq(authTagMsg, ctx->mgm_ctx.final_tag, auth_tag_len) ? -EBADMSG : 0;
}


static struct aead_alg kuznyechik_aeads[] = { {
    .setkey			= gost_esp_mgmkuznyechik_set_key,
    .setauthsize	= gost_esp_mgmkuznyechik_set_authsize,
    .encrypt		= gost_esp_mgmkuznyechik_encrypt,
    .decrypt		= gost_esp_mgmkuznyechik_decrypt,
    .ivsize			= MGM_KUZNYECHIKESP_IV_SIZE,
    .maxauthsize	= 16,
    .base = {
        .cra_name       	= "gost_esp(mgm(kuznyechik))",
        .cra_driver_name	= "gost_esp-mgm-kuznyechik",
        .cra_priority		= 100,
        .cra_flags      	= CRYPTO_ALG_ASYNC | CRYPTO_ALG_TYPE_AEAD,
        .cra_blocksize		= 1,
        .cra_ctxsize		= sizeof(struct gost_esp_mgmkuznyechik_ctx),
        .cra_alignmask		= KUZNYECHIK_ALIGN - 1,
        .cra_module     	= THIS_MODULE,
    },
},

};



static int __init kuznyechik_init(void)
{
    int err;

    err = crypto_register_alg(&kuznyechik_alg);
    if (err)
        return err;

    err = crypto_register_aeads(kuznyechik_aeads, ARRAY_SIZE(kuznyechik_aeads));

    if (err)
        goto unregister_cipher;

    pr_info("kuznyechik_mgm_esp initialized\n");

    return 0;

unregister_cipher:
    crypto_unregister_alg(&kuznyechik_alg);
    return err;
}

static void __exit kuznyechik_fini(void)
{
    crypto_unregister_aeads(kuznyechik_aeads, ARRAY_SIZE(kuznyechik_aeads));
	crypto_unregister_alg(&kuznyechik_alg);
}

module_init(kuznyechik_init);
module_exit(kuznyechik_fini);

MODULE_DESCRIPTION("GOST R 34.12-2015 (Kuznyechik) algorithm RFC 9227 MGM mode for esp");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS_CRYPTO("kuznyechik");
MODULE_ALIAS_CRYPTO("kuznyechik-mgm");
