#include "scomm.h"

CryptoCtx ctx;

static int 
get_rand_num(void *r, unsigned long len)
{
    unsigned long nread;
    uchar *buf;

    buf = zalloc(len);
    if (buf == NULL)
       return CRYPT_MEM;

    nread = yarrow_read(buf, len, &(ctx.prng));
    if (nread != len) {
        free(buf);
        return CRYPT_ERROR_READPRNG;
    }
           
    mp_read_unsigned_bin(r, buf, len);

    free(buf);
    return CRYPT_OK;
}

static int 
pack_dh_params()
{
    int soi;
    uint32_t n, nlen;
    uchar *ptr;

    soi = sizeof(uint32_t);
    nlen = strlen(username);

    ctx.dhp.packed_len = ctx.dhp.g.len + ctx.dhp.p.len + 
        ctx.dhp.g_exp_a.len + nlen + (3*soi) + 1;

    ctx.dhp.packed = zalloc(ctx.dhp.packed_len);
    if (ctx.dhp.packed == NULL)
        return -1;

    ptr = ctx.dhp.packed;

    //g length
    n = htonl(ctx.dhp.g.len);
    memcpy(ptr, &n, soi); ptr += soi;
    //g
    mp_to_unsigned_bin(ctx.dhp.g.n, ptr); ptr += ctx.dhp.g.len;

    //p length
    n = htonl(ctx.dhp.p.len);
    memcpy(ptr, &n, soi); ptr += soi;
    //p
    mp_to_unsigned_bin(ctx.dhp.p.n, ptr); ptr += ctx.dhp.p.len;

    //g^a length
    n = htonl(ctx.dhp.g_exp_a.len);
    memcpy(ptr, &n, soi); ptr += soi;
    //g^a
    mp_to_unsigned_bin(ctx.dhp.g_exp_a.n, ptr); ptr += ctx.dhp.g_exp_a.len;

    //name
    memcpy(ptr, username, nlen+1);

    return 0;
}

static int 
get_dh_params()
{
    int ret, err, res;
    void *q, *tmp, *g, *p, *a, *g_exp_a;
        
    if ((err = mp_init_multi(&p, &q, &tmp, &g, &a, &g_exp_a, NULL)) != CRYPT_OK)
        return -1;

    do {
        if ((err = rand_prime(q, 32, &(ctx.prng), find_prng("yarrow"))) != CRYPT_OK)
            goto err_exit;

        // p = 2q + 1
        mp_mul_d(q, 2, tmp);
        mp_add_d(tmp, 1, p);

        if ((err = mp_prime_is_prime(p, 8, &res)) != CRYPT_OK)
            goto err_exit;
    } while (res == LTC_MP_NO);


    res = 0;
    do {
        if ((err = get_rand_num(g, 16)) != CRYPT_OK)
            goto err_exit;

        // is g a primitive root?
        mp_mod(g, p, tmp); // tmp = g mod p
        if (mp_cmp_d(tmp, 1) != LTC_MP_EQ) {
            mp_sqrmod(g, p, tmp); // tmp = g^2 mod p
            if (mp_cmp_d(tmp, 1) != LTC_MP_EQ) {
                mp_exptmod(g, q, p, tmp); // tmp = g^q mod p
                if (mp_cmp_d(tmp, 1) != LTC_MP_EQ) {
                    res = 1;
                }
            }
        }
    } while (res == 0);


    if ((err = get_rand_num(a, 16)) != CRYPT_OK)
        goto err_exit;
            
    mp_exptmod(g, a, p, g_exp_a);

    /* Note tmp will now be = p-1 = 2q
     * We know g^q != 1 mod p from above
     * But g^q = g^((p-1)/2) = (g^(p-1))^(1/2) = 1^(1/2) = 1 or -1
     * Must be -1 mod p i.e. p-1 = 2q
     */

    //store
    ctx.dhp.g.n = g;
    ctx.dhp.p.n = p;
    ctx.dhp.a.n = a;
    ctx.dhp.g_exp_a.n = g_exp_a;
    ctx.dhp.g.len = mp_unsigned_bin_size(g);
    ctx.dhp.p.len = mp_unsigned_bin_size(p);
    ctx.dhp.a.len = mp_unsigned_bin_size(a);
    ctx.dhp.g_exp_a.len = mp_unsigned_bin_size(g_exp_a);

    if (pack_dh_params() == -1)
        goto err_exit;

    ret = 0;

err_exit:
    mp_clear(q); 
    mp_clear(tmp);

    if (ret == -1) {
        mp_clear(g); 
        mp_clear(p);
        mp_clear(a); 
        mp_clear(g_exp_a);
    }

    return ret;
}

void 
init_crypto()
{
    ltc_mp = gmp_desc;
    int err;

    register_cipher(&aes_desc);

    if (register_hash(&sha256_desc) == -1)
        die("FATAL: register_hash failed");

    if (register_prng(&yarrow_desc) == -1)
        die("FATAL: register_prng failed");

    ctx.cipher_idx = find_cipher("aes");
    ctx.hash_idx = find_hash("sha256");

    ctx.ivsize = cipher_descriptor[ctx.cipher_idx].block_length;
    ctx.ks = hash_descriptor[ctx.hash_idx].hashsize;
    if (cipher_descriptor[ctx.cipher_idx].keysize(&(ctx.ks)) != CRYPT_OK)
        die("FATAL: error getting keysize");

    if ((err = rng_make_prng(128, find_prng("yarrow"), &(ctx.prng), NULL)) != CRYPT_OK)
        die("FATAL: rng_make_prng failed");

    if (get_dh_params() == -1)
        die("FATAL: get_dh_params failed");
}

int 
get_key(uchar *buf, int len, uchar *key, unsigned long *keylen)
{
    int err, ret, g_exp_ab_len;
    void *g_exp_b, *g_exp_ab;
    uchar tmp[128];

    ret = -1;
    if ((err = mp_init_multi(&g_exp_b, &g_exp_ab, NULL)) != CRYPT_OK)
        return -1;
    mp_read_unsigned_bin(g_exp_b, buf, len);
    mp_exptmod(g_exp_b, ctx.dhp.a.n, ctx.dhp.p.n, g_exp_ab);
    g_exp_ab_len = mp_unsigned_bin_size(g_exp_ab);
    mp_to_unsigned_bin(g_exp_ab, tmp);

    if (hash_memory(ctx.hash_idx, tmp, g_exp_ab_len, key, keylen) != CRYPT_OK)
        goto err_exit;

    ret = 0;

err_exit:
    mp_clear(g_exp_b); 
    mp_clear(g_exp_ab);

    return ret;
}

int 
parse_dh_args( uchar *buf, char **name, uchar **key, int *outlen)
{
    int err, ret, soi, sz;
    uint32_t n;
    unsigned long len_in, len_out;
    void *g, *p, *g_exp_a, *g_exp_b, *k;
    uchar tmp[128], keytmp[128], *ptr;

    if ((err = mp_init_multi(&g, &p, &g_exp_a, &g_exp_b, &k, NULL)) != CRYPT_OK)
        return -1;

    ptr = buf;
    soi = sizeof(uint32_t);
    ret = -1;

    n = ntohl(*(uint32_t *)ptr); ptr += soi;
    mp_read_unsigned_bin(g, ptr, n); ptr += n;
    n = ntohl(*(uint32_t *)ptr); ptr += soi;
    mp_read_unsigned_bin(p, ptr, n); ptr += n;
    n = ntohl(*(uint32_t *)ptr); ptr += soi;
    mp_read_unsigned_bin(g_exp_a, ptr, n); ptr += n;
    n = _strlen(ptr);
    *name = zalloc(n+1);
    if (*name == NULL)
        goto err_exit;
    memcpy(*name, ptr, n);

    mp_exptmod(g, ctx.dhp.a.n, p, g_exp_b); //g^b

    mp_exptmod(g_exp_a, ctx.dhp.a.n, p, k); //(g^a)^b = key
    len_in = mp_unsigned_bin_size(k);
    mp_to_unsigned_bin(k, tmp);

    len_out = sizeof(keytmp);
    if (hash_memory(ctx.hash_idx, tmp, len_in, keytmp, &len_out) != CRYPT_OK)
        goto err_exit;

    *key = zalloc(len_out);
    if (*key == NULL)
        goto err_exit;
    memcpy(*key, keytmp, len_out);

    // put g^b and name into buf to send back
    ptr = buf;

    //g^b
    sz = mp_unsigned_bin_size(g_exp_b);
    n = htonl(sz);
    memcpy(ptr, &n, soi); ptr += soi;
    mp_to_unsigned_bin(g_exp_b, ptr); ptr += sz;

    //name
    sz = strlen(username)+1;
    memcpy(ptr, username, sz); ptr += sz;

    *outlen = ptr-buf;

    ret = 0;

err_exit:
    mp_clear(g); 
    mp_clear(p);
    mp_clear(g_exp_a); 
    mp_clear(g_exp_b);
    mp_clear(k);
    if (ret == -1) {
        if (*name != NULL)
            free(*name);
        if (*key != NULL)
            free(*key);
    }

    return ret;
}

int 
get_iv(uchar *IV)
{
    unsigned long x;
    x = yarrow_read(IV, ctx.ivsize, &(ctx.prng));
    if (x != ctx.ivsize)
        return -1;
    else
        return 0;
}

int 
init_send(Cxn *c)
{
    int err;
    if ((err = ctr_start(ctx.cipher_idx, c->IV, c->key, ctx.ks, 0, CTR_COUNTER_LITTLE_ENDIAN, &(c->ctr))) != CRYPT_OK) {
        fprintf(stderr, "ctr_start error: %s\n", error_to_string(err));
        return -1;
    }
    return 0;
}

int 
decrypt_msg(Cxn *c, uchar *plaintext, uchar *ciphertext, int len)
{
    int err;
    
    if ((err = ctr_decrypt(ciphertext, plaintext, len, &(c->ctr))) != CRYPT_OK) {
        fprintf(stderr, "ctr_decrypt error: %s\n", error_to_string(err));
        return -1;
    }
    return 0;
}

int 
encrypt_msg(Cxn *c, uchar *ciphertext, uchar *plaintext, int len)
{
    int err;

    if ((err = ctr_encrypt(plaintext, ciphertext, len, &(c->ctr))) != CRYPT_OK) {
        fprintf(stderr, "ctr_encrypt error: %s\n", error_to_string(err));
        return -1;
    }
    return 0;
}

void 
clean_ctx()
{
    mp_clear(ctx.dhp.g.n);
    mp_clear(ctx.dhp.p.n);
    mp_clear(ctx.dhp.a.n);
    mp_clear(ctx.dhp.g_exp_a.n);
    free(ctx.dhp.packed);
    //clear prng
}
