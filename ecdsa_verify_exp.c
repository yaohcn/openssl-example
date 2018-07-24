#include "ecdsa_verify.h"
#include "utils.h"
#include <string.h>
#include <openssl/ecdsa.h>
#include <openssl/hmac.h>
#include <openssl/sm2.h>
#include <openssl/bn.h>

static int get_digest(const uint8_t* message, uint8_t len, uint8_t* digest, unsigned int* dgst_len) {
    EVP_MD_CTX *md_ctx = NULL;
    int ret = SUCCESS;

    md_ctx = EVP_MD_CTX_new();
    if(md_ctx == NULL) {
        ret = SYSTEM_ERROR;
        goto end;
    }
    if(1 != EVP_DigestInit(md_ctx, EVP_sha1())) {
        ret = SYSTEM_ERROR;
        goto end;
    }
    if(1 != EVP_DigestUpdate(md_ctx, (const void *)message, len)) {
        ret = SYSTEM_ERROR;
        goto end;
    }
    if(1 != EVP_DigestFinal(md_ctx, digest, dgst_len)) {
        ret = SYSTEM_ERROR;
        goto end;
    }
end:
    EVP_MD_CTX_free(md_ctx);
    return ret;
}
static EC_GROUP *create_EC_group(const char *p_hex, const char *a_hex,
                                 const char *b_hex, const char *x_hex,
                                 const char *y_hex, const char *order_hex,
                                 const char *cof_hex)
{
    BIGNUM *p = NULL;
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    BIGNUM *g_x = NULL;
    BIGNUM *g_y = NULL;
    BIGNUM *order = NULL;
    BIGNUM *cof = NULL;
    EC_POINT *generator = NULL;
    EC_GROUP *group = NULL;

    BN_hex2bn(&p, p_hex);
    BN_hex2bn(&a, a_hex);
    BN_hex2bn(&b, b_hex);

    group = EC_GROUP_new_curve_GFp(p, a, b, NULL);
    BN_free(p);
    BN_free(a);
    BN_free(b);

    if (group == NULL)
        return NULL;

    generator = EC_POINT_new(group);
    if (generator == NULL)
        return NULL;

    BN_hex2bn(&g_x, x_hex);
    BN_hex2bn(&g_y, y_hex);

    if (EC_POINT_set_affine_coordinates_GFp(group, generator, g_x, g_y, NULL) ==
        0)
        return NULL;

    BN_free(g_x);
    BN_free(g_y);

    BN_hex2bn(&order, order_hex);
    BN_hex2bn(&cof, cof_hex);

    if (EC_GROUP_set_generator(group, generator, order, cof) == 0)
        return NULL;

    EC_POINT_free(generator);
    BN_free(order);
    BN_free(cof);

    return group;
}
#if 0
//sig格式为der格式
int _ecdsa_verify_sm2(uint8_t* puk, const uint8_t* sig, uint8_t sig_len, \
                                          const uint8_t* data, uint8_t data_len) {
    int verified = 0;
    int ret = 0;
    ECDSA_SIG *signature = NULL;
    EC_KEY *key = NULL;
    const uint8_t* pub_bytes_copy;
    const uint8_t* sig_bytes_copy;

    pub_bytes_copy = puk;
    sig_bytes_copy = sig;

    EC_GROUP *group =
        create_EC_group
        ("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
         "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
         "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
         "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
         "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
         "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
         "1");
    key = EC_KEY_new();
    EC_KEY_set_group(key, group);
    o2i_ECPublicKey(&key, &pub_bytes_copy, 33);
    if(key == NULL) {
        ret = SYSTEM_ERROR;
        goto end;
    }

    //第一个参数传NULL，函数内部分配空间，并返回该空间指针，调用处要释放。
    signature = d2i_ECDSA_SIG(NULL, &sig_bytes_copy, (long)sig_len);
    if(signature == NULL) {
        ret = SYSTEM_ERROR;
        goto end;
    }
    verified = SM2_do_verify(key, EVP_sm3(), signature, "1234567812345678", data, data_len);
    TRACE("sm2 verified:%d\n", verified);
    if(verified == 1)
        ret = SUCCESS;
    else if(verified == 0)
        ret = SIG_INVALID;
    else if(verified == -1)
        ret = SYSTEM_ERROR;
end:
    EC_KEY_free(key);
    EC_GROUP_free(group);
    ECDSA_SIG_free(signature);

    return ret;
}
#endif
//sig格式为64位r||s
int ecdsa_verify_sm2(uint8_t* puk, const uint8_t* sig, uint8_t sig_len,\
                    const uint8_t* data, int data_len) {
    int verified = 0;
    int ret = 0;
    ECDSA_SIG *signature = NULL;
    EC_KEY *key = NULL;
    BIGNUM *r=NULL, *s=NULL;
    const uint8_t* pub_bytes_copy;
    const uint8_t* sig_bytes_copy;

    pub_bytes_copy = puk;
    sig_bytes_copy = sig;

    signature = ECDSA_SIG_new();
    if (signature == NULL)
        return SYSTEM_ERROR;
    //第三个参数传NULL，则函数内部分配空间，并返回该空间指针，调用出不用分配，只需释放
    r = BN_bin2bn(sig, 32, NULL);
    s = BN_bin2bn(sig+32, 32, NULL);
    ECDSA_SIG_set0(signature, r, s);
    BN_free(r);
    BN_free(s);

    EC_GROUP *group =
        create_EC_group
        ("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
         "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
         "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
         "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
         "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
         "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
         "1");
    key = EC_KEY_new();
    EC_KEY_set_group(key, group);
    o2i_ECPublicKey(&key, &pub_bytes_copy, 33);
    if(key == NULL) {
        ret = SYSTEM_ERROR;
        goto end;
    }

    verified = SM2_do_verify(key, EVP_sm3(), signature, "1234567812345678", data, data_len);
    TRACE("sm2 verified:%d\n", verified);
    if(verified == 1)
        ret = SUCCESS;
    else if(verified == 0)
        ret = SIG_INVALID;
    else if(verified == -1)
        ret = SYSTEM_ERROR;
end:
    EC_KEY_free(key);
    EC_GROUP_free(group);
    ECDSA_SIG_free(signature);

    return ret;
}
int ecdsa_verify_secp(int nid, uint8_t* puk, \
                      const uint8_t* sig, uint8_t sig_len, \
                      const uint8_t* data, int data_len) {
    int ret = 0;
    uint8_t digest[20];
    unsigned int dgst_len = 0;
    EC_KEY *key = NULL;
    ECDSA_SIG *signature = NULL;
    const uint8_t* pub_bytes_copy;
    const uint8_t* sig_bytes_copy;
    int verified;

    int puk_len = (nid == NID_secp192k1) ? 25 : 33;
    TRACE("puk=%d", puk_len);

    pub_bytes_copy = puk;
    sig_bytes_copy = sig;
    key = EC_KEY_new_by_curve_name(nid);
    //trace_hex("=================user_pub_key", qrcode_info->user_pub_key, qrcode_info->user_pk_len);
    /*这里如果直接复制会改变user_puk_key的指向，故采用pub_bytes_copy
     *疑问：指针复制会重新开辟内存？
     *不会重新开辟内存，此处只是o2i_ECPublicKey函数修改了user_puk_key的指向
     *并没有修改原来指针指向的内容。
     * */
    o2i_ECPublicKey(&key, &pub_bytes_copy, puk_len);
    //o2i_ECPublicKey(&key, &(qrcode_info->user_pub_key), qrcode_info->user_pk_len);
    //trace_hex("=================user_pub_key", qrcode_info->user_pub_key, qrcode_info->user_pk_len);
    if(key == NULL) {
        ret = SYSTEM_ERROR;
        goto end;
    }

    signature = d2i_ECDSA_SIG(NULL, &sig_bytes_copy, (long)sig_len);
    if(signature == NULL) {
        ret = SYSTEM_ERROR;
        goto end;
    }

    if(SUCCESS!=get_digest(data, data_len, digest, &dgst_len))
    {
        ret = SYSTEM_ERROR;
        goto end;
    }
    verified = ECDSA_do_verify(digest, dgst_len, signature, key);
    TRACE("user verified:%d\n", verified);
    if(verified == 1)
        ret = SUCCESS;
    else if(verified == 0)
        ret = SIG_INVALID;
    else if(verified == -1)
        ret = SYSTEM_ERROR;

end:
    ECDSA_SIG_free(signature);
    EC_KEY_free(key);
    ECDSA_SIG_free(signature);
    return ret;
}
int ecdsa_verify(CIRCLETYPE c, uint8_t* puk, \
                      const uint8_t* sig, uint8_t sig_len, \
                      const uint8_t* data, int data_len) {
    int ret;
    if(c == SM2_CIRCLE) {
        RET_CHK(ecdsa_verify_sm2(puk, sig, sig_len, data, data_len));
    }else if(c == SECP256_CIRCLE) {
        RET_CHK(ecdsa_verify_secp(NID_secp256k1, puk, sig, sig_len, data, data_len));
    }else if(c == SECP192_CIRCLE) {
        RET_CHK(ecdsa_verify_secp(NID_secp192k1, puk, sig, sig_len, data, data_len));
    }
    return SUCCESS;
}
int hmac_md5(uint8_t* key,int key_len, const uint8_t* data, int data_len, uint8_t* hash, unsigned int* hash_len) {
    HMAC(EVP_md5(), key, key_len, data, data_len, hash, hash_len);
    return SUCCESS;
}
