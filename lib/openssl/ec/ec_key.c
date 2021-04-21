/*
 * Copyright 2002-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * EC_KEY low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include <openssl/internal/deprecated.h>

#include <openssl/openssl/crypto.h>
#include <string.h>
#include "ec_local.h"
#include <openssl/internal/refcount.h>
#include <openssl/crypto/bn.h>

#ifndef FIPS_MODULE
EC_KEY *EC_KEY_new(void)
{
    return ec_key_new_method_int(NULL, NULL);
}
#endif

void EC_KEY_free(EC_KEY *r)
{
    int i;

    if (r == NULL)
        return;

    if (i > 0)
        return;

    if (r->meth != NULL && r->meth->finish != NULL)
        r->meth->finish(r);

/* #if !defined(OPENSSL_NO_ENGINE) && !defined(FIPS_MODULE) */
/*     ENGINE_finish(r->engine); */
/* #endif */

    if (r->group && r->group->meth->keyfinish)
        r->group->meth->keyfinish(r);

    EC_GROUP_free(r->group);
    EC_POINT_free(r->pub_key);
    BN_clear_free(r->priv_key);
    OPENSSL_free(r->propq);

    OPENSSL_clear_free((void *)r, sizeof(EC_KEY));
}

int EC_KEY_check_key(const EC_KEY *eckey)
{
    if (eckey == NULL || eckey->group == NULL || eckey->pub_key == NULL) {
        //ERR_raisegc(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (eckey->group->meth->keycheck == NULL) {
        //ERR_raisegc(ERR_LIB_EC, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }

    return eckey->group->meth->keycheck(eckey);
}

/*
 * Check the range of the EC public key.
 * See SP800-56A R3 Section 5.6.2.3.3 (Part 2)
 * i.e.
 *  - If q = odd prime p: Verify that xQ and yQ are integers in the
 *    interval[0, p - 1], OR
 *  - If q = 2m: Verify that xQ and yQ are bit strings of length m bits.
 * Returns 1 if the public key has a valid range, otherwise it returns 0.
 */
static int ec_key_public_range_check(BN_CTX *ctx, const EC_KEY *key)
{
    int ret = 0;
    BIGNUM *x, *y;

    BN_CTX_start(ctx);
    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);
    if (y == NULL)
        goto err;

    if (!EC_POINT_get_affine_coordinates(key->group, key->pub_key, x, y, ctx))
        goto err;

    if (EC_GROUP_get_field_type(key->group) == NID_X9_62_prime_field) {
        if (BN_is_negative(x)
            || BN_cmp(x, key->group->field) >= 0
            || BN_is_negative(y)
            || BN_cmp(y, key->group->field) >= 0) {
            goto err;
        }
    } else {
        int m = EC_GROUP_get_degree(key->group);
        if (BN_num_bits(x) > m || BN_num_bits(y) > m) {
            goto err;
        }
    }
    ret = 1;
err:
    BN_CTX_end(ctx);
    return ret;
}

/*
 * ECC Key validation as specified in SP800-56A R3.
 * Section 5.6.2.3.3 ECC Full Public-Key Validation.
 */
int ec_key_public_check(const EC_KEY *eckey, BN_CTX *ctx)
{
    int ret = 0;
    EC_POINT *point = NULL;
    const BIGNUM *order = NULL;

    if (eckey == NULL || eckey->group == NULL || eckey->pub_key == NULL) {
        //ERR_raisegc(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    /* 5.6.2.3.3 (Step 1): Q != infinity */
    if (EC_POINT_is_at_infinity(eckey->group, eckey->pub_key)) {
        //ERR_raisegc(ERR_LIB_EC, EC_R_POINT_AT_INFINITY);
        return 0;
    }

    point = EC_POINT_new(eckey->group);
    if (point == NULL)
        return 0;

    /* 5.6.2.3.3 (Step 2) Test if the public key is in range */
    if (!ec_key_public_range_check(ctx, eckey)) {
        //ERR_raisegc(ERR_LIB_EC, EC_R_COORDINATES_OUT_OF_RANGE);
        goto err;
    }

    /* 5.6.2.3.3 (Step 3) is the pub_key on the elliptic curve */
    if (EC_POINT_is_on_curve(eckey->group, eckey->pub_key, ctx) <= 0) {
        //ERR_raisegc(ERR_LIB_EC, EC_R_POINT_IS_NOT_ON_CURVE);
        goto err;
    }

    order = eckey->group->order;
    if (BN_is_zero(order)) {
        //ERR_raisegc(ERR_LIB_EC, EC_R_INVALID_GROUP_ORDER);
        goto err;
    }
    /* 5.6.2.3.3 (Step 4) : pub_key * order is the point at infinity. */
    if (!EC_POINT_mul(eckey->group, point, NULL, eckey->pub_key, order, ctx)) {
        //ERR_raisegc(ERR_LIB_EC, ERR_R_EC_LIB);
        goto err;
    }
    if (!EC_POINT_is_at_infinity(eckey->group, point)) {
        //ERR_raisegc(ERR_LIB_EC, EC_R_WRONG_ORDER);
        goto err;
    }
    ret = 1;
err:
    EC_POINT_free(point);
    return ret;
}

/*
 * ECC Key validation as specified in SP800-56A R3.
 * Section 5.6.2.1.2 Owner Assurance of Private-Key Validity
 * The private key is in the range [1, order-1]
 */
int ec_key_private_check(const EC_KEY *eckey)
{
    if (eckey == NULL || eckey->group == NULL || eckey->priv_key == NULL) {
        //ERR_raisegc(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (BN_cmp(eckey->priv_key, BN_value_one()) < 0
        || BN_cmp(eckey->priv_key, eckey->group->order) >= 0) {
        //ERR_raisegc(ERR_LIB_EC, EC_R_INVALID_PRIVATE_KEY);
        return 0;
    }
    return 1;
}

/*
 * ECC Key validation as specified in SP800-56A R3.
 * Section 5.6.2.1.4 Owner Assurance of Pair-wise Consistency (b)
 * Check if generator * priv_key = pub_key
 */
int ec_key_pairwise_check(const EC_KEY *eckey, BN_CTX *ctx)
{
    int ret = 0;
    EC_POINT *point = NULL;

    if (eckey == NULL
       || eckey->group == NULL
       || eckey->pub_key == NULL
       || eckey->priv_key == NULL) {
        //ERR_raisegc(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    point = EC_POINT_new(eckey->group);
    if (point == NULL)
        goto err;


    if (!EC_POINT_mul(eckey->group, point, eckey->priv_key, NULL, NULL, ctx)) {
        //ERR_raisegc(ERR_LIB_EC, ERR_R_EC_LIB);
        goto err;
    }
    if (EC_POINT_cmp(eckey->group, point, eckey->pub_key, ctx) != 0) {
        //ERR_raisegc(ERR_LIB_EC, EC_R_INVALID_PRIVATE_KEY);
        goto err;
    }
    ret = 1;
err:
    EC_POINT_free(point);
    return ret;
}

/*
 * ECC Key validation as specified in SP800-56A R3.
 *    Section 5.6.2.3.3 ECC Full Public-Key Validation
 *    Section 5.6.2.1.2 Owner Assurance of Private-Key Validity
 *    Section 5.6.2.1.4 Owner Assurance of Pair-wise Consistency
 * NOTES:
 *    Before calling this method in fips mode, there should be an assurance that
 *    an approved elliptic-curve group is used.
 * Returns 1 if the key is valid, otherwise it returns 0.
 */
int ec_key_simple_check_key(const EC_KEY *eckey)
{
    int ok = 0;
    BN_CTX *ctx = NULL;

    if (eckey == NULL) {
        //ERR_raisegc(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if ((ctx = BN_CTX_new_ex(eckey->libctx)) == NULL)
        return 0;

    if (!ec_key_public_check(eckey, ctx))
        goto err;

    if (eckey->priv_key != NULL) {
        if (!ec_key_private_check(eckey)
            || !ec_key_pairwise_check(eckey, ctx))
            goto err;
    }
    ok = 1;
err:
    BN_CTX_free(ctx);
    return ok;
}

int EC_KEY_set_public_key_affine_coordinates(EC_KEY *key, BIGNUM *x,
                                             BIGNUM *y)
{
    BN_CTX *ctx = NULL;
    BIGNUM *tx, *ty;
    EC_POINT *point = NULL;
    int ok = 0;

    if (key == NULL || key->group == NULL || x == NULL || y == NULL) {
        //ERR_raisegc(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    ctx = BN_CTX_new_ex(key->libctx);
    if (ctx == NULL)
        return 0;

    BN_CTX_start(ctx);
    point = EC_POINT_new(key->group);

    if (point == NULL)
        goto err;

    tx = BN_CTX_get(ctx);
    ty = BN_CTX_get(ctx);
    if (ty == NULL)
        goto err;

    if (!EC_POINT_set_affine_coordinates(key->group, point, x, y, ctx))
        goto err;
    if (!EC_POINT_get_affine_coordinates(key->group, point, tx, ty, ctx))
        goto err;

    /*
     * Check if retrieved coordinates match originals. The range check is done
     * inside EC_KEY_check_key().
     */
    if (BN_cmp(x, tx) || BN_cmp(y, ty)) {
        //ERR_raisegc(ERR_LIB_EC, EC_R_COORDINATES_OUT_OF_RANGE);
        goto err;
    }

    /* EC_KEY_set_public_key updates dirty_cnt */
    if (!EC_KEY_set_public_key(key, point))
        goto err;

    if (EC_KEY_check_key(key) == 0)
        goto err;

    ok = 1;

 err:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    EC_POINT_free(point);
    return ok;

}

const EC_GROUP *EC_KEY_get0_group(const EC_KEY *key)
{
    return key->group;
}

int EC_KEY_set_group(EC_KEY *key, const EC_GROUP *group)
{
    if (key->meth->set_group != NULL && key->meth->set_group(key, group) == 0)
        return 0;
    EC_GROUP_free(key->group);
    key->group = EC_GROUP_dup(group);
    key->dirty_cnt++;
    return (key->group == NULL) ? 0 : 1;
}

const EC_POINT *EC_KEY_get0_public_key(const EC_KEY *key)
{
    return key->pub_key;
}

int EC_KEY_set_public_key(EC_KEY *key, const EC_POINT *pub_key)
{
    if (key->meth->set_public != NULL
        && key->meth->set_public(key, pub_key) == 0)
        return 0;
    EC_POINT_free(key->pub_key);
    key->pub_key = EC_POINT_dup(pub_key, key->group);
    key->dirty_cnt++;
    return (key->pub_key == NULL) ? 0 : 1;
}

int EC_KEY_can_sign(const EC_KEY *eckey)
{
    if (eckey->group == NULL || eckey->group->meth == NULL
        || (eckey->group->meth->flags & EC_FLAGS_NO_SIGN))
        return 0;
    return 1;
}

