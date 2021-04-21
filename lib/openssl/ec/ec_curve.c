/*
 * Copyright 2002-2020 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * ECDSA low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include <openssl/internal/deprecated.h>

#include <string.h>
#include "ec_local.h"
#include <openssl/internal/nelem.h>

typedef struct {
    int field_type,             /* either NID_X9_62_prime_field or
                                 * NID_X9_62_characteristic_two_field */
     seed_len, param_len;
    unsigned int cofactor;      /* promoted to BN_ULONG */
} EC_CURVE_DATA;

/* the nist prime curves */
static const struct {
    EC_CURVE_DATA h;
    unsigned char data[20 + 32 * 6];
} _EC_X9_62_PRIME_256V1 = {
    {
        NID_X9_62_prime_field, 20, 32, 1
    },
    {
        /* seed */
        0xC4, 0x9D, 0x36, 0x08, 0x86, 0xE7, 0x04, 0x93, 0x6A, 0x66, 0x78, 0xE1,
        0x13, 0x9D, 0x26, 0xB7, 0x81, 0x9F, 0x7E, 0x90,
        /* p */
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        /* a */
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
        /* b */
        0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7, 0xB3, 0xEB, 0xBD, 0x55,
        0x76, 0x98, 0x86, 0xBC, 0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6,
        0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B,
        /* x */
        0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5,
        0x63, 0xA4, 0x40, 0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0,
        0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96,
        /* y */
        0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a,
        0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
        0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
        /* order */
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
        0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
    }
};

typedef struct _ec_list_element_st {
    int nid;
    const EC_CURVE_DATA *data;
    const EC_METHOD *(*meth) (void);
    const char *comment;
} ec_list_element;

#ifdef FIPS_MODULE
static const ec_list_element curve_list[] = {
    /* prime field curves */
    /* secg curves */
    {NID_X9_62_prime256v1, &_EC_X9_62_PRIME_256V1.h,
     EC_GFp_nistp256_method,
     "X9.62/SECG curve over a 256 bit prime field"},
};

#else

static const ec_list_element curve_list[] = {
    /* prime field curves */
    /* secg curves */
    {NID_X9_62_prime256v1, &_EC_X9_62_PRIME_256V1.h,
     EC_GFp_nistp256_method,
     "X9.62/SECG curve over a 256 bit prime field"},
};
#endif /* FIPS_MODULE */

#define curve_list_length OSSL_NELEM(curve_list)

static const ec_list_element *ec_curve_nid2curve(int nid)
{
    size_t i;

    if (nid <= 0)
        return NULL;

    for (i = 0; i < curve_list_length; i++) {
        if (curve_list[i].nid == nid)
            return &curve_list[i];
    }
    return NULL;
}

static EC_GROUP *ec_group_new_from_data(OSSL_LIB_CTX *libctx,
                                        const char *propq,
                                        const ec_list_element curve)
{
    EC_GROUP *group = NULL;
    EC_POINT *P = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL, *x = NULL, *y = NULL, *order =
        NULL;
    int ok = 0;
    int seed_len, param_len;
    const EC_METHOD *meth;
    const EC_CURVE_DATA *data;
    const unsigned char *params;

    /* If no curve data curve method must handle everything */
    if (curve.data == NULL)
        return ec_group_new_ex(libctx, propq,
                               curve.meth != NULL ? curve.meth() : NULL);

    if ((ctx = BN_CTX_new_ex(libctx)) == NULL) {
        //ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    data = curve.data;
    seed_len = data->seed_len;
    param_len = data->param_len;
    params = (const unsigned char *)(data + 1); /* skip header */
    params += seed_len;         /* skip seed */

    if ((p = BN_bin2bn(params + 0 * param_len, param_len, NULL)) == NULL
        || (a = BN_bin2bn(params + 1 * param_len, param_len, NULL)) == NULL
        || (b = BN_bin2bn(params + 2 * param_len, param_len, NULL)) == NULL) {
        //ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto err;
    }

    if (curve.meth != 0) {
        meth = curve.meth();
        if (((group = ec_group_new_ex(libctx, propq, meth)) == NULL) ||
            (!(group->meth->group_set_curve(group, p, a, b, ctx)))) {
            //ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
            goto err;
        }
	}
	// TODO: assuming curve method implemented, see if worth supporting this later
    /* } else if (data->field_type == NID_X9_62_prime_field) { */
    /*  */
    /*     if ((group = EC_GROUP_new_curve_GFp(p, a, b, ctx)) == NULL) { */
    /*         //ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB); */
    /*         goto err; */
    /*     } */
    /* } */
#ifndef OPENSSL_NO_EC2M
    /* else {                      #<{(| field_type == */
    /*                              * NID_X9_62_characteristic_two_field |)}># */
    /*  */
    /*     if ((group = EC_GROUP_new_curve_GF2m(p, a, b, ctx)) == NULL) { */
    /*         //ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB); */
    /*         goto err; */
    /*     } */
    /* } */
#endif

    EC_GROUP_set_curve_name(group, curve.nid);

    if ((P = EC_POINT_new(group)) == NULL) {
        //ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto err;
    }

    if ((x = BN_bin2bn(params + 3 * param_len, param_len, NULL)) == NULL
        || (y = BN_bin2bn(params + 4 * param_len, param_len, NULL)) == NULL) {
        //ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto err;
    }
    if (!EC_POINT_set_affine_coordinates(group, P, x, y, ctx)) {
        //ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto err;
    }
    if ((order = BN_bin2bn(params + 5 * param_len, param_len, NULL)) == NULL
        || !BN_set_word(x, (BN_ULONG)data->cofactor)) {
        //ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto err;
    }
    if (!EC_GROUP_set_generator(group, P, order, x)) {
        //ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
        goto err;
    }
    if (seed_len) {
        if (!EC_GROUP_set_seed(group, params - seed_len, seed_len)) {
            //ERR_raise(ERR_LIB_EC, ERR_R_EC_LIB);
            goto err;
        }
    }
    ok = 1;
 err:
    if (!ok) {
        EC_GROUP_free(group);
        group = NULL;
    }
    EC_POINT_free(P);
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(order);
    BN_free(x);
    BN_free(y);
    return group;
}

EC_GROUP *EC_GROUP_new_by_curve_name_ex(OSSL_LIB_CTX *libctx, const char *propq,
                                        int nid)
{
    EC_GROUP *ret = NULL;
    const ec_list_element *curve;

    if ((curve = ec_curve_nid2curve(nid)) == NULL
        || (ret = ec_group_new_from_data(libctx, propq, *curve)) == NULL) {
        return NULL;
    }

    return ret;
}

#ifndef FIPS_MODULE
EC_GROUP *EC_GROUP_new_by_curve_name(int nid)
{
    return EC_GROUP_new_by_curve_name_ex(NULL, NULL, nid);
}
#endif

