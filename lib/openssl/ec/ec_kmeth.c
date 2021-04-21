/*
 * Copyright 2015-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * ECDH and ECDSA low level APIs are deprecated for public use, but still ok
 * for internal use.
 */
#include <openssl/internal/deprecated.h>

#include <string.h>
#include "ec_local.h"

static const EC_KEY_METHOD openssl_ec_key_method = {
    "OpenSSL EC_KEY method",
    0,
    0,0,0,0,0,0,
    0, /* ossl_ec_key_gen, */
    0, /* ossl_ecdh_compute_key, */
    0, /* ossl_ecdsa_sign, */
    0, /* ossl_ecdsa_sign_setup, */
    0, /* ossl_ecdsa_sign_sig, */
    0, /* ossl_ecdsa_verify, */
    ossl_ecdsa_verify_sig
};

static const EC_KEY_METHOD *default_ec_key_meth = &openssl_ec_key_method;

const EC_KEY_METHOD *EC_KEY_get_default_method(void)
{
    return default_ec_key_meth;
}

EC_KEY *ec_key_new_method_int(OSSL_LIB_CTX *libctx, const char *propq)
{
    EC_KEY *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL) {
        //ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ret->libctx = libctx;
    if (propq != NULL) {
        ret->propq = OPENSSL_strdup(propq);
        if (ret->propq == NULL) {
            //ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    }

    ret->references = 1;

    ret->meth = EC_KEY_get_default_method();
    ret->version = 1;
    ret->conv_form = POINT_CONVERSION_UNCOMPRESSED;

    if (ret->meth->init != NULL && ret->meth->init(ret) == 0) {
        //ERR_raise(ERR_LIB_EC, ERR_R_INIT_FAIL);
        goto err;
    }
    return ret;

 err:
    EC_KEY_free(ret);
    return NULL;
}

