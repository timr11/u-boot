/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto/cryptlib.h>
/* #include <openssl/conf.h> */
/* #include "internal/thread_once.h" */
/* #include "internal/property.h" */

/* struct ossl_lib_ctx_onfree_list_st { */
/*     ossl_lib_ctx_onfree_fn *fn; */
/*     struct ossl_lib_ctx_onfree_list_st *next; */
/* }; */

/* struct ossl_lib_ctx_st { */
/*     CRYPTO_RWLOCK *lock; */
/*     CRYPTO_EX_DATA data; */
/*  */
/*     #<{(| */
/*      * For most data in the OSSL_LIB_CTX we just use ex_data to store it. But */
/*      * that doesn't work for ex_data itself - so we store that directly. */
/*      |)}># */
/*     OSSL_EX_DATA_GLOBAL global; */
/*  */
/*     #<{(| Map internal static indexes to dynamically created indexes |)}># */
/*     int dyn_indexes[OSSL_LIB_CTX_MAX_INDEXES]; */
/*  */
/*     #<{(| Keep a separate lock for each index |)}># */
/*     CRYPTO_RWLOCK *index_locks[OSSL_LIB_CTX_MAX_INDEXES]; */
/*  */
/*     CRYPTO_RWLOCK *oncelock; */
/*     int run_once_done[OSSL_LIB_CTX_MAX_RUN_ONCE]; */
/*     int run_once_ret[OSSL_LIB_CTX_MAX_RUN_ONCE]; */
/*     struct ossl_lib_ctx_onfree_list_st *onfreelist; */
/* }; */
/*  */
#ifndef FIPS_MODULE
/* The default default context */
/* static OSSL_LIB_CTX default_context_int; */
/*  */
/* static CRYPTO_ONCE default_context_init = CRYPTO_ONCE_STATIC_INIT; */
/* static CRYPTO_THREAD_LOCAL default_context_thread_local; */

#endif

/* static void ossl_lib_ctx_generic_free(void *parent_ign, void *ptr, */
/*                                       CRYPTO_EX_DATA *ad, int index, */
/*                                       long argl_ign, void *argp) */
/* { */
/*     const OSSL_LIB_CTX_METHOD *meth = argp; */
/*  */
/*     meth->free_func(ptr); */
/* } */
/*  */
/* int ossl_lib_ctx_onfree(OSSL_LIB_CTX *ctx, ossl_lib_ctx_onfree_fn onfreefn) */
/* { */
/*     struct ossl_lib_ctx_onfree_list_st *newonfree */
/*         = OPENSSL_malloc(sizeof(*newonfree)); */
/*  */
/*     if (newonfree == NULL) */
/*         return 0; */
/*  */
/*     newonfree->fn = onfreefn; */
/*     newonfree->next = ctx->onfreelist; */
/*     ctx->onfreelist = newonfree; */
/*  */
/*     return 1; */
/* } */
/*  */
