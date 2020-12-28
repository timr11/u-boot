/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2020, Alexandru Gagniuc <mr.nuke.me@gmail.com>
 * Copyright (c) 2013, Google Inc.
 */

#ifndef _FDT_LIBCRYPTO_H
#define _FDT_LIBCRYPTO_H

#include <openssl/bn.h>

int fdt_add_bignum(void *blob, int noffset, const char *prop_name,
		   BIGNUM *num, int num_bits);

#endif /* _FDT_LIBCRYPTO_H */
