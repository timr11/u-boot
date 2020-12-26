/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2020, Alexandru Gagniuc <mr.nuke.me@gmail.com>.
 */

#ifndef _ECDSA_H
#define _ECDSA_H

#include <errno.h>
#include <image.h>

/**
 * crypto_algo API impementation for ECDSA;
 * @see "struct crypto_algo"
 * @{
 */
int ecdsa_sign(struct image_sign_info *info, const struct image_region region[],
	       int region_count, uint8_t **sigp, uint *sig_len);
int ecdsa_verify(struct image_sign_info *info,
		 const struct image_region region[], int region_count,
		 uint8_t *sig, uint sig_len);
int ecdsa_add_verify_data(struct image_sign_info *info, void *keydest);
/** @} */

#define ECDSA256_BYTES	(256 / 8)

#endif
