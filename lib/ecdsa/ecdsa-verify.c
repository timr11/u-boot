// SPDX-License-Identifier: GPL-2.0+
/*
 * ECDSA image signing implementation using libcrypto backend
 *
 * The signature is a binary representation of the (R, S) points, padded to the
 * key size. The signature will be (2 * key_size_bits) / 8 bytes.
 *
 * Deviations from behavior of RSA equivalent:
 *  - Verification uses private key. This is not technically required, but a
 *    limitation on how clumsy the openssl API is to use.
 *  - Handling of keys and key paths:
 *    - No assumptions are made about the file extension of the key
 *    - The 'key-name-hint' property is only used for naming devicetree nodes,
 *      but is not used for looking up keys on the filesystem.
 *
 * Copyright (c) 2021, Tim Romanski <timromanski@gmail.com>
 */

#ifndef USE_HOSTCC
#include <common.h>
#include <fdtdec.h>
#include <malloc.h>
#include <asm/types.h>
#include <errno.h>
#include <image.h>
#include <stdio.h>
#else
#include "fdt_host.h"
#include "mkimage.h"
#include <fdt_support.h>
#endif
#include <openssl/openssl/bn.h>
#include <openssl/openssl/ec.h>
#include <linux/kconfig.h>
#include <u-boot/ecdsa.h>

#if CONFIG_IS_ENABLED(FIT_SIGNATURE_ECDSA)
struct verifier {
	EC_KEY *pubkey;
	void *digest;
	ECDSA_SIG *sig;
};

static int alloc_ctx(struct verifier *ctx, const struct image_sign_info *info)
{
	memset(ctx, 0, sizeof(*ctx));

	ctx->digest = malloc(info->checksum->checksum_len);
	if (!ctx->digest)
		return -ENOMEM;

	return 0;
}

static void free_ctx(struct verifier *ctx)
{
	if (ctx->pubkey)
		EC_KEY_free(ctx->pubkey);

	if (ctx->digest)
		free(ctx->digest);

	if (ctx->sig)
		ECDSA_SIG_free(ctx->sig);
}

static int ecdsa_verifier_set_sig(struct verifier *ctx, const struct image_sign_info *info, void *raw_sig)
{
	int point_bytes = info->crypto->key_len;
	uintptr_t s_buf;
	ECDSA_SIG *sig;
	BIGNUM *r, *s;
	int ret;

	ctx->sig = NULL;

	sig = ECDSA_SIG_new();
	if (!sig)
		return -ENOMEM;

	s_buf = (uintptr_t)raw_sig + point_bytes;
	r = BN_bin2bn(raw_sig, point_bytes, NULL);
	s = BN_bin2bn((void *)s_buf, point_bytes, NULL);

	if (r == NULL || s == NULL) {
		ret = -EINVAL;
		goto err;
	}

	if (!ECDSA_SIG_set0(sig, r, s)) {
		ret = -EINVAL;
		goto err;
	}

	ctx->sig = sig;

	return 0;

err:
	ECDSA_SIG_free(sig);

	return ret;
}

/* Prepare a 'verifier' context that's ready to verify */
static int prepare_ctx(struct verifier *ctx, const struct image_sign_info *info, void *sig)
{
	int ret;

	ret = alloc_ctx(ctx, info);
	if (ret)
		return ret;

	ret = ecdsa_verifier_set_sig(ctx, info, sig);
	if (ret)
		goto err_set_sig;

	return 0;

err_set_sig:
	free_ctx(ctx);

	return ret;
}

static int ecdsa_verifier_set_pubkey(struct verifier *ctx, struct image_sign_info *info, int node)
{
	const void *blob;
	int curve_nid;
	const unsigned char *x_bin, *y_bin;
	int x_bin_len, y_bin_len;
	BIGNUM *x, *y;
	EC_GROUP *group;
	EC_KEY *key;
	int ret;

	blob = info->fdt_blob;

	x_bin = fdt_getprop(blob, node, "ecdsa,x-point", &x_bin_len);
	if (x_bin == NULL || x_bin_len != info->crypto->key_len) {
		debug("%s: ECDSA public key x-point missing or invalid", __func__);
		return -EFAULT;
	}

	y_bin = fdt_getprop(blob, node, "ecdsa,y-point", &y_bin_len);
	if (y_bin == NULL || y_bin_len != info->crypto->key_len) {
		debug("%s: ECDSA public key y-point missing or invalid", __func__);
		return -EFAULT;
	}

	x = BN_bin2bn(x_bin, x_bin_len, NULL);
	y = BN_bin2bn(y_bin, y_bin_len, NULL);
	if (x == NULL || y == NULL) {
		debug("%s: ECDSA public key x or y coordinates invalid, public key creation failed",
				__func__);
		return -EFAULT;
	}
	key = EC_KEY_new();
	if (key == NULL) {
		return -ENOMEM;
	}

	curve_nid = fdtdec_get_int(blob, node, "ecdsa,curve", -1);
	if (curve_nid == -1) {
		ret = -EINVAL;
		goto curve_err;
	}

	group = EC_GROUP_new_by_curve_name(curve_nid);
	if (!group) {
		ret = -EINVAL;
		goto group_err;
	}

	if (!EC_KEY_set_group(key, group)) {
		ret = -EFAULT;
		goto key_set_group_err;
	}

	if (EC_KEY_set_public_key_affine_coordinates(key, x, y) != 1) {
		debug("%s: ECDSA public key creation failed", __func__);
		ret = -EFAULT;
		goto key_set_coords_err;
		return -EFAULT;
	}

	ctx->pubkey = key;

	BN_free(x);
	BN_free(y);
	EC_GROUP_free(group);

	return 0;

key_set_coords_err:
key_set_group_err:
	EC_GROUP_free(group);
group_err:
curve_err:
	BN_free(x);
	BN_free(y);
	EC_KEY_free(key);
	return ret;
}
#endif

#if CONFIG_IS_ENABLED(FIT_SIGNATURE_ECDSA)
/**
 * ecdsa_verify_with_keynode() - Verify a signature against some data using
 * information in node with properties of ECDSA Key consisting of the curve,
 * the x and the y values of the public key point.
 *
 * Parse sign-node and fill a key_prop structure with properties of the
 * key.  Verify a RSA PKCS1.5 signature against an expected digest using
 * the properties parsed
 *
 * @info:	Specifies key and FIT information
 * @ctx:	Contains signature and digest. This method sets the pubkey for the ctx.
 * @node:	Node having the RSA Key properties
 * @return 0 if verified, -ve on error
 */
static int ecdsa_verify_with_keynode(struct image_sign_info *info,
				   struct verifier *ctx, int node)
{
	int ret = 0;

	if (node < 0) {
		debug("%s: Skipping invalid node", __func__);
		ret = -EBADF;
		goto err;
	}

	ret = ecdsa_verifier_set_pubkey(ctx, info, node);
	if (ret)
		goto err;

	// Returns 1 if signature is successfully verified, 0 otherwise
	ret = ECDSA_do_verify(ctx->digest, info->checksum->checksum_len, ctx->sig, ctx->pubkey);

	return ret == 1 ? 0 : -1;

err:
	return ret;
}
#else
static int ecdsa_verify_with_keynode(struct image_sign_info *info,
				   const void *hash, uint8_t *sig,
				   uint sig_len, int node)
{
	return -EACCES;
}
#endif

#if CONFIG_IS_ENABLED(FIT_SIGNATURE_ECDSA)
int do_verify(struct image_sign_info *info, struct verifier *ctx)
{
	const void *blob = info->fdt_blob;
	int ndepth, noffset;
	int sig_node, key_node;
	const char *fdt_key_name;
	int ret;

	sig_node = fdt_subnode_offset(blob, 0, FIT_SIG_NODENAME);
	if (sig_node < 0) {
		debug("%s: No signature node found\n", __func__);
		return -ENOENT;
	}

	/* See if we must use a particular key */
	if (info->required_keynode != -1) {
		return ecdsa_verify_with_keynode(info, ctx, info->required_keynode);
	}

	/* Look for a key that matches our hint */
	fdt_key_name = info->keyname ? info->keyname : "default-key";
	key_node = fdt_subnode_offset(blob, sig_node, fdt_key_name);
	ret = ecdsa_verify_with_keynode(info, ctx, key_node);
	if (!ret) {
		return ret;
	}

	/* No luck, so try each of the keys in turn */
	for (ndepth = 0, noffset = fdt_next_node(blob, sig_node,
							&ndepth);
			(noffset >= 0) && (ndepth > 0);
			noffset = fdt_next_node(blob, noffset, &ndepth)) {
		if (ndepth == 1 && noffset != key_node) {
			ret = ecdsa_verify_with_keynode(info, ctx, noffset);
			if (!ret)
				break;
		}
	}

	return ret;
}
#else
static inline int do_verify(struct image_sign_info *info, struct verifier *ctx)
{
	return -EACCES;
}
#endif

#if CONFIG_IS_ENABLED(FIT_SIGNATURE_ECDSA)
int ecdsa_verify(struct image_sign_info *info,
		 const struct image_region region[], int region_count,
		 uint8_t *sig, uint sig_len)
{
	struct verifier ctx;
	const struct checksum_algo *algo = info->checksum;
	int ret;

	if (sig_len != info->crypto->key_len * 2) {
		fprintf(stderr, "Signature has wrong length\n");
		ret = -EINVAL;
		goto err_sig_len;
	}

	ret = prepare_ctx(&ctx, info, sig);
	if (ret)
		goto err_ctx;


	algo->calculate(algo->name, region, region_count, ctx.digest);

	ret = do_verify(info, &ctx);

	free_ctx(&ctx);
	return ret;

err_ctx:
err_sig_len:
	return ret;
	return -EACCES;
}
#endif

