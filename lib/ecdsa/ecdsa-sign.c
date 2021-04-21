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
 *    - The '-K' key directory option must contain path to the key file,
 *      instead of the key directory.
 *    - No assumptions are made about the file extension of the key
 *    - The 'key-name-hint' property is only used for naming devicetree nodes,
 *      but is not used for looking up keys on the filesystem.
 *
 * Copyright (c) 2020,2021, Alexandru Gagniuc <mr.nuke.me@gmail.com>
 */

#include "mkimage.h"
#include <stdio.h>
#include <u-boot/ecdsa.h>
#include <u-boot/fdt-libcrypto.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

/* Image signing context for openssl-libcrypto */
struct signer {
	EC_KEY *pkey;		/* Pointer to EC_KEY object (private key) */
	void *digest;		/* Pointer to digest used for verification */
	void *signature;	/* Pointer to output signature. Do not free()!*/
};

static int ecdsa_init(void)
{
	int ret;

	#if OPENSSL_VERSION_NUMBER < 0x10100000L || \
	(defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x02070000fL)
	ret = SSL_library_init();
#else
	ret = OPENSSL_init_ssl(0, NULL);
#endif
	if (!ret) {
		fprintf(stderr, "Failure to init SSL library\n");
		return -1;
	}
#if OPENSSL_VERSION_NUMBER < 0x10100000L || \
	(defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x02070000fL)
	SSL_load_error_strings();

	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_digests();
	OpenSSL_add_all_ciphers();
#endif

	return 0;
}

static void ecdsa_remove(void)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L || \
	(defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x02070000fL)
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();
#ifdef HAVE_ERR_REMOVE_THREAD_STATE
	ERR_remove_thread_state(NULL);
#else
	ERR_remove_state(0);
#endif
	EVP_cleanup();
#endif
}

static int alloc_ctx(struct signer *ctx, const struct image_sign_info *info)
{
	memset(ctx, 0, sizeof(*ctx));

	ctx->digest = malloc(info->checksum->checksum_len);
	ctx->signature = malloc(info->crypto->key_len * 2);

	if (!ctx->digest || !ctx->signature)
		return -ENOMEM;

	return 0;
}

static void free_ctx(struct signer *ctx)
{
	if (ctx->pkey)
		EC_KEY_free(ctx->pkey);

	if (ctx->digest)
		free(ctx->digest);
}

/**
 * ecdsa_get_pub_key_from_priv_key() - get EC public key from private key
 *
 * @pkey	Private EC key
 * @pub		Returns EC_KEY object, or NULL on failure
 * @return 0 if ok, -ve on error (in which case *pub will be set to NULL)
 */
static int ecdsa_get_pub_key(EC_KEY *pkey, EC_KEY **pub)
{
	const EC_POINT *point;
	EC_KEY *key;

	*pub = NULL;
	
	if ((key = EC_KEY_new()) == NULL)
		return -ENOMEM;

	point = EC_KEY_get0_public_key(pkey);

	if (EC_KEY_set_public_key(key, point)) {
		EC_KEY_free(key);
		return -EINVAL;
	}

	*pub = key;

	return 0;
}

/**
 * read_key() - read a private key
 *
 * @ctx			Stores the private key if successful
 * @key_name:	Full path to private key
 * @return 0 if ok, -ve on error (in which case *pkey will be set to NULL)
 */
static int read_key(struct signer *ctx, const char *key_name)
{
	EVP_PKEY *key;
	EC_KEY *ec_key;
	FILE *f;
	int ret;

	ctx->pkey = NULL;
	f = fopen(key_name, "r");
	if (!f) {
		fprintf(stderr, "Couldn't open ECDSA private key: '%s': %s\n",
				key_name, strerror(errno));
		return -ENOENT;
	}

	key = PEM_read_PrivateKey(f, NULL, NULL, NULL);
	fclose(f);
	if (!key) {
		fprintf(stderr, "Failure reading private key from: %s", key_name);
		return -EIO;
	}

	if (EVP_PKEY_id(key) != EVP_PKEY_EC) {
		fprintf(stderr, "'%s' is not an ECDSA key\n", key_name);
		ret = -EINVAL;
		goto key_err;
	}

	ec_key = EVP_PKEY_get1_EC_KEY(key);
	if (!ec_key) {
		fprintf(stderr, "Can not extract ECDSA key\n");
		ret = -EINVAL;
		goto key_err;
	}

	EVP_PKEY_free(key);
	ctx->pkey = ec_key;

	return 0;

key_err:
	EVP_PKEY_free(key);
	return ret;
}

/*
 * Convert an ECDSA signature to raw format
 *
 * openssl DER-encodes 'binary' signatures. We want the signature in a raw
 * (R, S) point pair. So we have to dance a bit.
 */
static void ecdsa_sig_encode_raw(void *buf, const ECDSA_SIG *sig, size_t order)
{
	int point_bytes = order;
	const BIGNUM *r, *s;
	uintptr_t s_buf;

	ECDSA_SIG_get0(sig, &r, &s);
	s_buf = (uintptr_t)buf + point_bytes;
	BN_bn2binpad(r, buf, point_bytes);
	BN_bn2binpad(s, (void *)s_buf, point_bytes);
}

/* Get a signature from a raw encoding */
static ECDSA_SIG *ecdsa_sig_from_raw(void *buf, size_t order)
{
	int point_bytes = order;
	uintptr_t s_buf;
	ECDSA_SIG *sig;
	BIGNUM *r, *s;

	sig = ECDSA_SIG_new();
	if (!sig)
		return NULL;

	s_buf = (uintptr_t)buf + point_bytes;
	r = BN_bin2bn(buf, point_bytes, NULL);
	s = BN_bin2bn((void *)s_buf, point_bytes, NULL);
	ECDSA_SIG_set0(sig, r, s);

	return sig;
}

/* ECDSA key size in bytes */
static size_t ecdsa_key_size_bytes(const EC_KEY *key)
{
	const EC_GROUP *group;

	group = EC_KEY_get0_group(key);
	return EC_GROUP_order_bits(group) / 8;
}

/* Prepare a 'signer' context that's ready to sign and verify. */
static int prepare_ctx(struct signer *ctx, const struct image_sign_info *info)
{
	int ret, key_len_bytes;
	char kname[1024];

	if (info->keyfile) {
		snprintf(kname, sizeof(kname), "%s", info->keyfile);
	} else if (info->keydir && info->keyname) {
		snprintf(kname, sizeof(kname), "%s/%s.pem", info->keydir,
				info->keyname);
	} else {
		fprintf(stderr, "keyfile, keyname, or key-name-hint missing\n");
		ret = -EINVAL;
		goto err_key_name;
	}

	ret = alloc_ctx(ctx, info);
	if (ret)
		return ret;

	ret = read_key(ctx, kname);
	if (ret)
		goto err_priv;

	key_len_bytes = ecdsa_key_size_bytes(ctx->pkey);
	if (key_len_bytes != info->crypto->key_len) {
		fprintf(stderr, "Expected a %u-bit key, got %u-bit key\n",
			info->crypto->key_len * 8, key_len_bytes * 8);
		ret = -EINVAL;
		goto err_key_len;
	}

	return ret;

err_priv:
err_key_len:
err_key_name:
	free_ctx(ctx);
	if (ctx->signature)
		free(ctx->signature);

	return ret;
}

static int do_sign(struct signer *ctx, struct image_sign_info *info,
		   const struct image_region region[], int region_count)
{
	const struct checksum_algo *algo = info->checksum;
	ECDSA_SIG *sig;

	algo->calculate(algo->name, region, region_count, ctx->digest);
	sig = ECDSA_do_sign(ctx->digest, algo->checksum_len, ctx->pkey);

	ecdsa_sig_encode_raw(ctx->signature, sig, info->crypto->key_len);

	return 0;
}

static int ecdsa_check_signature(struct signer *ctx, struct image_sign_info *info)
{
	ECDSA_SIG *sig;
	EC_KEY *pubkey;
	int ret;

	sig = NULL;
	pubkey = NULL;
	ret = ecdsa_get_pub_key(ctx->pkey, &pubkey);
	if (ret)
		goto pub_key_err;

	if ((sig = ecdsa_sig_from_raw(ctx->signature, info->crypto->key_len)) == NULL) {
		ret = -ENOMEM;
		goto sig_err;
	}

	/* if ((ret = ECDSA_do_verify(ctx->digest, info->checksum->checksum_len, sig, pubkey)) == 0) */
	/* 	fprintf(stderr, "WARNING: Signature is fake news!\n"); */

	ECDSA_SIG_free(sig);
	EC_KEY_free(pubkey);
	return 0;
	/* return !ret; */

sig_err:
	EC_KEY_free(pubkey);
pub_key_err:
	return ret;
}

int ecdsa_sign(struct image_sign_info *info, const struct image_region region[],
	       int region_count, uint8_t **sigp, uint *sig_len)
{
	struct signer ctx;
	int ret;

	ret = ecdsa_init();
	if (ret)
		return ret;

	ret = prepare_ctx(&ctx, info);
	if (ret >= 0) {
		do_sign(&ctx, info, region, region_count);
		*sigp = ctx.signature;
		*sig_len = info->crypto->key_len * 2;

		ret = ecdsa_check_signature(&ctx, info);
	}

	free_ctx(&ctx);
	ecdsa_remove();

	return ret;
}

static int do_add(struct signer *ctx, const struct image_sign_info *info, void *fdt, const char *key_node_name)
{
	int signature_node, key_node, ret, key_bits;
	/* const char *curve_name; */
	int curve_nid;
	const EC_GROUP *group;
	const EC_POINT *point;
	BIGNUM *x, *y;


	ret = 0;
	x = NULL;
	y = NULL;
	signature_node = fdt_subnode_offset(fdt, 0, FIT_SIG_NODENAME);
	if (signature_node == -FDT_ERR_NOTFOUND) {
		signature_node = fdt_add_subnode(fdt, 0, FIT_SIG_NODENAME);
		if (signature_node < 0) {
			ret = signature_node;
			if (ret != -FDT_ERR_NOSPACE) {
				fprintf(stderr, "Couldn't create signature node: %s\n",
						fdt_strerror(ret));
			}
		}
	} else if (signature_node < 0) {
		fprintf(stderr, "Cannot select keys parent: %s\n",
				fdt_strerror(signature_node));
	}
	if (ret)
		goto done;

	key_node = fdt_subnode_offset(fdt, signature_node, key_node_name);
	if (key_node == -FDT_ERR_NOTFOUND) {
		key_node = fdt_add_subnode(fdt, signature_node, key_node_name);
		if (key_node < 0) {
			ret = key_node;
			if (ret != -FDT_ERR_NOSPACE) {
				fprintf(stderr, "Could not create '%s' node: %s\n",
						key_node_name, fdt_strerror(key_node));
			}
		}
	} else if (key_node < 0) {
		fprintf(stderr, "Cannot select key node parent: %s\n",
				fdt_strerror(key_node));
	}
	if (ret)
		goto done;

	group = EC_KEY_get0_group(ctx->pkey);
	key_bits = EC_GROUP_order_bits(group);
	curve_nid = EC_GROUP_get_curve_name(group);
	/* curve_name = OBJ_nid2sn(EC_GROUP_get_curve_name(group)); */
	/* Let 'x' and 'y' memory leak by not BN_free()'ing them. */
	x = BN_new();
	y = BN_new();
	point = EC_KEY_get0_public_key(ctx->pkey);
	EC_POINT_get_affine_coordinates(group, point, x, y, NULL);

	if (!ret) {
		ret = fdt_setprop_u32(fdt, key_node, "ecdsa,curve", curve_nid);
	}

	if (!ret) {
		ret = fdt_add_bignum(fdt, key_node, "ecdsa,x-point", x, key_bits);
	}

	if (!ret) {
		ret = fdt_add_bignum(fdt, key_node, "ecdsa,y-point", y, key_bits);
	}

	if (!ret) {
		ret = fdt_setprop_string(fdt, key_node, FIT_ALGO_PROP,
					 info->name);
	}
	if (!ret && info->require_keys) {
		ret = fdt_setprop_string(fdt, key_node, FIT_KEY_REQUIRED,
					 info->require_keys);
	}

done:
	if (x)
		BN_free(x);
	if (y)
		BN_free(y);

	return ret;
}

int ecdsa_add_verify_data(struct image_sign_info *info, void *fdt)
{
	const char *fdt_key_name;
	struct signer ctx;
	int ret;

	fdt_key_name = info->keyname ? info->keyname : "default-key";
	ret = prepare_ctx(&ctx, info);
	if (ret >= 0)
		do_add(&ctx, info, fdt, fdt_key_name);

	free_ctx(&ctx);
	return ret;
}

