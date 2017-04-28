/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2009 by Aris Adamantiadis
 * Botan support (c) 2015 Bas Timmer
 *
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * The SSH Library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the SSH Library; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include "libssh/priv.h"
#include "libssh/session.h"
#include "libssh/crypto.h"
#include "libssh/wrapper.h"
#include "libssh/botan.h"

#ifdef HAVE_BOTAN

#include "libssh/crypto.h"

#include <botan/md5.h>
#include <botan/sha160.h>
#include <botan/sha2_32.h>
#include <botan/sha2_64.h>

#include <botan/hmac.h>

#include <botan/aes.h>
#include <botan/ctr.h>
#include <botan/cbc.h>
#include <botan/des.h>
#include <botan/blowfish.h>

struct ssh_mac_ctx_struct
{
	enum ssh_mac_e mac_type;
	Botan::HashFunction* mac;
};

static int alloc_key(struct ssh_cipher_struct *cipher)
{
	cipher->key = new ssh_cipher_key_struct;

	return 0;
}

void ssh_reseed(void)
{
}

SHACTX sha1_init(void)
{
	SHACTX ctx = NULL;
	ctx = std::make_shared<Botan::SHA_160>();

	return ctx;
}

void sha1_update(SHACTX c, const void *data, unsigned long len)
{
	c->update((const uint8_t*)data, (size_t)len);
}

void sha1_final(unsigned char *md, SHACTX c)
{
	c->final(md);
}

void sha1(unsigned char *digest, int len, unsigned char *hash)
{
	SHACTX ctx = sha1_init();
	sha1_update(ctx, digest, len);
	sha1_final(hash, ctx);
}

SHA256CTX sha256_init(void)
{
	SHA256CTX ctx = NULL;
	ctx = std::make_shared<Botan::SHA_256>();

	return ctx;
}

void sha256_update(SHACTX c, const void *data, unsigned long len)
{
	c->update((const uint8_t*)data, (size_t)len);
}

void sha256_final(unsigned char *md, SHACTX c)
{
	c->final(md);
}

void sha256(unsigned char *digest, int len, unsigned char *hash){
	SHACTX ctx = sha256_init();
	sha256_update(ctx, digest, len);
	sha256_final(hash, ctx);
}

SHA384CTX sha384_init(void) {
	SHA384CTX ctx = NULL;
	ctx = std::make_shared<Botan::SHA_384>();

	return ctx;
}

void sha384_update(SHACTX c, const void *data, unsigned long len) {
	c->update((const uint8_t*)data, (size_t)len);
}

void sha384_final(unsigned char *md, SHACTX c) {
	c->final(md);
}

void sha384(unsigned char *digest, int len, unsigned char *hash) {
	SHACTX ctx = sha384_init();
	sha384_update(ctx, digest, len);
	sha384_final(hash, ctx);
}

SHA512CTX sha512_init(void) {
	SHA512CTX ctx = NULL;
	ctx = std::make_shared<Botan::SHA_512>();

	return ctx;
}

void sha512_update(SHACTX c, const void *data, unsigned long len) {
	c->update((const uint8_t*)data, (size_t)len);
}

void sha512_final(unsigned char *md, SHACTX c) {
	c->final(md);
}

void sha512(unsigned char *digest, int len, unsigned char *hash) {
	SHACTX ctx = sha512_init();
	sha512_update(ctx, digest, len);
	sha512_final(hash, ctx);
}

MD5CTX md5_init(void)
{
	MD5CTX c = NULL;
	c = std::make_shared<Botan::MD5>();

	return c;
}

void md5_update(MD5CTX c, const void *data, unsigned long len)
{
	c->update((const uint8_t*)data, (size_t)len);
}

void md5_final(unsigned char *md, MD5CTX c)
{
	c->final(md);
}

ssh_mac_ctx ssh_mac_ctx_init(enum ssh_mac_e type)
{
	ssh_mac_ctx ctx = (ssh_mac_ctx)malloc(sizeof(struct ssh_mac_ctx_struct));
	if (ctx == NULL)
	{
		return NULL;
	}

	ctx->mac_type = type;
	switch (type)
	{
		case SSH_MAC_SHA1:
			ctx->mac = new Botan::SHA_160();
			break;
		case SSH_MAC_SHA256:
			ctx->mac = new Botan::SHA_256();
			break;
		case SSH_MAC_SHA384:
			ctx->mac = new Botan::SHA_384();
			break;
		case SSH_MAC_SHA512:
			ctx->mac = new Botan::SHA_512();
			break;
		default:
			SAFE_FREE(ctx);
			return NULL;
	}
	return ctx;
}

void ssh_mac_update(ssh_mac_ctx ctx, const void *data, unsigned long len)
{
	ctx->mac->update((const uint8_t*)data, (size_t)len);
}

void ssh_mac_final(unsigned char *md, ssh_mac_ctx ctx)
{
	size_t len;
	switch (ctx->mac_type)
	{
		case SSH_MAC_SHA1:
			len = SHA_DIGEST_LEN;
			break;
		case SSH_MAC_SHA256:
			len = SHA256_DIGEST_LEN;
			break;
		case SSH_MAC_SHA384:
			len = SHA384_DIGEST_LEN;
			break;
		case SSH_MAC_SHA512:
			len = SHA512_DIGEST_LEN;
			break;
	}
	ctx->mac->final(md);
	delete ctx->mac;

	SAFE_FREE(ctx);
}

HMACCTX hmac_init(const void *key, int len, enum ssh_hmac_e type)
{
	HMACCTX c = NULL;

	switch (type)
	{
		case SSH_HMAC_SHA1:
			c = std::make_shared<Botan::HMAC>(new Botan::SHA_160());
			break;
		case SSH_HMAC_SHA256:
			c = std::make_shared<Botan::HMAC>(new Botan::SHA_256());
			break;
		case SSH_HMAC_SHA384:
			c = std::make_shared<Botan::HMAC>(new Botan::SHA_384());
			break;
		case SSH_HMAC_SHA512:
			c = std::make_shared<Botan::HMAC>(new Botan::SHA_512());
			break;
		case SSH_HMAC_MD5:
			c = std::make_shared<Botan::HMAC>(new Botan::MD5());
			break;
		default:
			c = NULL;
	}

	c->set_key((const uint8_t*)key, (size_t)len);

	return c;
}

void hmac_update(HMACCTX c, const void *data, unsigned long len)
{
	c->update((const uint8_t*)data, (size_t)len);
}

void hmac_final(HMACCTX c, unsigned char *hashmacbuf, unsigned int *len)
{
	*len = c->output_length();
	c->final(hashmacbuf);
}

/* the wrapper functions for blowfish */
static int blowfish_set_key(struct ssh_cipher_struct *cipher, void *key, void *IV)
{
	if (cipher->key == NULL)
	{
		alloc_key(cipher);

		ssh_cipher_key_struct* k = (ssh_cipher_key_struct*)cipher->key;
		k->algorithm = new Botan::Blowfish();
		k->encrypt = std::make_unique<Botan::CBC_Encryption>(k->algorithm, new Botan::Null_Padding());
		k->decrypt = std::make_unique<Botan::CBC_Decryption>(k->algorithm, new Botan::Null_Padding());

		k->algorithm->set_key((const uint8_t*)key, 16);
		k->encrypt->start((const uint8_t*)IV, 16);
		k->decrypt->start((const uint8_t*)IV, 16);
	}

	return 0;
}

static void blowfish_encrypt(struct ssh_cipher_struct *cipher, void *in,
							 void *out, unsigned long len)
{
	ssh_cipher_key_struct* k = (ssh_cipher_key_struct*)cipher->key;
	
	Botan::secure_vector<uint8_t> inData(len);
	memcpy(&inData[0], in, inData.size());

	k->encrypt->update(inData);
	k->encrypt->finish(inData);

	memcpy(out, &inData[0], inData.size());
}

static void blowfish_decrypt(struct ssh_cipher_struct *cipher, void *in,
							 void *out, unsigned long len)
{
	ssh_cipher_key_struct* k = (ssh_cipher_key_struct*)cipher->key;

	Botan::secure_vector<uint8_t> inData(len);
	memcpy(&inData[0], in, inData.size());

	k->decrypt->update(inData);
	k->decrypt->finish(inData);

	memcpy(out, &inData[0], inData.size());
}

static int aes_set_key(struct ssh_cipher_struct *cipher, void *key, void *IV)
{
	if (cipher->key == nullptr)
	{
		alloc_key(cipher);

		ssh_cipher_key_struct* k = (ssh_cipher_key_struct*)cipher->key;

		switch (cipher->keysize)
		{
			case 128:
				k->algorithm = new Botan::AES_128();
				break;

			case 192:
				k->algorithm = new Botan::AES_192();
				break;

			case 256:
				k->algorithm = new Botan::AES_256();
				break;
		}

		k->algorithm->set_key((const uint8_t*)key, cipher->keysize / 8);

		if (strstr(cipher->name, "-ctr"))
		{
			k->ctr = std::make_unique<Botan::CTR_BE>(k->algorithm);
			k->ctr->set_iv((const uint8_t*)IV, 16);
		}
		else
		{
			k->encrypt = std::make_unique<Botan::CBC_Encryption>(k->algorithm, new Botan::Null_Padding());
			k->decrypt = std::make_unique<Botan::CBC_Decryption>(k->algorithm, new Botan::Null_Padding());

			k->encrypt->start((const uint8_t*)IV, 16);
			k->decrypt->start((const uint8_t*)IV, 16);
		}
	}

	return 0;
}

static void aes_encrypt(struct ssh_cipher_struct *cipher, void *in, void *out,
						unsigned long len)
{
	ssh_cipher_key_struct* k = (ssh_cipher_key_struct*)cipher->key;

	Botan::secure_vector<uint8_t> inData(len);
	memcpy(&inData[0], in, inData.size());

	if (k->ctr.get())
	{
		k->ctr->encipher(inData);
	}
	else
	{
		k->encrypt->update(inData);
		k->encrypt->finish(inData);
	}

	memcpy(out, &inData[0], inData.size());
}

static void aes_decrypt(struct ssh_cipher_struct *cipher, void *in, void *out,
						unsigned long len) {
	ssh_cipher_key_struct* k = (ssh_cipher_key_struct*)cipher->key;

	Botan::secure_vector<uint8_t> inData(len);
	memcpy(&inData[0], in, inData.size());

	if (k->ctr.get())
	{
		k->ctr->encipher(inData);
	}
	else
	{
		k->decrypt->update(inData);
		k->decrypt->finish(inData);
	}

	memcpy(out, &inData[0], inData.size());
}

static int des1_set_key(struct ssh_cipher_struct *cipher, void *key, void *IV)
{
	if (cipher->key == nullptr)
	{
		alloc_key(cipher);

		ssh_cipher_key_struct* k = (ssh_cipher_key_struct*)cipher->key;

		k->algorithm = new Botan::DES();
		k->algorithm->set_key((uint8_t*)key, 8);

		k->encrypt = std::make_unique<Botan::CBC_Encryption>(k->algorithm, new Botan::Null_Padding());
		k->decrypt = std::make_unique<Botan::CBC_Decryption>(k->algorithm, new Botan::Null_Padding());

		k->encrypt->start((const uint8_t*)IV, 8);
		k->decrypt->start((const uint8_t*)IV, 8);
	}

	return 0;
}

static int des3_set_key(struct ssh_cipher_struct *cipher, void *key, void *IV) {
	if (cipher->key == nullptr)
	{
		alloc_key(cipher);

		ssh_cipher_key_struct* k = (ssh_cipher_key_struct*)cipher->key;

		k->algorithm = new Botan::TripleDES();
		k->algorithm->set_key((uint8_t*)key, 24);

		k->encrypt = std::make_unique<Botan::CBC_Encryption>(k->algorithm, new Botan::Null_Padding());
		k->decrypt = std::make_unique<Botan::CBC_Decryption>(k->algorithm, new Botan::Null_Padding());

		k->encrypt->start((const uint8_t*)IV, 8);
		k->decrypt->start((const uint8_t*)IV, 8);
	}

	return 0;
}

static void des_encrypt(struct ssh_cipher_struct *cipher, void *in,
						   void *out, unsigned long len)
{
	ssh_cipher_key_struct* k = (ssh_cipher_key_struct*)cipher->key;

	Botan::secure_vector<uint8_t> inData(len);
	memcpy(&inData[0], in, inData.size());

	k->encrypt->update(inData);
	k->encrypt->finish(inData);

	memcpy(out, &inData[0], inData.size());
}

static void des_decrypt(struct ssh_cipher_struct *cipher, void *in,
						void *out, unsigned long len)
{
	ssh_cipher_key_struct* k = (ssh_cipher_key_struct*)cipher->key;

	Botan::secure_vector<uint8_t> inData(len);
	memcpy(&inData[0], in, inData.size());

	k->decrypt->update(inData);
	k->decrypt->finish(inData);

	memcpy(out, &inData[0], inData.size());
}

static void des1_1_encrypt(struct ssh_cipher_struct *cipher, void *in,
						   void *out, unsigned long len) {
	des_encrypt(cipher, in, out, len);
}

static void des1_1_decrypt(struct ssh_cipher_struct *cipher, void *in,
						   void *out, unsigned long len) {
	des_decrypt(cipher, in, out, len);
}

static void des3_encrypt(struct ssh_cipher_struct *cipher, void *in,
						 void *out, unsigned long len) {
	des_encrypt(cipher, in, out, len);
}

static void des3_decrypt(struct ssh_cipher_struct *cipher, void *in,
						 void *out, unsigned long len) {
	des_decrypt(cipher, in, out, len);
}

/* the table of supported ciphers */
static struct ssh_cipher_struct ssh_ciphertab[] = {
	{
		"blowfish-cbc",
		8,
		0,
		NULL,
		128,
		blowfish_set_key,
		blowfish_set_key,
		blowfish_encrypt,
		blowfish_decrypt
	},
	{
		"aes128-ctr",
		16,
		0,
		NULL,
		128,
		aes_set_key,
		aes_set_key,
		aes_encrypt,
		aes_encrypt
	},
	{
		"aes192-ctr",
		16,
		0,
		NULL,
		192,
		aes_set_key,
		aes_set_key,
		aes_encrypt,
		aes_encrypt
	},
	{
		"aes256-ctr",
		16,
		0,
		NULL,
		256,
		aes_set_key,
		aes_set_key,
		aes_encrypt,
		aes_encrypt
	},
	{
		"aes128-cbc",
		16,
		0,
		NULL,
		128,
		aes_set_key,
		aes_set_key,
		aes_encrypt,
		aes_decrypt
		},
		{
			"aes192-cbc",
			16,
			0,
			NULL,
			192,
			aes_set_key,
			aes_set_key,
			aes_encrypt,
			aes_decrypt
		},
		{
			"aes256-cbc",
			16,
			0,
			NULL,
			256,
			aes_set_key,
			aes_set_key,
			aes_encrypt,
			aes_decrypt
		},
		{
			"3des-cbc",
			8,
			0,
			NULL,
			192,
			des3_set_key,
			des3_set_key,
			des3_encrypt,
			des3_decrypt
		},
		{
			NULL,
			0,
			0,
			NULL,
			0,
			NULL,
			NULL,
			NULL,
			NULL
		}
};

struct ssh_cipher_struct *ssh_get_ciphertab(void)
{
	return ssh_ciphertab;
}
#endif /* LIBCRYPTO */

