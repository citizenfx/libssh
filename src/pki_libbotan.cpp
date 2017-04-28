/*
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2009 Aris Adamantiadis
 * Copyright (c) 2009-2011 Andreas Schneider <asn@cryptomilk.org>
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

#ifdef HAVE_BOTAN

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <botan/rsa.h>
#include <botan/des.h>
#include <botan/aes.h>
#include <botan/cbc.h>
#include <botan/pk_ops.h>
#include <botan/pem.h>
#include <botan/pubkey.h>

#include "libssh/priv.h"
#include "libssh/buffer.h"
#include "libssh/session.h"
#include "libssh/wrapper.h"
#include "libssh/misc.h"
#include "libssh/pki.h"
#include "libssh/pki_priv.h"

#define MAXLINESIZE 80
#define RSA_HEADER_BEGIN "-----BEGIN RSA PRIVATE KEY-----"
#define RSA_HEADER_END "-----END RSA PRIVATE KEY-----"
#define DSA_HEADER_BEGIN "-----BEGIN DSA PRIVATE KEY-----"
#define DSA_HEADER_END "-----END DSA PRIVATE KEY-----"

#define MAX_KEY_SIZE 32
#define MAX_PASSPHRASE_SIZE 1024
#define ASN1_INTEGER 2
#define ASN1_SEQUENCE 48
#define PKCS5_SALT_LEN 8

static int load_iv(const char *header, unsigned char *iv, int iv_len) {
  int i;
  int j;
  int k;

  memset(iv, 0, iv_len);
  for (i = 0; i < iv_len; i++) {
    if ((header[2*i] >= '0') && (header[2*i] <= '9'))
      j = header[2*i] - '0';
    else if ((header[2*i] >= 'A') && (header[2*i] <= 'F'))
      j = header[2*i] - 'A' + 10;
    else if ((header[2*i] >= 'a') && (header[2*i] <= 'f'))
      j = header[2*i] - 'a' + 10;
    else
      return -1;
    if ((header[2*i+1] >= '0') && (header[2*i+1] <= '9'))
      k = header[2*i+1] - '0';
    else if ((header[2*i+1] >= 'A') && (header[2*i+1] <= 'F'))
      k = header[2*i+1] - 'A' + 10;
    else if ((header[2*i+1] >= 'a') && (header[2*i+1] <= 'f'))
      k = header[2*i+1] - 'a' + 10;
    else
      return -1;
    iv[i] = (j << 4) + k;
  }
  return 0;
}

static uint32_t char_to_u32(unsigned char *data, uint32_t size) {
  uint32_t ret;
  uint32_t i;

  for (i = 0, ret = 0; i < size; ret = ret << 8, ret += data[i++])
    ;
  return ret;
}

static uint32_t asn1_get_len(ssh_buffer buffer) {
  uint32_t len;
  unsigned char tmp[4];

  if (buffer_get_data(buffer,tmp,1) == 0) {
    return 0;
  }

  if (tmp[0] > 127) {
    len = tmp[0] & 127;
    if (len > 4) {
      return 0; /* Length doesn't fit in u32. Can this really happen? */
    }
    if (buffer_get_data(buffer,tmp,len) == 0) {
      return 0;
    }
    len = char_to_u32(tmp, len);
  } else {
    len = char_to_u32(tmp, 1);
  }

  return len;
}

static ssh_string asn1_get_int(ssh_buffer buffer) {
  ssh_string str;
  unsigned char type;
  uint32_t size;

  if (buffer_get_data(buffer, &type, 1) == 0 || type != ASN1_INTEGER) {
    return NULL;
  }
  size = asn1_get_len(buffer);
  if (size == 0) {
    return NULL;
  }

  str = ssh_string_new(size);
  if (str == NULL) {
    return NULL;
  }

  if (buffer_get_data(buffer, ssh_string_data(str), size) == 0) {
    ssh_string_free(str);
    return NULL;
  }

  return str;
}

static int asn1_check_sequence(ssh_buffer buffer) {
  unsigned char *j = NULL;
  unsigned char tmp;
  int i;
  uint32_t size;
  uint32_t padding;

  if (buffer_get_data(buffer, &tmp, 1) == 0 || tmp != ASN1_SEQUENCE) {
    return 0;
  }

  size = asn1_get_len(buffer);
  if ((padding = ssh_buffer_get_len(buffer) - buffer->pos - size) > 0) {
    for (i = ssh_buffer_get_len(buffer) - buffer->pos - size,
         j = (unsigned char*)ssh_buffer_get_begin(buffer) + size + buffer->pos;
         i;
         i--, j++)
    {
      if (*j != padding) {                   /* padding is allowed */
        return 0;                            /* but nothing else */
      }
    }
  }

  return 1;
}

static int passphrase_to_key(char *data, unsigned int datalen,
    unsigned char *salt, unsigned char *key, unsigned int keylen) {
  MD5CTX md;
  unsigned char digest[MD5_DIGEST_LEN] = {0};
  unsigned int i;
  unsigned int j;
  unsigned int md_not_empty;

  for (j = 0, md_not_empty = 0; j < keylen; ) {
    md = md5_init();
    if (md == NULL) {
      return -1;
    }

    if (md_not_empty) {
      md5_update(md, digest, MD5_DIGEST_LEN);
    } else {
      md_not_empty = 1;
    }

    md5_update(md, data, datalen);
    if (salt) {
      md5_update(md, salt, PKCS5_SALT_LEN);
    }
    md5_final(digest, md);

    for (i = 0; j < keylen && i < MD5_DIGEST_LEN; j++, i++) {
      if (key) {
        key[j] = digest[i];
      }
    }
  }

  return 0;
}

static int privatekey_decrypt(std::unique_ptr<Botan::SymmetricAlgorithm> algo, std::unique_ptr<Botan::Cipher_Mode> mode, unsigned int key_len,
                       unsigned char *iv, unsigned int iv_len,
                       ssh_buffer data, ssh_auth_callback cb,
                       void *userdata,
                       const char *desc)
{
  char passphrase[MAX_PASSPHRASE_SIZE] = {0};
  unsigned char key[MAX_KEY_SIZE] = {0};
  unsigned char *tmp = NULL;
  int rc = -1;

  if (!algo) {
    return -1;
  }

  if (cb) {
    rc = (*cb)(desc, passphrase, MAX_PASSPHRASE_SIZE, 0, 0, userdata);
    if (rc < 0) {
      return -1;
    }
  } else if (cb == NULL && userdata != NULL) {
    snprintf(passphrase, MAX_PASSPHRASE_SIZE, "%s", (char *) userdata);
  }

  if (passphrase_to_key(passphrase, strlen(passphrase), iv, key, key_len) < 0) {
    return -1;
  }

  algo->set_key((uint8_t*)key, key_len);
  mode->start((uint8_t*)iv, iv_len);

  Botan::secure_vector<uint8_t> dataBuf(ssh_buffer_get_len(data));
  memcpy(&dataBuf[0], ssh_buffer_get_begin(data), ssh_buffer_get_len(data));

  mode->update(dataBuf);
  mode->finish(dataBuf);

  memcpy(ssh_buffer_get_begin(data), &dataBuf[0], ssh_buffer_get_len(data));

  return 0;
}

static int privatekey_dek_header(const char *header, unsigned int header_len,
    std::unique_ptr<Botan::BlockCipher>& algo, std::unique_ptr<Botan::Cipher_Mode>& mode, unsigned int *key_len, unsigned char **iv,
    unsigned int *iv_len) {
  unsigned int iv_pos;

  if (header_len > 13 && !strncmp("DES-EDE3-CBC", header, 12))
  {
	algo = std::make_unique<Botan::TripleDES>();
    iv_pos = 13;
    mode = std::make_unique<Botan::CBC_Decryption>(algo.get(), new Botan::Null_Padding());
    *key_len = 24;
    *iv_len = 8;
  }
  else if (header_len > 8 && !strncmp("DES-CBC", header, 7))
  {
    algo = std::make_unique<Botan::DES>();
    iv_pos = 8;
    mode = std::make_unique<Botan::CBC_Decryption>(algo.get(), new Botan::Null_Padding());
    *key_len = 8;
    *iv_len = 8;
  }
  else if (header_len > 12 && !strncmp("AES-128-CBC", header, 11))
  {
    algo = std::make_unique<Botan::AES_128>();
    iv_pos = 12;
    mode = std::make_unique<Botan::CBC_Decryption>(algo.get(), new Botan::Null_Padding());
    *key_len = 16;
    *iv_len = 16;
  }
  else if (header_len > 12 && !strncmp("AES-192-CBC", header, 11))
  {
    algo = std::make_unique<Botan::AES_192>();
    iv_pos = 12;
    mode = std::make_unique<Botan::CBC_Decryption>(algo.get(), new Botan::Null_Padding());
    *key_len = 24;
    *iv_len = 16;
  }
  else if (header_len > 12 && !strncmp("AES-256-CBC", header, 11))
  {
    algo = std::make_unique<Botan::AES_256>();
    iv_pos = 12;
    mode = std::make_unique<Botan::CBC_Decryption>(algo.get(), new Botan::Null_Padding());
    *key_len = 32;
    *iv_len = 16;
  } else {
    return -1;
  }

  *iv = (unsigned char*)malloc(*iv_len);
  if (*iv == NULL) {
    return -1;
  }

  return load_iv(header + iv_pos, *iv, *iv_len);
}

#define get_next_line(p, len) {                                         \
        while(p[len] == '\n' || p[len] == '\r') /* skip empty lines */  \
            len++;                                                      \
        if(p[len] == '\0')    /* EOL */                                 \
            len = -1;                                                   \
        else                  /* calculate length */                    \
            for(p += len, len = 0; p[len] && p[len] != '\n'             \
                                          && p[len] != '\r'; len++);    \
    }

static ssh_buffer privatekey_string_to_buffer(const char *pkey, int type,
                ssh_auth_callback cb, void *userdata, const char *desc) {
    ssh_buffer buffer = NULL;
    ssh_buffer out = NULL;
    const char *p;
    unsigned char *iv = NULL;
    const char *header_begin;
    const char *header_end;
    unsigned int header_begin_size;
    unsigned int header_end_size;
    unsigned int key_len = 0;
    unsigned int iv_len = 0;
	std::unique_ptr<Botan::BlockCipher> algo;
	std::unique_ptr<Botan::Cipher_Mode> mode;
    int len;

    buffer = ssh_buffer_new();
    if (buffer == NULL) {
        return NULL;
    }

    switch(type) {
        case SSH_KEYTYPE_DSS:
            header_begin = DSA_HEADER_BEGIN;
            header_end = DSA_HEADER_END;
            break;
        case SSH_KEYTYPE_RSA:
            header_begin = RSA_HEADER_BEGIN;
            header_end = RSA_HEADER_END;
            break;
        default:
            ssh_buffer_free(buffer);
            return NULL;
    }

    header_begin_size = strlen(header_begin);
    header_end_size = strlen(header_end);

    p = pkey;
    len = 0;
    get_next_line(p, len);

    while(len > 0 && strncmp(p, header_begin, header_begin_size)) {
        /* skip line */
        get_next_line(p, len);
    }
    if(len < 0) {
        /* no header found */
        return NULL;
    }
    /* skip header line */
    get_next_line(p, len);

    if (len > 11 && strncmp("Proc-Type: 4,ENCRYPTED", p, 11) == 0) {
        /* skip line */
        get_next_line(p, len);

        if (len > 10 && strncmp("DEK-Info: ", p, 10) == 0) {
            p += 10;
            len = 0;
            get_next_line(p, len);
            if (privatekey_dek_header(p, len, algo, mode, &key_len,
                        &iv, &iv_len) < 0) {
                ssh_buffer_free(buffer);
                SAFE_FREE(iv);
                return NULL;
            }
        } else {
            ssh_buffer_free(buffer);
            SAFE_FREE(iv);
            return NULL;
        }
    } else {
        if(len > 0) {
            if (ssh_buffer_add_data(buffer, p, len) < 0) {
                ssh_buffer_free(buffer);
                SAFE_FREE(iv);
                return NULL;
            }
        }
    }

    get_next_line(p, len);
    while(len > 0 && strncmp(p, header_end, header_end_size) != 0) {
        if (ssh_buffer_add_data(buffer, p, len) < 0) {
            ssh_buffer_free(buffer);
            SAFE_FREE(iv);
            return NULL;
        }
        get_next_line(p, len);
    }

    if (len == -1 || strncmp(p, header_end, header_end_size) != 0) {
        ssh_buffer_free(buffer);
        SAFE_FREE(iv);
        return NULL;
    }

    if (ssh_buffer_add_data(buffer, "\0", 1) < 0) {
        ssh_buffer_free(buffer);
        SAFE_FREE(iv);
        return NULL;
    }

    out = base64_to_bin((const char*)ssh_buffer_get_begin(buffer));
    ssh_buffer_free(buffer);
    if (out == NULL) {
        SAFE_FREE(iv);
        return NULL;
    }

    if (algo.get()) {
        if (privatekey_decrypt(std::move(algo), std::move(mode), key_len, iv, iv_len, out,
                    cb, userdata, desc) < 0) {
            ssh_buffer_free(out);
            SAFE_FREE(iv);
            return NULL;
        }
    }
    SAFE_FREE(iv);

    return out;
}

static int b64decode_rsa_privatekey(const char *pkey, std::shared_ptr<Botan::RSA_PrivateKey>& r,
    ssh_auth_callback cb, void *userdata, const char *desc) {
  const unsigned char *data;
  ssh_string n = NULL;
  ssh_string e = NULL;
  ssh_string d = NULL;
  ssh_string p = NULL;
  ssh_string q = NULL;
  ssh_string unused1 = NULL;
  ssh_string unused2 = NULL;
  ssh_string u = NULL;
  ssh_string v = NULL;
  ssh_buffer buffer = NULL;
  int rc = 1;

  buffer = privatekey_string_to_buffer(pkey, SSH_KEYTYPE_RSA, cb, userdata, desc);
  if (buffer == NULL) {
    return 0;
  }

  if (!asn1_check_sequence(buffer)) {
    ssh_buffer_free(buffer);
    return 0;
  }

  v = asn1_get_int(buffer);
  if (v == NULL) {
    ssh_buffer_free(buffer);
    return 0;
  }

  data = (uint8_t*)ssh_string_data(v);
  if (ssh_string_len(v) != 1 || data[0] != 0) {
    ssh_buffer_free(buffer);
    return 0;
  }

  n = asn1_get_int(buffer);
  e = asn1_get_int(buffer);
  d = asn1_get_int(buffer);
  q = asn1_get_int(buffer);
  p = asn1_get_int(buffer);
  unused1 = asn1_get_int(buffer);
  unused2 = asn1_get_int(buffer);
  u = asn1_get_int(buffer);

  ssh_buffer_free(buffer);

  if (n == NULL || e == NULL || d == NULL || p == NULL || q == NULL ||
      unused1 == NULL || unused2 == NULL|| u == NULL) {
    rc = 0;
    goto error;
  }

  {
	  Botan::BigInt nn((uint8_t*)ssh_string_data(n), ssh_string_len(n));
	  Botan::BigInt ee((uint8_t*)ssh_string_data(e), ssh_string_len(e));
	  Botan::BigInt dd((uint8_t*)ssh_string_data(d), ssh_string_len(d));
	  Botan::BigInt pp((uint8_t*)ssh_string_data(p), ssh_string_len(p));
	  Botan::BigInt qq((uint8_t*)ssh_string_data(q), ssh_string_len(q));
	  Botan::BigInt uu((uint8_t*)ssh_string_data(u), ssh_string_len(u));

	  Botan::RSA_PrivateKey pk(pp, qq, ee, dd, nn);

	  r = std::make_shared<Botan::RSA_PrivateKey>(pk);
  }

error:
  ssh_string_free(n);
  ssh_string_free(e);
  ssh_string_free(d);
  ssh_string_free(p);
  ssh_string_free(q);
  ssh_string_free(unused1);
  ssh_string_free(unused2);
  ssh_string_free(u);
  ssh_string_free(v);

  return rc;
}

static int b64decode_dsa_privatekey(const char *pkey, std::shared_ptr<Botan::DSA_PrivateKey>& r, ssh_auth_callback cb,
    void *userdata, const char *desc) {
  const unsigned char *data;
  ssh_buffer buffer = NULL;
  ssh_string p = NULL;
  ssh_string q = NULL;
  ssh_string g = NULL;
  ssh_string y = NULL;
  ssh_string x = NULL;
  ssh_string v = NULL;
  int rc = 1;

  buffer = privatekey_string_to_buffer(pkey, SSH_KEYTYPE_DSS, cb, userdata, desc);
  if (buffer == NULL) {
    return 0;
  }

  if (!asn1_check_sequence(buffer)) {
    ssh_buffer_free(buffer);
    return 0;
  }

  v = asn1_get_int(buffer);
  if (v == NULL) {
    ssh_buffer_free(buffer);
    return 0;
  }

  data = (uint8_t*)ssh_string_data(v);
  if (ssh_string_len(v) != 1 || data[0] != 0) {
    ssh_buffer_free(buffer);
    return 0;
  }

  p = asn1_get_int(buffer);
  q = asn1_get_int(buffer);
  g = asn1_get_int(buffer);
  y = asn1_get_int(buffer);
  x = asn1_get_int(buffer);
  ssh_buffer_free(buffer);

  if (p == NULL || q == NULL || g == NULL || y == NULL || x == NULL) {
    rc = 0;
    goto error;
  }

  {
	  Botan::BigInt pp((uint8_t*)ssh_string_data(p), ssh_string_len(p));
	  Botan::BigInt qq((uint8_t*)ssh_string_data(q), ssh_string_len(q));
	  Botan::BigInt gg((uint8_t*)ssh_string_data(g), ssh_string_len(g));
	  Botan::BigInt xx((uint8_t*)ssh_string_data(x), ssh_string_len(x));

	  Botan::AutoSeeded_RNG rng;
	  Botan::DL_Group dl(pp, qq, gg);

	  r = std::make_shared<Botan::DSA_PrivateKey>(rng, dl, xx);
  }

error:
  ssh_string_free(p);
  ssh_string_free(q);
  ssh_string_free(g);
  ssh_string_free(y);
  ssh_string_free(x);
  ssh_string_free(v);

  return rc;
}

#ifdef HAVE_GCRYPT_ECC
int pki_key_ecdsa_nid_from_name(const char *name)
{
    return -1;
}
#endif

ssh_string pki_private_key_to_pem(const ssh_key key,
                                  const char *passphrase,
                                  ssh_auth_callback auth_fn,
                                  void *auth_data)
{
    (void) key;
    (void) passphrase;
    (void) auth_fn;
    (void) auth_data;

	std::shared_ptr<Botan::Private_Key> pkey;

	if (key->type == SSH_KEYTYPE_RSA)
	{
		pkey = key->rsa;
	}
	else if (key->type == SSH_KEYTYPE_DSS)
	{
		pkey = key->dsa;
	}

	if (pkey.get())
	{
		Botan::AutoSeeded_RNG rng;
		std::string pem;

		pem = Botan::PEM_Code::encode(pkey->private_key_bits(), pkey->algo_name() + " PRIVATE KEY");

/*		if (passphrase)
		{
			pem = Botan::PKCS8::PEM_encode(*pkey.get(), rng, std::string(passphrase), std::chrono::milliseconds(1000));
		}
		else
		{
			pem = Botan::PKCS8::PEM_encode(*pkey.get());
		}*/

		ssh_string str = ssh_string_new(pem.size());
		ssh_string_fill(str, pem.c_str(), pem.size());

		return str;
	}

    return NULL;
}

ssh_key pki_private_key_from_base64(const char *b64_key,
                                    const char *passphrase,
                                    ssh_auth_callback auth_fn,
                                    void *auth_data)
{
    std::shared_ptr<Botan::DSA_PrivateKey> dsa;
    std::shared_ptr<Botan::RSA_PrivateKey> rsa;
    ssh_key key = NULL;
    enum ssh_keytypes_e type;
    int valid;

    /* needed for gcrypt initialization */
    if (ssh_init() < 0) {
        return NULL;
    }

    type = pki_privatekey_type_from_string(b64_key);
    if (type == SSH_KEYTYPE_UNKNOWN) {
        ssh_pki_log("Unknown or invalid private key.");
        return NULL;
    }

    switch (type) {
        case SSH_KEYTYPE_DSS:
            if (passphrase == NULL) {
                if (auth_fn) {
                    valid = b64decode_dsa_privatekey(b64_key, dsa, auth_fn,
                            auth_data, "Passphrase for private key:");
                } else {
                    valid = b64decode_dsa_privatekey(b64_key, dsa, NULL, NULL,
                            NULL);
                }
            } else {
                valid = b64decode_dsa_privatekey(b64_key, dsa, NULL, (void *)
                        passphrase, NULL);
            }

            if (!valid) {
                ssh_pki_log("Parsing private key");
                goto fail;
            }
            break;
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            if (passphrase == NULL) {
                if (auth_fn) {
                    valid = b64decode_rsa_privatekey(b64_key, rsa, auth_fn,
                            auth_data, "Passphrase for private key:");
                } else {
                    valid = b64decode_rsa_privatekey(b64_key, rsa, NULL, NULL,
                            NULL);
                }
            } else {
                valid = b64decode_rsa_privatekey(b64_key, rsa, NULL,
                        (void *)passphrase, NULL);
            }

            if (!valid) {
                ssh_pki_log("Parsing private key");
                goto fail;
            }
            break;
        case SSH_KEYTYPE_ED25519:
		/* Cannot open ed25519 keys with libgcrypt */
        case SSH_KEYTYPE_ECDSA:
        case SSH_KEYTYPE_UNKNOWN:
        default:
            ssh_pki_log("Unkown or invalid private key type %d", type);
            return NULL;
    }

    key = ssh_key_new();
    if (key == NULL) {
        goto fail;
    }

    key->type = type;
    key->type_c = ssh_key_type_to_char(type);
    key->flags = SSH_KEY_FLAG_PRIVATE | SSH_KEY_FLAG_PUBLIC;
    key->dsa = dsa;
    key->rsa = rsa;

    return key;
fail:
    ssh_key_free(key);

    return NULL;
}

int pki_pubkey_build_dss(ssh_key key,
                         ssh_string p,
                         ssh_string q,
                         ssh_string g,
                         ssh_string pubkey) {


	Botan::BigInt pp((uint8_t*)ssh_string_data(p), ssh_string_len(p));
	Botan::BigInt qq((uint8_t*)ssh_string_data(q), ssh_string_len(q));
	Botan::BigInt gg((uint8_t*)ssh_string_data(g), ssh_string_len(g));
	Botan::BigInt yy((uint8_t*)ssh_string_data(pubkey), ssh_string_len(pubkey));

	Botan::AutoSeeded_RNG rng;
	Botan::DL_Group dl(pp, qq, gg);

	//key->dsa = std::make_shared<Botan::DSA_PublicKey>(dl, yy);
	Botan::DSA_PublicKey pubKey(dl, yy);

	key->dsa_pub = std::make_shared<Botan::DSA_PublicKey>(pubKey);

    return SSH_OK;
}

int pki_pubkey_build_rsa(ssh_key key,
                         ssh_string e,
                         ssh_string n) {

	Botan::BigInt ee((uint8_t*)ssh_string_data(e), ssh_string_len(e));
	Botan::BigInt nn((uint8_t*)ssh_string_data(n), ssh_string_len(n));

	Botan::AutoSeeded_RNG rng;

	Botan::RSA_PublicKey pubKey(nn, ee);

	key->rsa_pub = std::make_shared<Botan::RSA_PublicKey>(pubKey);

    return SSH_OK;
}

#ifdef HAVE_GCRYPT_ECC
int pki_pubkey_build_ecdsa(ssh_key key, int nid, ssh_string e)
{
    return -1;
}
#endif

ssh_key pki_key_dup(const ssh_key key, int demote)
{
    ssh_key newk;
    const char *tmp = NULL;
    size_t size;
    int rc;

    ssh_string p = NULL;
    ssh_string q = NULL;
    ssh_string g = NULL;
    ssh_string y = NULL;
    ssh_string x = NULL;

    ssh_string e = NULL;
    ssh_string n = NULL;
    ssh_string d = NULL;
    ssh_string u = NULL;

    newk = ssh_key_new();
    if (newk == NULL) {
        return NULL;
    }
    newk->type = key->type;
    newk->type_c = key->type_c;
    if (demote) {
        newk->flags = SSH_KEY_FLAG_PUBLIC;
    } else {
        newk->flags = key->flags;
    }

	switch (key->type)
	{
		case SSH_KEYTYPE_DSS:
		{
			Botan::BigInt val = key->dsa->group_p();
			ssh_string v = ssh_string_new(val.bytes());
			val.binary_encode((uint8_t*)ssh_string_data(v));

			p = v;
		}

			{
				Botan::BigInt val = key->dsa->group_q();
				ssh_string v = ssh_string_new(val.bytes());
				val.binary_encode((uint8_t*)ssh_string_data(v));

				q = v;
			}

			{
				Botan::BigInt val = key->dsa->group_g();
				ssh_string v = ssh_string_new(val.bytes());
				val.binary_encode((uint8_t*)ssh_string_data(v));

				g = v;
			}

			{
				Botan::BigInt val = key->dsa->get_y();
				ssh_string v = ssh_string_new(val.bytes());
				val.binary_encode((uint8_t*)ssh_string_data(v));

				y = v;
			}

			{
				Botan::BigInt val = key->dsa->group_p();
				ssh_string v = ssh_string_new(val.bytes());
				val.binary_encode((uint8_t*)ssh_string_data(v));

				p = v;
			}

			if (!demote && (key->flags & SSH_KEY_FLAG_PRIVATE))
			{
				{
					Botan::BigInt val = key->dsa->get_x();
					ssh_string v = ssh_string_new(val.bytes());
					val.binary_encode((uint8_t*)ssh_string_data(v));

					x = v;
				}

				Botan::BigInt pp((uint8_t*)ssh_string_data(p), ssh_string_len(p));
				Botan::BigInt qq((uint8_t*)ssh_string_data(q), ssh_string_len(q));
				Botan::BigInt gg((uint8_t*)ssh_string_data(g), ssh_string_len(g));
				Botan::BigInt xx((uint8_t*)ssh_string_data(x), ssh_string_len(x));

				Botan::AutoSeeded_RNG rng;
				Botan::DL_Group dl(pp, qq, gg);

				newk->dsa = std::make_shared<Botan::DSA_PrivateKey>(rng, dl, xx);
				pki_pubkey_build_dss(key, p, q, g, y);
			}
			else
			{
				pki_pubkey_build_dss(key, p, q, g, y);
			}

			ssh_string_burn(p);
			ssh_string_free(p);
			ssh_string_burn(q);
			ssh_string_free(q);
			ssh_string_burn(g);
			ssh_string_free(g);
			ssh_string_burn(y);
			ssh_string_free(y);
			ssh_string_burn(x);
			ssh_string_free(x);
			break;
		case SSH_KEYTYPE_RSA:
		case SSH_KEYTYPE_RSA1:
			if (!key->rsa_pub.get())
			{
				{
					Botan::BigInt val = key->rsa->get_e();
					ssh_string v = ssh_string_new(val.bytes());
					val.binary_encode((uint8_t*)ssh_string_data(v));

					e = v;
				}

				{
					Botan::BigInt val = key->rsa->get_n();
					ssh_string v = ssh_string_new(val.bytes());
					val.binary_encode((uint8_t*)ssh_string_data(v));

					n = v;
				}

				pki_pubkey_build_rsa(key, e, n);
			}

			if (!demote && (key->flags & SSH_KEY_FLAG_PRIVATE))
			{
				newk->rsa = key->rsa;
				newk->rsa_pub = key->rsa_pub;
			}
			else
			{
				newk->rsa.reset();
				newk->rsa_pub = key->rsa_pub;
			}
			/*else
			{
				{
					Botan::BigInt val = key->rsa->get_e();
					ssh_string v = ssh_string_new(val.bytes());
					val.binary_encode((uint8_t*)ssh_string_data(v));

					e = v;
				}

				{
					Botan::BigInt val = key->rsa->get_n();
					ssh_string v = ssh_string_new(val.bytes());
					val.binary_encode((uint8_t*)ssh_string_data(v));

					n = v;
				}

				if (!demote && (key->flags & SSH_KEY_FLAG_PRIVATE))
				{
					{
						Botan::BigInt val = key->rsa->get_d();
						ssh_string v = ssh_string_new(val.bytes());
						val.binary_encode((uint8_t*)ssh_string_data(v));

						d = v;
					}

					{
						Botan::BigInt val = key->rsa->get_p();
						ssh_string v = ssh_string_new(val.bytes());
						val.binary_encode((uint8_t*)ssh_string_data(v));

						p = v;
					}

					{
						Botan::BigInt val = key->rsa->get_q();
						ssh_string v = ssh_string_new(val.bytes());
						val.binary_encode((uint8_t*)ssh_string_data(v));

						q = v;
					}

					Botan::AutoSeeded_RNG rng;
					Botan::BigInt nn((uint8_t*)ssh_string_data(n), ssh_string_len(n));
					Botan::BigInt ee((uint8_t*)ssh_string_data(e), ssh_string_len(e));
					Botan::BigInt dd((uint8_t*)ssh_string_data(d), ssh_string_len(d));
					Botan::BigInt pp((uint8_t*)ssh_string_data(p), ssh_string_len(p));
					Botan::BigInt qq((uint8_t*)ssh_string_data(q), ssh_string_len(q));
					Botan::BigInt uu((uint8_t*)ssh_string_data(u), ssh_string_len(u));

					Botan::RSA_PrivateKey pk(rng, pp, qq, ee, dd, nn);

					newk->rsa = std::make_shared<Botan::RSA_PrivateKey>(pk);
					pki_pubkey_build_rsa(newk, e, n);
				}
				else
				{
					pki_pubkey_build_rsa(newk, e, n);
				}

				ssh_string_burn(e);
				ssh_string_free(e);
				ssh_string_burn(n);
				ssh_string_free(n);
				ssh_string_burn(d);
				ssh_string_free(d);
				ssh_string_burn(p);
				ssh_string_free(p);
				ssh_string_burn(q);
				ssh_string_free(q);
				ssh_string_burn(u);
				ssh_string_free(u);
			}*/

            break;
        case SSH_KEYTYPE_ED25519:
		rc = pki_ed25519_key_dup(newk, key);
		if (rc != SSH_OK){
			goto fail;
		}
		break;

        case SSH_KEYTYPE_ECDSA:
        case SSH_KEYTYPE_UNKNOWN:
        default:
            ssh_key_free(newk);
            return NULL;
    }

    return newk;
fail:
    ssh_string_burn(p);
    ssh_string_free(p);
    ssh_string_burn(q);
    ssh_string_free(q);
    ssh_string_burn(g);
    ssh_string_free(g);
    ssh_string_burn(y);
    ssh_string_free(y);
    ssh_string_burn(x);
    ssh_string_free(x);

    ssh_string_burn(e);
    ssh_string_free(e);
    ssh_string_burn(n);
    ssh_string_free(n);
    ssh_string_burn(u);
    ssh_string_free(u);

    ssh_key_free(newk);

    return NULL;
}

static int pki_key_generate(ssh_key key, int parameter, const char *type_s, int type){
	Botan::AutoSeeded_RNG rng;

	if (type == SSH_KEYTYPE_RSA)
	{
		key->rsa = std::make_shared<Botan::RSA_PrivateKey>(rng, parameter);
	}
	else
	{
		Botan::DL_Group dl(rng, Botan::DL_Group::DSA_Kosherizer, parameter);

		key->dsa = std::make_shared<Botan::DSA_PrivateKey>(rng, dl);
	}

    return SSH_OK;
}

int pki_key_generate_rsa(ssh_key key, int parameter){
    return pki_key_generate(key, parameter, "rsa", SSH_KEYTYPE_RSA);
}
int pki_key_generate_dss(ssh_key key, int parameter){
    return pki_key_generate(key, parameter, "dsa", SSH_KEYTYPE_DSS);
}

#ifdef HAVE_GCRYPT_ECC
int pki_key_generate_ecdsa(ssh_key key, int parameter) {
    return -1;
}
#endif

int pki_key_compare(const ssh_key k1,
                    const ssh_key k2,
                    enum ssh_keycmp_e what)
{
    switch (k1->type) {
        case SSH_KEYTYPE_DSS:
			if (k1->dsa->group_p() != k2->dsa->group_p())
			{
				return 1;
			}

			if (k1->dsa->group_q() != k2->dsa->group_q())
			{
				return 1;
			}

			if (k1->dsa->group_g() != k2->dsa->group_g())
			{
				return 1;
			}

			if (k1->dsa->get_y() != k2->dsa->get_y())
			{
				return 1;
			}

            if (what == SSH_KEY_CMP_PRIVATE) {
				if (k1->dsa->get_x() != k2->dsa->get_x()) {
                    return 1;
                }
            }
            break;
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
			if (k1->rsa->get_e() != k2->rsa->get_e()) {
                return 1;
            }

            if (k1->rsa->get_n() != k2->rsa->get_n()) {
                return 1;
            }

            if (what == SSH_KEY_CMP_PRIVATE) {
				if (k1->rsa->get_d() != k2->rsa->get_d()) {
                    return 1;
                }

                if (k1->rsa->get_p() != k2->rsa->get_p()) {
                    return 1;
                }

                if (k1->rsa->get_q() != k2->rsa->get_q()) {
                    return 1;
                }
            }
            break;
        case SSH_KEYTYPE_ED25519:
		/* ed25519 keys handled globaly */
		return 0;
        case SSH_KEYTYPE_ECDSA:
        case SSH_KEYTYPE_UNKNOWN:
            return 1;
    }

    return 0;
}

ssh_string pki_publickey_to_blob(const ssh_key key)
{
    ssh_buffer buffer;
    ssh_string type_s;
    ssh_string str = NULL;
    ssh_string e = NULL;
    ssh_string n = NULL;
    ssh_string p = NULL;
    ssh_string g = NULL;
    ssh_string q = NULL;
    const char *tmp = NULL;
    size_t size;
    int rc;

    buffer = ssh_buffer_new();
    if (buffer == NULL) {
        return NULL;
    }

    type_s = ssh_string_from_char(key->type_c);
    if (type_s == NULL) {
        ssh_buffer_free(buffer);
        return NULL;
    }

    rc = buffer_add_ssh_string(buffer, type_s);
    ssh_string_free(type_s);
    if (rc < 0) {
        ssh_buffer_free(buffer);
        return NULL;
    }

	std::shared_ptr<Botan::DSA_PublicKey> dsa = (key->dsa.get()) ? key->dsa : key->dsa_pub;
	std::shared_ptr<Botan::RSA_PublicKey> rsa = (key->rsa.get()) ? key->rsa : key->rsa_pub;

    switch (key->type) {
        case SSH_KEYTYPE_DSS:
			{
				Botan::BigInt val = dsa->group_p();
				ssh_string v = ssh_string_new(val.bytes());
				val.binary_encode((uint8_t*)ssh_string_data(v));

				p = v;
			}

			{
				Botan::BigInt val = dsa->group_q();
				ssh_string v = ssh_string_new(val.bytes());
				val.binary_encode((uint8_t*)ssh_string_data(v));

				q = v;
			}

			{
				Botan::BigInt val = dsa->group_g();
				ssh_string v = ssh_string_new(val.bytes());
				val.binary_encode((uint8_t*)ssh_string_data(v));

				g = v;
			}

			{
				Botan::BigInt val = dsa->get_y();
				ssh_string v = ssh_string_new(val.bytes());
				val.binary_encode((uint8_t*)ssh_string_data(v));

				n = v;
			}

            if (buffer_add_ssh_string(buffer, p) < 0) {
                goto fail;
            }
            if (buffer_add_ssh_string(buffer, q) < 0) {
                goto fail;
            }
            if (buffer_add_ssh_string(buffer, g) < 0) {
                goto fail;
            }
            if (buffer_add_ssh_string(buffer, n) < 0) {
                goto fail;
            }

            ssh_string_burn(p);
            ssh_string_free(p);
            ssh_string_burn(g);
            ssh_string_free(g);
            ssh_string_burn(q);
            ssh_string_free(q);
            ssh_string_burn(n);
            ssh_string_free(n);

            break;
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
			{
				Botan::BigInt val = rsa->get_e();
				ssh_string v = ssh_string_new(val.encoded_size());
				val.binary_encode((uint8_t*)ssh_string_data(v));

				e = v;
			}

			// make sure the BigInt isn't negative
			{
				Botan::BigInt val = rsa->get_n();

				Botan::secure_vector<uint8_t> data(val.encoded_size());
				val.binary_encode(&data[0]);

				int offset = 0;

				if (data[0] & 0x80)
				{
					offset = 1;
				}

				ssh_string v = ssh_string_new(data.size() + offset);
				memset(ssh_string_data(v), 0, 4);
				memcpy((char*)ssh_string_data(v) + offset, &data[0], data.size());

				n = v;
			}

            if (buffer_add_ssh_string(buffer, e) < 0) {
                goto fail;
            }
            if (buffer_add_ssh_string(buffer, n) < 0) {
                goto fail;
            }

            ssh_string_burn(e);
            ssh_string_free(e);
            ssh_string_burn(n);
            ssh_string_free(n);

            break;
        case SSH_KEYTYPE_ED25519:
		rc = pki_ed25519_public_key_to_blob(buffer, key);
		if (rc != SSH_OK){
			goto fail;
		}
		break;
        case SSH_KEYTYPE_ECDSA:
        case SSH_KEYTYPE_UNKNOWN:
        default:
            goto fail;
    }

    str = ssh_string_new(buffer_get_rest_len(buffer));
    if (str == NULL) {
        goto fail;
    }

    rc = ssh_string_fill(str, buffer_get_rest(buffer), buffer_get_rest_len(buffer));
    if (rc < 0) {
        goto fail;
    }
    ssh_buffer_free(buffer);

    return str;
fail:
    ssh_buffer_free(buffer);
    ssh_string_burn(str);
    ssh_string_free(str);
    ssh_string_burn(e);
    ssh_string_free(e);
    ssh_string_burn(p);
    ssh_string_free(p);
    ssh_string_burn(g);
    ssh_string_free(g);
    ssh_string_burn(q);
    ssh_string_free(q);
    ssh_string_burn(n);
    ssh_string_free(n);

    return NULL;
}

int pki_export_pubkey_rsa1(const ssh_key key,
                           const char *host,
                           char *rsa1,
                           size_t rsa1_len)
{
    /*gcry_sexp_t sexp;
    int rsa_size;
    bignum b;
    char *e, *n;

    sexp = gcry_sexp_find_token(key->rsa, "e", 0);
    if (sexp == NULL) {
        return SSH_ERROR;
    }
    b = gcry_sexp_nth_mpi(sexp, 1, GCRYMPI_FMT_USG);
    gcry_sexp_release(sexp);
    if (b == NULL) {
        return SSH_ERROR;
    }
    e = bignum_bn2dec(b);

    sexp = gcry_sexp_find_token(key->rsa, "n", 0);
    if (sexp == NULL) {
        SAFE_FREE(e);
        return SSH_ERROR;
    }
    b = gcry_sexp_nth_mpi(sexp, 1, GCRYMPI_FMT_USG);
    gcry_sexp_release(sexp);
    if (b == NULL) {
        SAFE_FREE(e);
        return SSH_ERROR;
    }
    n = bignum_bn2dec(b);

    rsa_size = (gcry_pk_get_nbits(key->rsa) + 7) / 8;

    snprintf(rsa1, rsa1_len,
             "%s %d %s %s\n",
             host, rsa_size << 3, e, n);
    SAFE_FREE(e);
    SAFE_FREE(n);

    return SSH_OK;*/
	return SSH_ERROR;
}

ssh_string pki_signature_to_blob(const ssh_signature sig)
{
	size_t size = 0;
	ssh_string sig_blob = NULL;

	switch (sig->type)
	{
		case SSH_KEYTYPE_DSS:
			sig_blob = ssh_string_copy(sig->dsa_sig);
			break;

		case SSH_KEYTYPE_RSA:
		case SSH_KEYTYPE_RSA1:
			sig_blob = ssh_string_copy(sig->rsa_sig);
			break;

		case SSH_KEYTYPE_ED25519:
			sig_blob = pki_ed25519_sig_to_blob(sig);
			break;
		case SSH_KEYTYPE_ECDSA:
		case SSH_KEYTYPE_UNKNOWN:
		default:
			ssh_pki_log("Unknown signature key type: %d", sig->type);
			return NULL;
			break;
	}

	return sig_blob;
}

ssh_signature pki_signature_from_blob(const ssh_key pubkey,
                                      const ssh_string sig_blob,
                                      enum ssh_keytypes_e type)
{
    ssh_signature sig;
    size_t len;
    size_t rsalen;
    int rc;

    sig = ssh_signature_new();
    if (sig == NULL) {
        return NULL;
    }

    sig->type = type;

    len = ssh_string_len(sig_blob);

	std::shared_ptr<Botan::RSA_PublicKey> rsa = (pubkey->rsa.get()) ? pubkey->rsa : pubkey->rsa_pub;

    switch(type) {
        case SSH_KEYTYPE_DSS:
            /* 40 is the dual signature blob len. */
            if (len != 40) {
                ssh_pki_log("Signature has wrong size: %lu",
                            (unsigned long)len);
                ssh_signature_free(sig);
                return NULL;
            }

			sig->dsa_sig = ssh_string_copy(sig_blob);
            break;
        case SSH_KEYTYPE_RSA:
        case SSH_KEYTYPE_RSA1:
            rsalen = (rsa->key_length() + 7) / 8;

            if (len > rsalen) {
                ssh_pki_log("Signature is to big size: %lu",
                            (unsigned long)len);
                ssh_signature_free(sig);
                return NULL;
            }

            if (len < rsalen) {
                ssh_pki_log("RSA signature len %lu < %lu",
                            (unsigned long)len, (unsigned long)rsalen);
            }

			sig->rsa_sig = ssh_string_copy(sig_blob);
			break;
        case SSH_KEYTYPE_ED25519:
		rc = pki_ed25519_sig_from_blob(sig, sig_blob);
		if (rc != SSH_OK){
			ssh_signature_free(sig);
			return NULL;
		}
		break;
        case SSH_KEYTYPE_ECDSA:
        case SSH_KEYTYPE_UNKNOWN:
        default:
            ssh_pki_log("Unknown signature type");
            return NULL;
    }

    return sig;
}

int pki_signature_verify(ssh_session session,
                         const ssh_signature sig,
                         const ssh_key key,
                         const unsigned char *hash,
                         size_t hlen)
{
    int err;

    switch(key->type) {
		case SSH_KEYTYPE_DSS:
			{
				std::shared_ptr<Botan::DSA_PublicKey> dsa = (key->dsa.get()) ? key->dsa : key->dsa_pub;

				Botan::PK_Verifier op(*dsa, std::string("EMSA3(SHA-1)"));
				err = (!op.verify_message(hash, hlen, (uint8_t*)ssh_string_data(sig->dsa_sig), ssh_string_len(sig->dsa_sig))) ? 1 : 0;
			}

            if (err) {
                ssh_set_error(session, SSH_FATAL, "Invalid DSA signature");

                return SSH_ERROR;
            }
            break;
        case SSH_KEYTYPE_RSA:
		case SSH_KEYTYPE_RSA1:
			{
				std::shared_ptr<Botan::RSA_PublicKey> rsa = (key->rsa.get()) ? key->rsa : key->rsa_pub;

				Botan::PK_Verifier op(*rsa, std::string("EMSA3(SHA-1)"));
				err = (!op.verify_message(hash, hlen, (uint8_t*)ssh_string_data(sig->rsa_sig), ssh_string_len(sig->rsa_sig))) ? 1 : 0;
			}

            if (err) {
                ssh_set_error(session, SSH_FATAL, "Invalid RSA signature");
                return SSH_ERROR;
            }
            break;
        case SSH_KEYTYPE_ED25519:
		err = pki_ed25519_verify(key, sig, hash, hlen);
		if (err != SSH_OK){
			ssh_set_error(session, SSH_FATAL, "ed25519 signature verification error");
			return SSH_ERROR;
		}
		break;
        case SSH_KEYTYPE_ECDSA:
        case SSH_KEYTYPE_UNKNOWN:
        default:
            ssh_set_error(session, SSH_FATAL, "Unknown public key type");
            return SSH_ERROR;
    }

    return SSH_OK;
}

ssh_signature pki_do_sign(const ssh_key privkey,
                          const unsigned char *hash,
                          size_t hlen) {
    ssh_signature sig;
	int err;

    sig = ssh_signature_new();
    if (sig == NULL) {
        return NULL;
    }
    sig->type = privkey->type;
    sig->type_c = privkey->type_c;
    switch (privkey->type) {
		case SSH_KEYTYPE_DSS:
			{
				Botan::AutoSeeded_RNG rng;
				Botan::PK_Signer op(*privkey->dsa, std::string("EMSA1(Raw)"));
				std::vector<uint8_t> signature = op.sign_message(hash, hlen, rng);

				sig->dsa_sig = ssh_string_new(signature.size());
				ssh_string_fill(sig->dsa_sig, &signature[0], signature.size());
			}
            break;
        case SSH_KEYTYPE_RSA:
		case SSH_KEYTYPE_RSA1:
			{
				Botan::AutoSeeded_RNG rng;
				Botan::PK_Signer op(*privkey->rsa, std::string("EMSA3(SHA-1)"));
				std::vector<uint8_t> signature = op.sign_message(hash, hlen, rng);

				sig->rsa_sig = ssh_string_new(signature.size());
				ssh_string_fill(sig->rsa_sig, &signature[0], signature.size());
			}
            break;
        case SSH_KEYTYPE_ED25519:
		err = pki_ed25519_sign(privkey, sig, hash, hlen);
		if (err != SSH_OK){
			ssh_signature_free(sig);
			return NULL;
		}
		break;
        case SSH_KEYTYPE_ECDSA:
        case SSH_KEYTYPE_UNKNOWN:
        default:
            ssh_signature_free(sig);
            return NULL;
    }

    return sig;
}

#ifdef WITH_SERVER
ssh_signature pki_do_sign_sessionid(const ssh_key key,
                                    const unsigned char *hash,
                                    size_t hlen)
{
    ssh_signature sig;

    sig = ssh_signature_new();
    if (sig == NULL) {
        return NULL;
    }
    sig->type = key->type;
    sig->type_c = key->type_c;

    switch(key->type) {
		case SSH_KEYTYPE_DSS:
		{
			Botan::AutoSeeded_RNG rng;
			Botan::PK_Signer op(*key->dsa, std::string("EMSA1(Raw)"));
			std::vector<uint8_t> signature = op.sign_message(hash, hlen, rng);

			sig->dsa_sig = ssh_string_new(signature.size());
			ssh_string_fill(sig->dsa_sig, &signature[0], signature.size());
		}
		break;
		case SSH_KEYTYPE_RSA:
		case SSH_KEYTYPE_RSA1:
		{
			Botan::AutoSeeded_RNG rng;
			//Botan::RSA_Private_Operation op(*key->rsa, rng);
			
			Botan::PK_Signer op(*key->rsa, std::string("EMSA3(SHA-1)"));
			std::vector<uint8_t> signature = op.sign_message(hash, hlen, rng);

			sig->rsa_sig = ssh_string_new(signature.size());
			ssh_string_fill(sig->rsa_sig, &signature[0], signature.size());
		}
		break;
        case SSH_KEYTYPE_ED25519:
		/* ED25519 handled in caller */
        case SSH_KEYTYPE_ECDSA:
        case SSH_KEYTYPE_UNKNOWN:
        default:
            return NULL;
    }

    return sig;
}
#endif /* WITH_SERVER */

#endif /* HAVE_LIBGCRYPT */

/* vim: set ts=4 sw=4 et cindent: */
