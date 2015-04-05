#ifndef BOTAN_H_
#define BOTAN_H_

#ifdef HAVE_BOTAN

// wincrypt.h fix
#ifdef X942_DH_PARAMETERS
#undef X942_DH_PARAMETERS
#endif

#include <botan/auto_rng.h>
#include <botan/hash.h>
#include <botan/hmac.h>
#include <botan/pow_mod.h>

#include <botan/rsa.h>
#include <botan/dsa.h>

#include <botan/block_cipher.h>
#include <botan/cipher_mode.h>
#include <botan/stream_cipher.h>

#include <memory>

typedef std::shared_ptr<Botan::HashFunction> SHACTX;
typedef std::shared_ptr<Botan::HashFunction> SHA256CTX;
typedef std::shared_ptr<Botan::HashFunction> SHA384CTX;
typedef std::shared_ptr<Botan::HashFunction> SHA512CTX;
typedef std::shared_ptr<Botan::HashFunction> MD5CTX;
typedef std::shared_ptr<Botan::HMAC> HMACCTX;

struct ssh_cipher_key_struct
{
	Botan::BlockCipher* algorithm;

	std::unique_ptr<Botan::Cipher_Mode> decrypt;
	std::unique_ptr<Botan::Cipher_Mode> encrypt;

	std::unique_ptr<Botan::StreamCipher> ctr;
};

typedef void *EVPCTX;
#define SHA_DIGEST_LENGTH 20
#define SHA_DIGEST_LEN SHA_DIGEST_LENGTH
#define MD5_DIGEST_LEN 16
#define SHA256_DIGEST_LENGTH 32
#define SHA256_DIGEST_LEN SHA256_DIGEST_LENGTH
#define SHA384_DIGEST_LENGTH 48
#define SHA384_DIGEST_LEN SHA384_DIGEST_LENGTH
#define SHA512_DIGEST_LENGTH 64
#define SHA512_DIGEST_LEN SHA512_DIGEST_LENGTH

#ifndef EVP_MAX_MD_SIZE
#define EVP_MAX_MD_SIZE 64
#endif

#define EVP_DIGEST_LEN EVP_MAX_MD_SIZE

typedef Botan::BigInt bignum;

#define bignum_new() Botan::BigInt()
#define bignum_free(x) 
#define bignum_set_word(bn, n) bn = Botan::BigInt(n)
#define bignum_bin2bn(bn, datalen, data) bn.binary_decode(data, datalen)
#define bignum_dec2bn(num, data) *data = Botan::BigInt(std::string(num))
#define bignum_bn2hex(num,data) strcpy(data, "dmy")
#define bignum_rand(num,bits) do { Botan::AutoSeeded_RNG r; num.randomize(r, bits); } while(0)
#define bignum_mod_exp(dest,generator,exp,modulo) do { Botan::Power_Mod m; m.set_modulus(modulo); m.set_base(generator); m.set_exponent(exp); dest = m.execute(); } while(0)
#define bignum_num_bits(num) num.bits()
#define bignum_num_bytes(num) num.bytes()
#define bignum_is_bit_set(num, bit) num.get_bit(bit)
#define bignum_bn2bin(num, datalen, data) num.binary_encode(data)
#define bignum_cmp(num1, num2) num1.cmp(num2)
#endif

#endif