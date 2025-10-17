#ifndef WOLFSSL_MODULE
#define WOLFSSL_MODULE

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/ed448.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include "CryptoApiCommons.h"
#include "ICryptoModule.h"

#define MY_ED25519_KEY_SIZE 32
#define MY_ED448_KEY_SIZE 57

class WolfsslModule : public ICryptoModule
{
public:
  WolfsslModule(CryptoApiCommons &commons);

  int init(Algorithms algorithm, Hashes hash, size_t length_of_shake256);
  int get_signature_size();

  int gen_rsa_keys(unsigned int rsa_key_size, int rsa_exponent);
  int gen_keys();

  int sign(const unsigned char *message, size_t message_length, unsigned char *signature, size_t *signature_length);
  int verify(const unsigned char *message, size_t message_length, unsigned char *signature, size_t signature_length);
  void close();

  int hash_message(const unsigned char *message, size_t message_length, unsigned char *hash);

  size_t get_public_key_size();
  size_t get_public_key_pem_size();
  int get_public_key_pem(unsigned char *public_key_pem);

  size_t get_private_key_size();
  size_t get_private_key_pem_size();
  int get_private_key_pem(unsigned char *private_key_pem);

  void save_private_key(const char *file_path, unsigned char *private_key, size_t private_key_size);
  void save_public_key(const char *file_path, unsigned char *public_key, size_t public_key_size);
  void save_signature(const char *file_path, const unsigned char *signature, size_t sig_len);

  void load_file(const char *file_path, unsigned char *buffer, size_t buffer_size);

private:
  CryptoApiCommons &commons;
  WC_RNG rng;
  ed25519_key wolf_ed25519_key;
  RsaKey wolf_rsa_key;
  ecc_key wolf_ecc_key;
  ed448_key wolf_ed448_key;
  unsigned int rsa_key_size;

  int get_key_size(int curve_id);
  int get_ecc_curve_id();
  size_t get_public_key_der_size();
  size_t get_private_key_der_size();
};

#endif