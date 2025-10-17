#include "WolfsslModule.h"
#include <esp_task_wdt.h>

static const char *TAG = "WolfsslModule";
// ============================================================
// CORREÇÕES PARA WolfsslModule.cpp
// ============================================================
// Substitua as funções init(), gen_keys(), sign() e verify()
WolfsslModule::WolfsslModule(CryptoApiCommons &commons) : commons(commons) {}

int WolfsslModule::init(Algorithms algorithm, Hashes hash, size_t length_of_shake256)
{
  commons.set_chosen_algorithm(algorithm);
  commons.set_chosen_hash(hash);
  commons.set_shake256_hash_length(length_of_shake256);

  wolfCrypt_Init();

  memset(&rng, 0, sizeof(WC_RNG));
  memset(&wolf_ed25519_key, 0, sizeof(ed25519_key));
  memset(&wolf_rsa_key, 0, sizeof(RsaKey));
  memset(&wolf_ecc_key, 0, sizeof(ecc_key));
  memset(&wolf_ed448_key, 0, sizeof(ed448_key));

  int ret = wc_InitRng(&rng);
  if (ret != 0)
  {
    commons.log_error("wc_InitRng");
    return ret;
  }

  // CORREÇÃO: Remover medição de memória do init
  // Não medir memória aqui - será medido no main
  unsigned long start_time = esp_timer_get_time() / 1000;

  switch (commons.get_chosen_algorithm())
  {
  case EDDSA_25519:
    ret = wc_ed25519_init(&wolf_ed25519_key);
    if (ret != 0)
    {
      commons.log_error("wc_ed25519_init");
      return ret;
    }
    break;
  case RSA:
    ret = wc_InitRsaKey(&wolf_rsa_key, NULL);
    if (ret != 0)
    {
      commons.log_error("wc_InitRsaKey");
      return ret;
    }
    break;
  case ECDSA_BP256R1:
  case ECDSA_BP512R1:
  case ECDSA_SECP256R1:
  case ECDSA_SECP521R1:
    ret = wc_ecc_init(&wolf_ecc_key);
    if (ret != 0)
    {
      commons.log_error("wc_ecc_init");
      return ret;
    }
    break;
  case EDDSA_448:
    ret = wc_ed448_init(&wolf_ed448_key);
    if (ret != 0)
    {
      commons.log_error("wc_ed448_init");
      return ret;
    }
    break;
  }

  unsigned long end_time = esp_timer_get_time() / 1000;
  // Apenas log de tempo, não memória
  ESP_LOGI(TAG, "wolfssl_init completed in %lu ms", end_time - start_time);

  commons.log_success("init");
  return 0;
}

int WolfsslModule::gen_keys()
{
  int ret;
  int curve_id = get_ecc_curve_id();
  int key_size = get_key_size(curve_id);

  // CORREÇÃO: Remover medição de memória
  unsigned long start_time = esp_timer_get_time() / 1000;

  switch (commons.get_chosen_algorithm())
  {
  case EDDSA_25519:
    ret = wc_ed25519_make_key(&rng, key_size, &wolf_ed25519_key);
    if (ret != 0)
    {
      commons.log_error("wc_ed25519_make_key");
      return ret;
    }
    break;
  case EDDSA_448:
    ret = wc_ed448_make_key(&rng, key_size, &wolf_ed448_key);
    if (ret != 0)
    {
      commons.log_error("wc_ed448_make_key");
      return ret;
    }
    break;
  case ECDSA_BP256R1:
  case ECDSA_BP512R1:
  case ECDSA_SECP256R1:
  case ECDSA_SECP521R1:
  default:
    ret = wc_ecc_make_key_ex(&rng, key_size, &wolf_ecc_key, curve_id);
    if (ret != 0)
    {
      commons.log_error("wc_ecc_make_key_ex");
      return ret;
    }
    break;
  }

  unsigned long end_time = esp_timer_get_time() / 1000;
  ESP_LOGI(TAG, "wolfssl_gen_keys completed in %lu ms", end_time - start_time);

  commons.log_success("gen_keys");
  return 0;
}

int WolfsslModule::gen_rsa_keys(unsigned int rsa_key_size, int rsa_exponent)
{
  // CORREÇÃO: Remover medição de memória
  unsigned long start_time = esp_timer_get_time() / 1000;

  this->rsa_key_size = rsa_key_size;

  int ret = wc_MakeRsaKey(&wolf_rsa_key, rsa_key_size, rsa_exponent, &rng);
  if (ret != 0)
  {
    commons.log_error("wc_MakeRsaKey");
    return ret;
  }

  unsigned long end_time = esp_timer_get_time() / 1000;
  ESP_LOGI(TAG, "wolfssl_gen_rsa_keys completed in %lu ms", end_time - start_time);

  commons.log_success("gen_keys");
  return 0;
}

int WolfsslModule::sign(const unsigned char *message, size_t message_length, 
                        unsigned char *signature, size_t *signature_length)
{
  int ret;
  byte *hash = NULL;
  size_t hash_length = 0;
  bool needs_hash = true;

  if (commons.get_chosen_algorithm() == EDDSA_25519 ||
      commons.get_chosen_algorithm() == EDDSA_448) {
    needs_hash = false;
  }

  // CORREÇÃO: Remover medição de memória do hash
  if (needs_hash) {
    hash_length = commons.get_hash_length();
    hash = (byte *)malloc(hash_length * sizeof(byte));

    ret = hash_message(message, message_length, hash);
    if (ret != 0)
    {
      ESP_LOGE(TAG, "hash_message failed: %d", ret);
      commons.log_error("hash_message");
      free(hash);
      return ret;
    }
  }

  // CORREÇÃO: Remover medição de memória
  unsigned long start_time = esp_timer_get_time() / 1000;

  switch (commons.get_chosen_algorithm())
  {
  case EDDSA_25519:
    ret = wc_ed25519_sign_msg(message, message_length, signature, signature_length, &wolf_ed25519_key);
    if (ret != 0)
    {
      commons.log_error("wc_ed25519_sign_msg");
      return ret;
    }
    break;
  case RSA:
    ret = wc_RsaSSL_Sign(hash, hash_length, signature, *signature_length, &wolf_rsa_key, &rng);
    if (ret < 0)
    {
      commons.log_error("wc_RsaSSL_Sign");
      free(hash);
      return ret;
    }
    *signature_length = ret;
    break;
  case ECDSA_BP256R1:
  case ECDSA_BP512R1:
  case ECDSA_SECP256R1:
  case ECDSA_SECP521R1:
    ret = wc_ecc_sign_hash(hash, hash_length, signature, signature_length, &rng, &wolf_ecc_key);
    if (ret != 0)
    {
      ESP_LOGE(TAG, "wc_ecc_sign_hash failed: %d", ret);
      commons.log_error("wc_ecc_sign_hash");
      free(hash);
      return ret;
    }
    break;
  case EDDSA_448:
    ret = wc_ed448_sign_msg(message, message_length, signature, signature_length, &wolf_ed448_key, NULL, 0);
    if (ret != 0)
    {
      commons.log_error("wc_ed448_sign_msg");
      return ret;
    }
    break;
  }

  unsigned long end_time = esp_timer_get_time() / 1000;
  // Apenas log de tempo
  // ESP_LOGD(TAG, "wolfssl_sign: %lu ms", end_time - start_time);

  if (needs_hash && hash != NULL) {
    free(hash);
  }

  commons.log_success("sign");
  return 0;
}

int WolfsslModule::verify(const unsigned char *message, size_t message_length, 
                          unsigned char *signature, size_t signature_length)
{
  int ret;
  byte *hash = NULL;
  size_t hash_length = 0;
  bool needs_hash = true;

  if (commons.get_chosen_algorithm() == EDDSA_25519 ||
      commons.get_chosen_algorithm() == EDDSA_448) {
    needs_hash = false;
  }

  // CORREÇÃO: Remover medição de memória
  if (needs_hash) {
    hash_length = commons.get_hash_length();
    hash = (byte *)malloc(hash_length * sizeof(byte));

    ret = hash_message(message, message_length, hash);
    if (ret != 0)
    {
      ESP_LOGE(TAG, "hash_message failed: %d", ret);
      commons.log_error("hash_message");
      free(hash);
      return ret;
    }
  }

  unsigned long start_time = esp_timer_get_time() / 1000;

  int verify_status = 0;
  switch (commons.get_chosen_algorithm())
  {
  case EDDSA_25519:
    ret = wc_ed25519_verify_msg(signature, signature_length, message, message_length,
                                 &verify_status, &wolf_ed25519_key);
    if (ret != 0)
    {
      ESP_LOGE(TAG, "wc_ed25519_verify_msg failed: %d", ret);
      commons.log_error("wc_ed25519_verify_msg");
      return ret;
    }
    break;
  case RSA:
    {
      byte *decrypted_signature = (byte *)malloc(hash_length * sizeof(byte));
      ret = wc_RsaSSL_Verify(signature, signature_length, decrypted_signature, hash_length, &wolf_rsa_key);
      if (ret < 0)
      {
        ESP_LOGE(TAG, "wc_RsaSSL_Verify failed: %d", ret);
        commons.log_error("wc_RsaSSL_Verify");
        free(hash);
        free(decrypted_signature);
        return ret;
      }
      verify_status = (memcmp(hash, decrypted_signature, hash_length) == 0) ? 1 : 0;
      free(decrypted_signature);
    }
    break;
  case ECDSA_BP256R1:
  case ECDSA_BP512R1:
  case ECDSA_SECP256R1:
  case ECDSA_SECP521R1:
    ret = wc_ecc_verify_hash(signature, signature_length, hash, hash_length,
                              &verify_status, &wolf_ecc_key);
    if (ret != 0)
    {
      ESP_LOGE(TAG, "wc_ecc_verify_hash failed: %d", ret);
      commons.log_error("wc_ecc_verify_hash");
      free(hash);
      return ret;
    }
    break;
  case EDDSA_448:
    ret = wc_ed448_verify_msg(signature, signature_length, message, message_length,
                               &verify_status, &wolf_ed448_key, NULL, 0);
    if (ret != 0)
    {
      ESP_LOGE(TAG, "wc_ed448_verify_msg failed: %d", ret);
      commons.log_error("wc_ed448_verify_msg");
      return ret;
    }
    break;
  }

  if (verify_status != 1)
  {
    ESP_LOGE(TAG, "Signature verification failed (status: %d)", verify_status);
  }

  unsigned long end_time = esp_timer_get_time() / 1000;
  // ESP_LOGD(TAG, "wolfssl_verify: %lu ms", end_time - start_time);

  if (needs_hash && hash != NULL) {
    free(hash);
  }

  commons.log_success("verify");
  return 0;
}
void WolfsslModule::close()
{
  wolfCrypt_Cleanup();
  wc_FreeRng(&rng);
  if (commons.get_chosen_algorithm() == Algorithms::RSA)
  {
    wc_FreeRsaKey(&wolf_rsa_key);
  }
  else if (commons.get_chosen_algorithm() == Algorithms::EDDSA_25519)
  {
    wc_ed25519_free(&wolf_ed25519_key);
  }
  else if (commons.get_chosen_algorithm() == Algorithms::EDDSA_448)
  {
    wc_ed448_free(&wolf_ed448_key);
  }
  else
  {
    wc_ecc_free(&wolf_ecc_key);
  }

  ESP_LOGI(TAG, "> wolfssl closed.");
}

int WolfsslModule::get_key_size(int curve_id)
{
  if (commons.get_chosen_algorithm() == Algorithms::EDDSA_25519)
  {
    return ED25519_KEY_SIZE;
  }
  else if (commons.get_chosen_algorithm() == Algorithms::EDDSA_448)
  {
    return ED448_KEY_SIZE;
  }
  else if (commons.get_chosen_algorithm() == Algorithms::RSA)
  {
    return rsa_key_size / 8;
  }
  else
  {
    return wc_ecc_get_curve_size_from_id(curve_id);
  }
}

int WolfsslModule::get_ecc_curve_id()
{
  if (commons.get_chosen_algorithm() == Algorithms::ECDSA_SECP256R1)
  {
    return ECC_SECP256R1;
  }
  else if (commons.get_chosen_algorithm() == Algorithms::ECDSA_SECP521R1)
  {
    return ECC_SECP521R1;
  }
  else if (commons.get_chosen_algorithm() == Algorithms::ECDSA_BP256R1)
  {
    return ECC_BRAINPOOLP256R1;
  }
  else if (commons.get_chosen_algorithm() == Algorithms::ECDSA_BP512R1)
  {
    return ECC_BRAINPOOLP512R1;
  }
  else
  {
    return ECC_SECP256R1; // Default
  }
}

size_t WolfsslModule::get_private_key_size()
{
  if (commons.get_chosen_algorithm() == Algorithms::EDDSA_25519)
  {
    return ED25519_KEY_SIZE;
  }
  else if (commons.get_chosen_algorithm() == Algorithms::EDDSA_448)
  {
    return ED448_KEY_SIZE;
  }
  else if (commons.get_chosen_algorithm() == Algorithms::RSA)
  {
    return rsa_key_size / 8;
  }
  else
  {
    return wc_ecc_size(&wolf_ecc_key);
  }
}

int WolfsslModule::hash_message(const unsigned char *message, size_t message_len, unsigned char *hash)
{
  switch (commons.get_chosen_hash())
  {
  case Hashes::MY_SHA_256:
    return wc_Sha256Hash(message, message_len, hash);
  case Hashes::MY_SHA_512:
    return wc_Sha512Hash(message, message_len, hash);
  case Hashes::MY_SHA3_256:
    return wc_Sha3_256Hash(message, message_len, hash);
  case Hashes::MY_SHAKE_256:
    return wc_Shake256Hash(message, message_len, hash, commons.get_hash_length());
  default:
    return wc_Sha256Hash(message, message_len, hash);
  }
}

size_t WolfsslModule::get_public_key_size()
{
  return get_key_size(get_ecc_curve_id());
}

int WolfsslModule::get_signature_size()
{
  if (commons.get_chosen_algorithm() == EDDSA_25519)
  {
    return ED25519_SIG_SIZE;
  }
  else if (commons.get_chosen_algorithm() == EDDSA_448)
  {
    return ED448_SIG_SIZE;
  }
  else if (commons.get_chosen_algorithm() == RSA)
  {
    return rsa_key_size / 8;
  }
  
  // Para ECDSA, calcular tamanho adequado baseado na curva
  if (commons.get_chosen_algorithm() >= ECDSA_BP256R1 && 
      commons.get_chosen_algorithm() <= ECDSA_SECP521R1)
  {
    int curve_id = get_ecc_curve_id();
    int key_size = wc_ecc_get_curve_size_from_id(curve_id);
    // Assinatura ECDSA em formato DER: aproximadamente 2*key_size + 9 bytes
    return (2 * key_size) + 9;
  }

  return ECC_MAX_SIG_SIZE;
}

int WolfsslModule::get_public_key_pem(unsigned char *public_key_pem)
{
  int ret;
  size_t der_pub_key_size = get_public_key_der_size();
  unsigned char *der_pub_key = (unsigned char *)malloc(der_pub_key_size * sizeof(unsigned char));
  CertType cert_type;

  switch (commons.get_chosen_algorithm())
  {
  case EDDSA_25519:
    ret = wc_ed25519_export_public(&wolf_ed25519_key, der_pub_key, &der_pub_key_size);
    cert_type = PUBLICKEY_TYPE;
    if (ret != 0)
    {
      commons.log_error("wc_ed25519_export_public");
      free(der_pub_key);
      return ret;
    }
    break;
  case EDDSA_448:
    ret = wc_ed448_export_public(&wolf_ed448_key, der_pub_key, &der_pub_key_size);
    cert_type = PUBLICKEY_TYPE;
    if (ret != 0)
    {
      commons.log_error("wc_ed448_export_public");
      free(der_pub_key);
      return ret;
    }
    break;
  case RSA:
    ret = wc_RsaKeyToPublicDer(&wolf_rsa_key, der_pub_key, der_pub_key_size);
    cert_type = RSA_PUBLICKEY_TYPE;
    if (ret < 0)
    {
      commons.log_error("wc_RsaKeyToPublicDer");
      free(der_pub_key);
      return ret;
    }
    else
    {
      der_pub_key_size = ret;
    }
    break;
  case ECDSA_BP256R1:
  case ECDSA_BP512R1:
  case ECDSA_SECP256R1:
  case ECDSA_SECP521R1:
  default:
    ret = wc_EccPublicKeyToDer(&wolf_ecc_key, der_pub_key, der_pub_key_size, 0);
    cert_type = ECC_PUBLICKEY_TYPE;
    if (ret < 0)
    {
      commons.log_error("wc_EccPublicKeyToDer");
      free(der_pub_key);
      return ret;
    }
    else
    {
      der_pub_key_size = ret;
    }
    break;
  }

  ret = wc_DerToPem(der_pub_key, der_pub_key_size, public_key_pem, get_public_key_pem_size(), cert_type);
  if (ret < 0)
  {
    commons.log_error("wc_DerToPem");
    free(der_pub_key);
    return ret;
  }

  ESP_LOGE(TAG, "public key pem size: %d", ret);
  ESP_LOGE(TAG, "public key der size: %lu", (unsigned long)der_pub_key_size);

  public_key_pem[get_public_key_pem_size()] = '\0';
  
  free(der_pub_key);
  return 0;
}

size_t WolfsslModule::get_public_key_pem_size()
{
  if (commons.get_chosen_algorithm() == Algorithms::EDDSA_25519)
  {
    return 97;
  }
  else if (commons.get_chosen_algorithm() == Algorithms::EDDSA_448)
  {
    return 130;
  }
  else if (commons.get_chosen_algorithm() == Algorithms::ECDSA_SECP256R1 || commons.get_chosen_algorithm() == Algorithms::ECDSA_BP256R1)
  {
    return 142;
  }
  else if (commons.get_chosen_algorithm() == Algorithms::ECDSA_SECP521R1)
  {
    return 235;
  }
  else if (commons.get_chosen_algorithm() == Algorithms::ECDSA_BP512R1)
  {
    return 227;
  }
  else if (rsa_key_size == 2048)
  {
    return 459;
  }
  else
  {
    return 808;
  }
}

size_t WolfsslModule::get_private_key_pem_size()
{
  if (commons.get_chosen_algorithm() == Algorithms::EDDSA_25519)
  {
    return 152;
  }
  else if (commons.get_chosen_algorithm() == Algorithms::EDDSA_448)
  {
    return 217;
  }
  else if (commons.get_chosen_algorithm() == Algorithms::ECDSA_SECP256R1 || commons.get_chosen_algorithm() == Algorithms::ECDSA_BP256R1)
  {
    return 227;
  }
  else if (commons.get_chosen_algorithm() == Algorithms::ECDSA_SECP521R1)
  {
    return 365;
  }
  else if (commons.get_chosen_algorithm() == Algorithms::ECDSA_BP512R1)
  {
    return 361;
  }
  else if (rsa_key_size == 2048)
  {
    return 1679;
  }
  else
  {
    return 3260;
  }
}

size_t WolfsslModule::get_public_key_der_size()
{
  if (commons.get_chosen_algorithm() == Algorithms::EDDSA_25519)
  {
    return 32;
  }
  else if (commons.get_chosen_algorithm() == Algorithms::EDDSA_448)
  {
    return 57;
  }
  else if (commons.get_chosen_algorithm() == Algorithms::ECDSA_SECP256R1 || commons.get_chosen_algorithm() == Algorithms::ECDSA_BP256R1)
  {
    return 65;
  }
  else if (commons.get_chosen_algorithm() == Algorithms::ECDSA_SECP521R1)
  {
    return 133;
  }
  else if (commons.get_chosen_algorithm() == Algorithms::ECDSA_BP512R1)
  {
    return 129;
  }
  else if (rsa_key_size == 2048)
  {
    return 294;
  }
  else
  {
    return 550;
  }
}

size_t WolfsslModule::get_private_key_der_size()
{
  if (commons.get_chosen_algorithm() == Algorithms::EDDSA_25519)
  {
    return 64;
  }
  else if (commons.get_chosen_algorithm() == Algorithms::EDDSA_448)
  {
    return 114;
  }
  else if (commons.get_chosen_algorithm() == Algorithms::ECDSA_SECP256R1)
  {
    return 121;
  }
  else if (commons.get_chosen_algorithm() == Algorithms::ECDSA_BP256R1)
  {
    return 122;
  }
  else if (commons.get_chosen_algorithm() == Algorithms::ECDSA_SECP521R1)
  {
    return 223;
  }
  else if (commons.get_chosen_algorithm() == Algorithms::ECDSA_BP512R1)
  {
    return 221;
  }
  else if (rsa_key_size == 2048)
  {
    return 1194;
  }
  else
  {
    return 2400;
  }
}

int WolfsslModule::get_private_key_pem(unsigned char *private_key_pem)
{
  int ret;
  size_t der_priv_key_size = get_private_key_der_size();
  unsigned char *der_priv_key = (unsigned char *)malloc(der_priv_key_size * sizeof(unsigned char));
  CertType cert_type;

  switch (commons.get_chosen_algorithm())
  {
  case EDDSA_25519:
    ret = wc_ed25519_export_private(&wolf_ed25519_key, der_priv_key, &der_priv_key_size);
    cert_type = PRIVATEKEY_TYPE;
    if (ret != 0)
    {
      commons.log_error("wc_ed25519_export_private");
      free(der_priv_key);
      return ret;
    }
    break;
  case EDDSA_448:
    ret = wc_ed448_export_private(&wolf_ed448_key, der_priv_key, &der_priv_key_size);
    cert_type = PRIVATEKEY_TYPE;
    if (ret != 0)
    {
      commons.log_error("wc_ed448_export_private");
      free(der_priv_key);
      return ret;
    }
    break;
  case RSA:
    ret = wc_RsaKeyToDer(&wolf_rsa_key, der_priv_key, der_priv_key_size);
    cert_type = CertType::RSA_TYPE;
    if (ret < 0)
    {
      commons.log_error("wc_RsaKeyToDer");
      free(der_priv_key);
      return ret;
    }
    else
    {
      der_priv_key_size = ret;
    }
    break;
  case ECDSA_BP256R1:
  case ECDSA_BP512R1:
  case ECDSA_SECP256R1:
  case ECDSA_SECP521R1:
  default:
    ret = wc_EccKeyToDer(&wolf_ecc_key, der_priv_key, der_priv_key_size);
    cert_type = ECC_PRIVATEKEY_TYPE;
    if (ret < 0)
    {
      commons.log_error("wc_EccKeyToDer");
      free(der_priv_key);
      return ret;
    }
    else
    {
      der_priv_key_size = ret;
    }
    break;
  }

  ret = wc_DerToPem(der_priv_key, der_priv_key_size, private_key_pem, get_private_key_pem_size(), cert_type);

  ESP_LOGE(TAG, "private key pem size: %d", ret);
  ESP_LOGE(TAG, "private key der size: %lu", (unsigned long)der_priv_key_size);

  if (ret < 0)
  {
    commons.log_error("wc_DerToPem");
    free(der_priv_key);
    return ret;
  }

  private_key_pem[get_private_key_pem_size()] = '\0';
  
  free(der_priv_key);
  return 0;
}

void WolfsslModule::save_private_key(const char *file_path, unsigned char *private_key, size_t private_key_size)
{
  int ret = get_private_key_pem(private_key);
  if (ret == 0)
  {
    commons.write_file(file_path, private_key);
  }
  else
  {
    ESP_LOGE(TAG, "Failed to write private key to PEM format, wolfssl error code: %d", ret);
  }
}

void WolfsslModule::save_public_key(const char *file_path, unsigned char *public_key, size_t public_key_size)
{
  int ret = get_public_key_pem(public_key);
  if (ret == 0)
  {
    commons.write_file(file_path, public_key);
  }
  else
  {
    ESP_LOGE(TAG, "Failed to write public key to PEM format, wolfssl error code: %d", ret);
  }
}

void WolfsslModule::save_signature(const char *file_path, const unsigned char *signature, size_t sig_len)
{
  commons.write_binary_file(file_path, signature, sig_len);
}

void WolfsslModule::load_file(const char *file_path, unsigned char *buffer, size_t buffer_size)
{
  commons.read_file(file_path, buffer, buffer_size);
}