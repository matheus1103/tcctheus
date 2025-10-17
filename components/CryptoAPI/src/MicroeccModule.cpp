#include "MicroeccModule.h"
#include "MbedtlsModule.h"
#include "esp_random.h"
#include <string.h>
#include <esp_task_wdt.h>

static const char *TAG = "MicroeccModule";

MicroeccModule::MicroeccModule(CryptoApiCommons &commons, MbedtlsModule &mbedtls_module) : commons(commons), mbedtls_module(mbedtls_module)
{
}

const struct uECC_Curve_t *curve = uECC_secp256r1();

int MicroeccModule::init(Algorithms _, Hashes hash, size_t __)
{
  // CORREÇÃO: Remover medição de memória
  unsigned long start_time = esp_timer_get_time() / 1000;

  commons.set_chosen_hash(hash);

  unsigned int seed = esp_random();
  srandom(seed);
  uECC_set_rng(&MicroeccModule::rng_function);

  unsigned long end_time = esp_timer_get_time() / 1000;
  ESP_LOGI(TAG, "microecc_init completed in %lu ms", end_time - start_time);

  commons.log_success("init");
  return 0;
}
int MicroeccModule::gen_rsa_keys(unsigned int rsa_key_size, int rsa_exponent)
{
  return -1;
}

int MicroeccModule::get_signature_size()
{
  return 64;
}

int MicroeccModule::gen_keys()
{
  // CORREÇÃO: Remover medição de memória
  unsigned long start_time = esp_timer_get_time() / 1000;

  size_t private_key_size = MY_ECC_256_PRIVATE_KEY_SIZE;
  size_t public_key_size = MY_ECC_256_PUBLIC_KEY_SIZE;

  private_key = (unsigned char *)malloc(private_key_size * sizeof(unsigned char));
  public_key = (unsigned char *)malloc(public_key_size * sizeof(unsigned char));

  int ret = uECC_make_key(public_key, private_key, uECC_secp256r1());

  if (ret == 0)
  {
    commons.log_error("uECC_make_key");
    return -1;
  }

  unsigned long end_time = esp_timer_get_time() / 1000;
  ESP_LOGI(TAG, "microecc_gen_keys completed in %lu ms", end_time - start_time);

  commons.log_success("gen_keys");
  return 0;
}

int MicroeccModule::get_public_key_pem(unsigned char *public_key_pem)
{
  return public_key_to_pem_format(public_key_pem);
}

int MicroeccModule::public_key_to_pem_format(unsigned char *public_key_buffer)
{
  size_t base64_len = 89;
  unsigned char *base64_output = (unsigned char *)malloc(base64_len * sizeof(unsigned char));

  size_t olen = 0;
  int ret = mbedtls_module.base64_encode(base64_output, base64_len, &olen, this->public_key, get_private_key_size());
  if (ret != 0)
  {
    ESP_LOGE(TAG, "Failed to encode public key to Base64 (error %d)", ret);
    return ret;
  }

  std::string pem_content = "-----BEGIN PUBLIC KEY-----\n";
  pem_content.append(reinterpret_cast<char *>(base64_output), olen);

  // Insert line breaks every 64 characters
  size_t line_length = 64;
  for (size_t i = line_length; i < pem_content.size(); i += line_length + 1)
  {
    pem_content.insert(i, "\n");
  }

  pem_content += "\n-----END PUBLIC KEY-----\n";

  memcpy(public_key_buffer, pem_content.c_str(), pem_content.size() + 1); // +1 to include null terminator
  return 0;
}

size_t MicroeccModule::get_public_key_pem_size()
{
  return 142;
}

int MicroeccModule::private_key_to_pem_format(unsigned char *private_key_buffer)
{
  size_t base64_len = 89; // Adjust size based on expected private key size
  unsigned char *base64_output = (unsigned char *)malloc(base64_len * sizeof(unsigned char));

  size_t olen = 0;
  int ret = mbedtls_module.base64_encode(base64_output, base64_len, &olen, this->private_key, get_private_key_size());
  if (ret != 0)
  {
    ESP_LOGE(TAG, "Failed to encode private key to Base64 (error %d)", ret);
    return ret;
  }

  std::string pem_content = "-----BEGIN PRIVATE KEY-----\n";
  pem_content.append(reinterpret_cast<char *>(base64_output), olen);

  // Insert line breaks every 64 characters
  size_t line_length = 64;
  for (size_t i = line_length; i < pem_content.size(); i += line_length + 1)
  {
    pem_content.insert(i, "\n");
  }

  pem_content += "\n-----END PRIVATE KEY-----\n";

  // Copy PEM content to the output buffer
  memcpy(private_key_buffer, pem_content.c_str(), pem_content.size() + 1); // +1 to include null terminator

  // free(base64_output);
  return 0;
}

int MicroeccModule::sign(const unsigned char *message, size_t message_length, 
                         unsigned char *signature, size_t *_)
{
  // CORREÇÃO: Remover medição de memória
  size_t hash_length = commons.get_hash_length();
  unsigned char *hash = (unsigned char *)malloc(hash_length * sizeof(unsigned char));

  int ret = mbedtls_module.hash_message(message, message_length, hash);
  if (ret != 0)
  {
    commons.log_error("hash_message");
    free(hash);
    return ret;
  }

  unsigned long start_time = esp_timer_get_time() / 1000;

  ret = uECC_sign(private_key, hash, hash_length, signature, uECC_secp256r1());

  if (ret == 0)
  {
    commons.log_error("uECC_sign");
    free(hash);
    return -1;
  }

  unsigned long end_time = esp_timer_get_time() / 1000;
  // ESP_LOGD(TAG, "microecc_sign: %lu ms", end_time - start_time);

  free(hash);

  commons.log_success("sign");
  return 0;
}
int MicroeccModule::verify(const unsigned char *message, size_t message_length, 
                           unsigned char *signature, size_t __)
{
  // CORREÇÃO: Remover medição de memória
  size_t hash_length = commons.get_hash_length();
  unsigned char *hash = (unsigned char *)malloc(hash_length * sizeof(unsigned char));

  int ret = mbedtls_module.hash_message(message, message_length, hash);
  if (ret != 0)
  {
    commons.log_error("hash_message");
    free(hash);
    return ret;
  }

  unsigned long start_time = esp_timer_get_time() / 1000;

  ret = uECC_verify(public_key, hash, hash_length, signature, uECC_secp256r1());

  if (ret != 1)
  {
    commons.log_error("uECC_verify");
    free(hash);
    return -1;
  }

  unsigned long end_time = esp_timer_get_time() / 1000;
  // ESP_LOGD(TAG, "microecc_verify: %lu ms", end_time - start_time);

  free(hash);

  commons.log_success("verify");
  return 0;
}
void MicroeccModule::close()
{
  free(private_key);
  free(public_key);
  ESP_LOGI(TAG, "> microecc closed.");
}

size_t MicroeccModule::get_public_key_size()
{
  return MY_ECC_256_PUBLIC_KEY_SIZE;
}

size_t MicroeccModule::get_private_key_size()
{
  return MY_ECC_256_PRIVATE_KEY_SIZE;
}

int MicroeccModule::rng_function(unsigned char *dest, unsigned int size)
{
  // Fill dest with `size` random bytes
  while (size--)
  {
    *dest++ = (uint8_t)(esp_random() & 0xFF); // Mask to get a byte (0-255)
  }
  return 1; // Return 1 to indicate success
}

void MicroeccModule::save_private_key(const char *file_path, unsigned char *private_key, size_t _)
{
  int ret = private_key_to_pem_format(private_key);
  if (ret == 0)
  {
    commons.write_file(file_path, private_key);
  }
  else
  {
    ESP_LOGE(TAG, "Failed to save private key in PEM format, error code: %d", ret);
  }
}

void MicroeccModule::save_public_key(const char *file_path, unsigned char *public_key, size_t _)
{
  int ret = public_key_to_pem_format(public_key);
  if (ret == 0)
  {
    commons.write_file(file_path, public_key);
  }
  else
  {
    ESP_LOGE(TAG, "Failed to save public key in PEM format, error code: %d", ret);
  }
}

void MicroeccModule::save_signature(const char *file_path, const unsigned char *signature, size_t sig_len)
{
  commons.write_binary_file(file_path, signature, sig_len);
}

void MicroeccModule::load_file(const char *file_path, unsigned char *buffer, size_t buffer_size)
{
  commons.read_file(file_path, buffer, buffer_size);
}