// ============================================================
// CORREÇÃO COMPLETA - main.cpp (CryptoTest)
// Medição correta de memória para ESP32C6
// ============================================================
#include <stdio.h>
#include "CryptoAPI.h"
#include "esp_system.h"
#include <esp_log.h>
#include <esp_task_wdt.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <esp_timer.h>
#include <esp_heap_caps.h>
#include <string.h>
#include "../experiments/test_strings_exact.h"
#include <driver/gpio.h>
#include <cmath>

static const char *TAG = "CryptoTest";

#define MY_RSA_KEY_SIZE 2048
#define MY_RSA_EXPONENT 65537
#define NUM_KEY_GENERATIONS 10
#define NUM_SIGN_TESTS 10
#define NUM_VERIFY_TESTS 10

CryptoAPI crypto_api;

// ============================================================
// ESTRUTURA DE MEDIÇÃO CORRIGIDA
// ============================================================
typedef struct {
    size_t heap_before;
    size_t heap_after;
    size_t heap_delta;  // Alocação líquida nesta fase
    int64_t time_start;
    int64_t time_end;
} MemoryMeasurement;

// Função para iniciar medição
static inline void start_measurement(MemoryMeasurement* m) {
    heap_caps_check_integrity_all(true);
    vTaskDelay(pdMS_TO_TICKS(10));
    
    m->heap_before = heap_caps_get_free_size(MALLOC_CAP_8BIT);
    m->time_start = esp_timer_get_time();
}

// Função para finalizar medição
static inline void end_measurement(MemoryMeasurement* m) {
    m->time_end = esp_timer_get_time();
    
    heap_caps_check_integrity_all(true);
    vTaskDelay(pdMS_TO_TICKS(10));
    
    m->heap_after = heap_caps_get_free_size(MALLOC_CAP_8BIT);
    
    // Delta de heap (pode ser 0 se houver reutilização)
    m->heap_delta = (m->heap_before > m->heap_after) ? 
                    (m->heap_before - m->heap_after) : 0;
}

// ============================================================
// ESTRUTURAS DE MÉTRICAS
// ============================================================
typedef struct {
    // Métricas de geração de chaves
    struct {
        int64_t time_us;
        size_t heap_start;
        size_t heap_end;
        size_t heap_used;
    } key_generation[NUM_KEY_GENERATIONS];
    
    // Métricas detalhadas de memória
    struct {
        size_t heap_base;           // Heap antes de qualquer operação
        size_t heap_after_init;     // Heap após init
        size_t heap_after_keygen;   // Heap após gerar chave
        size_t heap_after_first_sign;   // Heap após primeira assinatura
        size_t heap_after_first_verify; // Heap após primeira verificação
        
        size_t memory_init;         // Heap alocado pelo init
        size_t memory_keygen;       // Heap alocado pela keygen
        size_t memory_first_sign;   // Heap alocado na primeira sign
        size_t memory_first_verify; // Heap alocado na primeira verify
        size_t memory_total;        // Total (heap persistente + stack pico)
        
        size_t heap_persistent;     // Heap que ficou alocado
        size_t stack_peak;          // Stack máximo usado
    } memory_profile;
    
    // Métricas para cada tamanho de string
    struct {
        size_t string_size;
        
        struct {
            int64_t time_us;
            size_t heap_used;
        } first_signature;
        
        struct {
            int64_t time_us;
            size_t heap_used;
        } first_verification;
        
        struct {
            int64_t time_us;
            size_t heap_used;
        } subsequent_signatures[NUM_SIGN_TESTS - 1];
        
        struct {
            int64_t time_us;
            size_t heap_used;
        } subsequent_verifications[NUM_VERIFY_TESTS - 1];
        
    } string_tests[NUM_TEST_STRINGS];
    
} TestMetrics;

typedef struct {
    Libraries lib;
    Algorithms algo;
    Hashes hash;
    int rsa_key_size;
    const char* name;
    TestMetrics metrics;
} TestConfig;

// ============================================================
// CONFIGURAÇÕES DE TESTE
// ============================================================
TestConfig test_configs[] = {

    // MBEDTLS
    // RSA básico
    //foi{Libraries::MBEDTLS_LIB, Algorithms::RSA, Hashes::MY_SHA_256, 2048, "MBEDTLS_RSA_2048_SHA256"},
    //foi {Libraries::MBEDTLS_LIB, Algorithms::RSA, Hashes::MY_SHA_512, 2048, "MBEDTLS_RSA_2048_SHA512"},
    //foi {Libraries::MBEDTLS_LIB, Algorithms::RSA, Hashes::MY_SHA_256, 4096, "MBEDTLS_RSA_4096_SHA256"},
//     {Libraries::MBEDTLS_LIB, Algorithms::RSA, Hashes::MY_SHA_512, 4096, "MBEDTLS_RSA_4096_SHA512"},

//    // ============ ECDSA P-256 (secp256r1) ============
//     {Libraries::MBEDTLS_LIB, Algorithms::ECDSA_SECP256R1, Hashes::MY_SHA_256, 0, "MBEDTLS_ECDSA_P256_SHA256"},
//     {Libraries::MBEDTLS_LIB, Algorithms::ECDSA_SECP256R1, Hashes::MY_SHA_512, 0, "MBEDTLS_ECDSA_P256_SHA512"},
    
//     // // ============ ECDSA P-521 (secp521r1) ============
//     {Libraries::MBEDTLS_LIB, Algorithms::ECDSA_SECP521R1, Hashes::MY_SHA_256, 0, "MBEDTLS_ECDSA_P521_SHA256"},
//     {Libraries::MBEDTLS_LIB, Algorithms::ECDSA_SECP521R1, Hashes::MY_SHA_512, 0, "MBEDTLS_ECDSA_P521_SHA512"},
    
//     // // ============ BRAINPOOL CURVES ============
//     {Libraries::MBEDTLS_LIB, Algorithms::ECDSA_BP256R1, Hashes::MY_SHA_256, 0, "MBEDTLS_ECDSA_BP256_SHA256"},
//     {Libraries::MBEDTLS_LIB, Algorithms::ECDSA_BP256R1, Hashes::MY_SHA_512, 0, "MBEDTLS_ECDSA_BP256_SHA512"},
//     {Libraries::MBEDTLS_LIB, Algorithms::ECDSA_BP512R1, Hashes::MY_SHA_256, 0, "MBEDTLS_ECDSA_BP512_SHA256"},
//     {Libraries::MBEDTLS_LIB, Algorithms::ECDSA_BP512R1, Hashes::MY_SHA_512, 0, "MBEDTLS_ECDSA_BP512_SHA512"},

    // WOLFSSL
    // RSA básico
    //{Libraries::WOLFSSL_LIB, Algorithms::RSA, Hashes::MY_SHA_256, 2048, "WOLFSSL_LIB_RSA_2048_SHA256"},
    //{Libraries::WOLFSSL_LIB, Algorithms::RSA, Hashes::MY_SHA_512, 2048, "WOLFSSL_LIB_RSA_2048_SHA512"},

   // ============ ECDSA P-256 (secp256r1) ============
    //{Libraries::WOLFSSL_LIB, Algorithms::ECDSA_SECP256R1, Hashes::MY_SHA_256, 0, "WOLFSSL_LIB_ECDSA_P256_SHA256"},
    //foi {Libraries::WOLFSSL_LIB, Algorithms::ECDSA_SECP256R1, Hashes::MY_SHA_512, 0, "WOLFSSL_LIB_ECDSA_P256_SHA512"},
    
    // // // ============ ECDSA P-521 (secp521r1) ============
    // {Libraries::WOLFSSL_LIB, Algorithms::ECDSA_SECP521R1, Hashes::MY_SHA_256, 0, "WOLFSSL_LIB_ECDSA_P521_SHA256"},
    // {Libraries::WOLFSSL_LIB, Algorithms::ECDSA_SECP521R1, Hashes::MY_SHA_512, 0, "WOLFSSL_LIB_ECDSA_P521_SHA512"},
    
    // // // ============ BRAINPOOL CURVES ============
    // {Libraries::WOLFSSL_LIB, Algorithms::ECDSA_BP256R1, Hashes::MY_SHA_256, 0, "WOLFSSL_LIB_ECDSA_BP256_SHA256"},
    // {Libraries::WOLFSSL_LIB, Algorithms::ECDSA_BP256R1, Hashes::MY_SHA_512, 0, "WOLFSSL_LIB_ECDSA_BP256_SHA512"},
    // {Libraries::WOLFSSL_LIB, Algorithms::ECDSA_BP512R1, Hashes::MY_SHA_256, 0, "WOLFSSL_LIB_ECDSA_BP512_SHA256"},
    // {Libraries::WOLFSSL_LIB, Algorithms::ECDSA_BP512R1, Hashes::MY_SHA_512, 0, "WOLFSSL_LIB_ECDSA_BP512_SHA512"},
    
    //{Libraries::WOLFSSL_LIB, Algorithms::EDDSA_25519, Hashes::MY_SHA_256, 0, "WOLFSSL_LIB_EDDSA_25519"},
    // {Libraries::WOLFSSL_LIB, Algorithms::EDDSA_25519, Hashes::MY_SHA_512, 0, "WOLFSSL_LIB_EDDSA_25519_SHA_512"},
    // {Libraries::WOLFSSL_LIB, Algorithms::EDDSA_448, Hashes::MY_SHA_256, 0, "WOLFSSL_LIB_EDDSA_448_SHA_256"},
    {Libraries::WOLFSSL_LIB, Algorithms::EDDSA_448, Hashes::MY_SHA_512, 0, "WOLFSSL_LIB_EDDSA_448_MY_SHA_512"},
    // MICROECC
    // ============ ECDSA P-256 (secp256r1) ============
    // {Libraries::MICROECC_LIB, Algorithms::ECDSA_SECP256R1 , Hashes::MY_SHA_256, 0, "MICROECC_LIB_ECDSA_P256_SHA256"},
    // {Libraries::MICROECC_LIB, Algorithms::ECDSA_SECP256R1 , Hashes::MY_SHA_512, 0, "MICROECC_LIB_ECDSA_P256_SHA512"},


};

// ============================================================
// FUNÇÃO AUXILIAR
// ============================================================
void heap_stabilize() {
    heap_caps_check_integrity_all(true);
    vTaskDelay(pdMS_TO_TICKS(50));
}

// ============================================================
// PERFIL DE MEMÓRIA CORRIGIDO
// ============================================================
void execute_memory_profiling(TestConfig* config) {
    TestMetrics* metrics = &config->metrics;
    memset(&metrics->memory_profile, 0, sizeof(metrics->memory_profile));
    MemoryMeasurement m;
    
    ESP_LOGI(TAG, "\n=== PROFILING DE MEMÓRIA: %s ===", config->name);
    
    // ========== BASELINE ==========
    heap_stabilize();
    size_t heap_baseline = heap_caps_get_free_size(MALLOC_CAP_8BIT);
    UBaseType_t stack_hwm_initial = uxTaskGetStackHighWaterMark(NULL);
    
    metrics->memory_profile.heap_base = heap_baseline;
    
    ESP_LOGI(TAG, "Baseline - Heap livre: %zu bytes, Stack HWM inicial: %u words (%u bytes)",
             heap_baseline, stack_hwm_initial, stack_hwm_initial * 4);
    
    // ========== INIT ==========
    start_measurement(&m);
    crypto_api.init(config->lib, config->algo, config->hash, 0);
    end_measurement(&m);
    
    metrics->memory_profile.heap_after_init = m.heap_after;
    metrics->memory_profile.memory_init = m.heap_delta;
    
    ESP_LOGI(TAG, "Init - Heap alocado: %zu bytes", m.heap_delta);
    
    // ========== KEYGEN ==========
    start_measurement(&m);
    if (config->algo == Algorithms::RSA) {
        crypto_api.gen_rsa_keys(config->rsa_key_size, MY_RSA_EXPONENT);
    } else {
        crypto_api.gen_keys();
    }
    end_measurement(&m);
    
    metrics->memory_profile.heap_after_keygen = m.heap_after;
    metrics->memory_profile.memory_keygen = m.heap_delta;
    
    ESP_LOGI(TAG, "KeyGen - Heap alocado: %zu bytes", m.heap_delta);
    
    // ========== PRIMEIRA ASSINATURA ==========
    static const unsigned char test_msg[] = "Memory profiling test";
    size_t test_msg_len = sizeof(test_msg) - 1;
    unsigned char test_signature[512];
    memset(test_signature, 0, sizeof(test_signature));
    size_t test_sig_len = sizeof(test_signature);
    
    start_measurement(&m);
    int ret = crypto_api.sign(test_msg, test_msg_len, test_signature, &test_sig_len);
    end_measurement(&m);
    
    if (ret != 0) {
        ESP_LOGE(TAG, "Sign failed: %d", ret);
    }
    
    metrics->memory_profile.heap_after_first_sign = m.heap_after;
    metrics->memory_profile.memory_first_sign = m.heap_delta;
    
    ESP_LOGI(TAG, "Sign - Heap alocado: %zu bytes", m.heap_delta);
    
    // ========== PRIMEIRA VERIFICAÇÃO ==========
    start_measurement(&m);
    ret = crypto_api.verify(test_msg, test_msg_len, test_signature, test_sig_len);
    end_measurement(&m);
    
    if (ret != 0) {
        ESP_LOGE(TAG, "Verify failed: %d", ret);
    }
    
    metrics->memory_profile.heap_after_first_verify = m.heap_after;
    metrics->memory_profile.memory_first_verify = m.heap_delta;
    
    ESP_LOGI(TAG, "Verify - Heap alocado: %zu bytes", m.heap_delta);
    
    // ========== CALCULAR FOOTPRINT TOTAL ==========
    size_t heap_final = heap_caps_get_free_size(MALLOC_CAP_8BIT);
    metrics->memory_profile.heap_persistent = (heap_baseline > heap_final) ? 
                                              (heap_baseline - heap_final) : 0;
    
    // Stack: diferença de HWM (menor HWM = mais stack usado)
    UBaseType_t stack_hwm_final = uxTaskGetStackHighWaterMark(NULL);
    metrics->memory_profile.stack_peak = (stack_hwm_initial > stack_hwm_final) ? 
                                         (stack_hwm_initial - stack_hwm_final) * 4 : 0;
    
    metrics->memory_profile.memory_total = metrics->memory_profile.heap_persistent + 
                                          metrics->memory_profile.stack_peak;
    
    // ========== RESULTADO FINAL ==========
    ESP_LOGI(TAG, "\n=== RESULTADO FINAL ===");
    ESP_LOGI(TAG, "FOOTPRINT DE MEMÓRIA:");
    ESP_LOGI(TAG, "  Heap persistente:  %zu bytes", metrics->memory_profile.heap_persistent);
    ESP_LOGI(TAG, "  Stack pico usado:  %zu bytes", metrics->memory_profile.stack_peak);
    ESP_LOGI(TAG, "  TOTAL:             %zu bytes", metrics->memory_profile.memory_total);
    ESP_LOGI(TAG, "\nDETALHAMENTO POR FASE (heap delta):");
    ESP_LOGI(TAG, "  Init:   %zu bytes", metrics->memory_profile.memory_init);
    ESP_LOGI(TAG, "  KeyGen: %zu bytes", metrics->memory_profile.memory_keygen);
    ESP_LOGI(TAG, "  Sign:   %zu bytes", metrics->memory_profile.memory_first_sign);
    ESP_LOGI(TAG, "  Verify: %zu bytes", metrics->memory_profile.memory_first_verify);
    
    // Limpar
    crypto_api.close();
    heap_stabilize();
}

// ============================================================
// MEDIÇÕES SILENCIOSAS (sem mudanças significativas)
// ============================================================
void execute_silent_measurements(TestConfig* config) {
    TestMetrics* metrics = &config->metrics;
    MemoryMeasurement m;
    
    // ========== FASE 1: GERAÇÃO DE CHAVES (10x) ==========
    for (int k = 0; k < NUM_KEY_GENERATIONS; k++) {
        if (k > 0) {
            crypto_api.close();
            heap_stabilize();
        }
        
        start_measurement(&m);
        
        int ret = crypto_api.init(config->lib, config->algo, config->hash, 0);
        if (ret == 0) {
            if (config->algo == Algorithms::RSA) {
                ret = crypto_api.gen_rsa_keys(config->rsa_key_size, MY_RSA_EXPONENT);
            } else {
                ret = crypto_api.gen_keys();
            }
        }
        
        end_measurement(&m);
        
        metrics->key_generation[k].time_us = m.time_end - m.time_start;
        metrics->key_generation[k].heap_start = m.heap_before;
        metrics->key_generation[k].heap_end = m.heap_after;
        metrics->key_generation[k].heap_used = m.heap_delta;
    }
    
    // ========== FASE 2: ASSINATURA E VERIFICAÇÃO ==========
    for (int s = 0; s < NUM_TEST_STRINGS; s++) {
        const unsigned char* msg = (const unsigned char*)test_strings[s];
        size_t msg_len = test_string_sizes[s];
        
        metrics->string_tests[s].string_size = msg_len;
        
        size_t sig_size = crypto_api.get_signature_size();
        unsigned char* signature = (unsigned char*)malloc(sig_size);
        if (signature == NULL) {
            ESP_LOGE(TAG, "Failed to allocate signature buffer");
            continue;
        }
        memset(signature, 0, sig_size);
        size_t sig_len = sig_size;
        
        // === ASSINATURAS ===
        for (int i = 0; i < NUM_SIGN_TESTS; i++) {
            sig_len = sig_size;
            
            start_measurement(&m);
            int ret = crypto_api.sign(msg, msg_len, signature, &sig_len);
            end_measurement(&m);
            
            if (ret != 0) {
                ESP_LOGE(TAG, "Sign failed: %d", ret);
            }
            
            if (i == 0) {
                metrics->string_tests[s].first_signature.time_us = m.time_end - m.time_start;
                metrics->string_tests[s].first_signature.heap_used = m.heap_delta;
            } else {
                metrics->string_tests[s].subsequent_signatures[i-1].time_us = m.time_end - m.time_start;
                metrics->string_tests[s].subsequent_signatures[i-1].heap_used = m.heap_delta;
            }
        }
        
        // === VERIFICAÇÕES ===
        for (int i = 0; i < NUM_VERIFY_TESTS; i++) {
            start_measurement(&m);
            int ret = crypto_api.verify(msg, msg_len, signature, sig_len);
            end_measurement(&m);
            
            if (ret != 0) {
                ESP_LOGE(TAG, "Verify failed: %d", ret);
            }
            
            if (i == 0) {
                metrics->string_tests[s].first_verification.time_us = m.time_end - m.time_start;
                metrics->string_tests[s].first_verification.heap_used = m.heap_delta;
            } else {
                metrics->string_tests[s].subsequent_verifications[i-1].time_us = m.time_end - m.time_start;
                metrics->string_tests[s].subsequent_verifications[i-1].heap_used = m.heap_delta;
            }
        }
        
        free(signature);
    }
    
    crypto_api.close();
}

// ============================================================
// FUNÇÕES DE ESTATÍSTICAS
// ============================================================
typedef struct {
    int64_t min;
    int64_t max;
    int64_t avg;
    int64_t median;
    int64_t std_dev;
} TimeStats;

TimeStats calculate_stats(int64_t* values, int count) {
    TimeStats stats = {0};
    if (count == 0) return stats;
    
    stats.min = values[0];
    stats.max = values[0];
    int64_t sum = 0;
    
    for (int i = 0; i < count; i++) {
        int64_t val = values[i];
        if (val < stats.min) stats.min = val;
        if (val > stats.max) stats.max = val;
        sum += val;
    }
    
    stats.avg = sum / count;
    
    int64_t variance_sum = 0;
    for (int i = 0; i < count; i++) {
        int64_t diff = values[i] - stats.avg;
        variance_sum += diff * diff;
    }
    stats.std_dev = (int64_t)sqrt((double)(variance_sum / count));
    
    stats.median = values[count / 2];
    
    return stats;
}

// ============================================================
// IMPRESSÃO DE RESULTADOS
// ============================================================
void print_all_results() {
    int num_configs = sizeof(test_configs) / sizeof(TestConfig);
    
    ESP_LOGI(TAG, "\n");
    ESP_LOGI(TAG, "=======================================================");
    ESP_LOGI(TAG, "         RESULTADOS COMPLETOS - ANÁLISE DETALHADA     ");
    ESP_LOGI(TAG, "=======================================================");
    
    for (int cfg = 0; cfg < num_configs; cfg++) {
        TestConfig* config = &test_configs[cfg];
        TestMetrics* metrics = &config->metrics;
        
        ESP_LOGI(TAG, "\n=======================================================");
        ESP_LOGI(TAG, "Configuração: %s", config->name);
        ESP_LOGI(TAG, "=======================================================");
        
        // === PERFIL DE MEMÓRIA ===
        ESP_LOGI(TAG, "\n--- PERFIL DE MEMÓRIA ---");
        ESP_LOGI(TAG, "Footprint Total:          %zu bytes", 
                 metrics->memory_profile.memory_total);
        ESP_LOGI(TAG, "  - Heap persistente:     %zu bytes", 
                 metrics->memory_profile.heap_persistent);
        ESP_LOGI(TAG, "  - Stack pico:           %zu bytes", 
                 metrics->memory_profile.stack_peak);
        ESP_LOGI(TAG, "\nDetalhamento Heap por fase:");
        ESP_LOGI(TAG, "  - Init:                 %zu bytes", 
                 metrics->memory_profile.memory_init);
        ESP_LOGI(TAG, "  - KeyGen:               %zu bytes", 
                 metrics->memory_profile.memory_keygen);
        ESP_LOGI(TAG, "  - 1ª Sign:              %zu bytes", 
                 metrics->memory_profile.memory_first_sign);
        ESP_LOGI(TAG, "  - 1ª Verify:            %zu bytes", 
                 metrics->memory_profile.memory_first_verify);
        
        // === GERAÇÃO DE CHAVES ===
        ESP_LOGI(TAG, "\n--- GERAÇÃO DE CHAVES ---");
        int64_t key_times[NUM_KEY_GENERATIONS];
        for (int i = 0; i < NUM_KEY_GENERATIONS; i++) {
            key_times[i] = metrics->key_generation[i].time_us;
        }
        TimeStats key_stats = calculate_stats(key_times, NUM_KEY_GENERATIONS);
        
        ESP_LOGI(TAG, "Estatísticas:");
        ESP_LOGI(TAG, "  Avg: %.2f ms", key_stats.avg / 1000.0);
        ESP_LOGI(TAG, "  Min: %.2f ms", key_stats.min / 1000.0);
        ESP_LOGI(TAG, "  Max: %.2f ms", key_stats.max / 1000.0);
        ESP_LOGI(TAG, "  Std: %.2f ms", key_stats.std_dev / 1000.0);
        
        // === FORMATO CSV ===
        ESP_LOGI(TAG, "\n--- CSV DATA ---");
        ESP_LOGI(TAG, "Config,Operation,StringSize,Type,Iteration,Time_us,HeapDelta");
        
        // Key generation
        for (int i = 0; i < NUM_KEY_GENERATIONS; i++) {
            ESP_LOGI(TAG, "%s,KeyGen,0,Full,%d,%lld,%zu",
                     config->name, i,
                     metrics->key_generation[i].time_us,
                     metrics->key_generation[i].heap_used);
        }
        
        // Sign/Verify por tamanho de string
        for (int s = 0; s < NUM_TEST_STRINGS; s++) {
            // Primeira assinatura
            ESP_LOGI(TAG, "%s,Sign,%zu,First,0,%lld,%zu",
                     config->name,
                     metrics->string_tests[s].string_size,
                     metrics->string_tests[s].first_signature.time_us,
                     metrics->string_tests[s].first_signature.heap_used);
            
            // Assinaturas subsequentes
            for (int i = 0; i < NUM_SIGN_TESTS - 1; i++) {
                ESP_LOGI(TAG, "%s,Sign,%zu,Subsequent,%d,%lld,%zu",
                         config->name,
                         metrics->string_tests[s].string_size,
                         i + 1,
                         metrics->string_tests[s].subsequent_signatures[i].time_us,
                         metrics->string_tests[s].subsequent_signatures[i].heap_used);
            }
            
            // Primeira verificação
            ESP_LOGI(TAG, "%s,Verify,%zu,First,0,%lld,%zu",
                     config->name,
                     metrics->string_tests[s].string_size,
                     metrics->string_tests[s].first_verification.time_us,
                     metrics->string_tests[s].first_verification.heap_used);
            
            // Verificações subsequentes
            for (int i = 0; i < NUM_VERIFY_TESTS - 1; i++) {
                ESP_LOGI(TAG, "%s,Verify,%zu,Subsequent,%d,%lld,%zu",
                         config->name,
                         metrics->string_tests[s].string_size,
                         i + 1,
                         metrics->string_tests[s].subsequent_verifications[i].time_us,
                         metrics->string_tests[s].subsequent_verifications[i].heap_used);
            }
        }
    }
    
    ESP_LOGI(TAG, "\n=======================================================");
    ESP_LOGI(TAG, "                   FIM DOS RESULTADOS                 ");
    ESP_LOGI(TAG, "=======================================================");
}

// ============================================================
// EXECUÇÃO COMPLETA DOS TESTES
// ============================================================
void perform_complete_tests() {
    int num_configs = sizeof(test_configs) / sizeof(TestConfig);
    
    #define LED_PIN GPIO_NUM_8
    gpio_set_direction(LED_PIN, GPIO_MODE_OUTPUT);
    
    // FASE 1: PERFIL DE MEMÓRIA
    ESP_LOGI(TAG, "\n>>> FASE 1: PROFILING DE MEMÓRIA <<<\n");
    for (int cfg = 0; cfg < num_configs; cfg++) {
        gpio_set_level(LED_PIN, 1);
        execute_memory_profiling(&test_configs[cfg]);
        gpio_set_level(LED_PIN, 0);
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    // FASE 2: MEDIÇÕES DE PERFORMANCE
    ESP_LOGI(TAG, "\n>>> FASE 2: MEDIÇÕES DE PERFORMANCE <<<\n");
    for (int cfg = 0; cfg < num_configs; cfg++) {
        gpio_set_level(LED_PIN, cfg % 2);
        execute_silent_measurements(&test_configs[cfg]);
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    gpio_set_level(LED_PIN, 0);
    
    // FASE 3: IMPRESSÃO DE RESULTADOS
    vTaskDelay(pdMS_TO_TICKS(1000));
    print_all_results();
}

// ============================================================
// MAIN
// ============================================================
extern "C" void app_main(void) {
    esp_task_wdt_deinit();
    
    ESP_LOGI(TAG, "\n=======================================================");
    ESP_LOGI(TAG, "  ESP32C6 Crypto Benchmark v2.2 - MEMORY CORRECTED    ");
    ESP_LOGI(TAG, "=======================================================");
    ESP_LOGI(TAG, "Heap inicial: %lu bytes", heap_caps_get_free_size(MALLOC_CAP_8BIT));
    ESP_LOGI(TAG, "Iniciando em 5 segundos...");
    
    vTaskDelay(pdMS_TO_TICKS(5000));
    
    perform_complete_tests();
    
    ESP_LOGI(TAG, "\n*** BENCHMARK FINALIZADO ***");
    ESP_LOGI(TAG, "Heap final: %lu bytes", heap_caps_get_free_size(MALLOC_CAP_8BIT));
    
    while(1) {
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}