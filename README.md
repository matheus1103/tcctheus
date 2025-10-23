# ESP32 Crypto API

A comprehensive cryptographic benchmarking framework for ESP32 devices, developed as part of the final university project/thesis, forked from https://github.com/bristotgl/esp32-crypto-api project titled "Digital Certification in IoT Devices."

## Overview

This project provides a unified API to benchmark and compare cryptographic libraries on ESP32 microcontrollers, with a focus on digital signature algorithms. The framework measures execution time, heap memory usage, and stack consumption across different cryptographic operations.

### Supported Libraries

- **mbedTLS** - Lightweight cryptographic library optimized for embedded systems
- **WolfSSL** - Fast, portable, and comprehensive cryptographic library
- **micro-ecc** - Compact ECDSA library for embedded systems

### Supported Algorithms

- **RSA** - 2048-bit and 4096-bit key sizes
- **ECDSA** - Multiple curves:
  - secp256r1 (NIST P-256)
  - secp521r1 (NIST P-521)
  - brainpoolP256r1
  - brainpoolP512r1
- **EdDSA** - Ed25519 and Ed448 (WolfSSL only)

### Supported Hash Functions

- SHA-256
- SHA-512

## Features

- **Comprehensive Benchmarking**: Measures key generation, signing, and verification operations
- **Memory Profiling**: Detailed heap and stack usage analysis using ESP32-C6's local memory monitoring
- **Statistical Analysis**: Min, max, average, median, and standard deviation calculations
- **CSV Export**: Results formatted for easy data analysis
- **Configurable Tests**: Multiple test configurations for different library/algorithm/hash combinations

## Requirements

### Hardware
- ESP32-C6 development board (or compatible ESP32 variant)
- USB cable for flashing and monitoring

### Software
- **ESP-IDF**: Framework version 5.3.1 or later
  - Follow the [ESP-IDF official documentation](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html) for installation
- **VSCode** (recommended): For easier development and debugging
  - Install the ESP-IDF VSCode extension for best experience

## Setup Instructions

### 1. Install ESP-IDF

Follow the official ESP-IDF installation guide for your operating system. Ensure the ESP-IDF tools are properly added to your system PATH.

### 2. Setting up WolfSSL

WolfSSL requires its source code to be available outside the project directory:

1. Download the WolfSSL source code from the [GitHub releases page (v5.7.4-stable)](https://github.com/wolfSSL/wolfssl/releases/tag/v5.7.4-stable)
2. Extract the downloaded archive to your desired location (e.g., `C:\wolfssl-source` or `/home/user/wolfssl-source`)
3. Create a system-wide environment variable:
   - **Variable name**: `WOLFSSL_ROOT`
   - **Variable value**: Path to the WolfSSL source directory (e.g., `C:\wolfssl-source`)
4. Restart your terminal/IDE or reboot your machine to apply the environment variable
5. The build system will automatically detect and link WolfSSL during compilation

### 3. Clone and Configure the Project

```bash
git clone <repository-url>
cd esp32-crypto-api
```

## Configuration

### Selecting Test Configurations

Edit the `test_configs[]` array in [main/main.cpp](main/main.cpp) to enable/disable specific test configurations:

```cpp
TestConfig test_configs[] = {
    // Example: Enable mbedTLS RSA-2048 with SHA-256
    {Libraries::MBEDTLS_LIB, Algorithms::RSA, Hashes::MY_SHA_256, 2048, "MBEDTLS_RSA_2048_SHA256"},

    // Example: Enable WolfSSL ECDSA P-256 with SHA-256
    {Libraries::WOLFSSL_LIB, Algorithms::ECDSA_SECP256R1, Hashes::MY_SHA_256, 0, "WOLFSSL_ECDSA_P256_SHA256"},

    // Uncomment desired configurations...
};
```

### Test Parameters

You can adjust the number of test iterations in [main/main.cpp](main/main.cpp):

```cpp
#define NUM_KEY_GENERATIONS 10   // Number of key generation tests
#define NUM_SIGN_TESTS 10        // Number of signing operations per string
#define NUM_VERIFY_TESTS 10      // Number of verification operations per string
```

## Building and Running

### Using Command Line

1. Connect your ESP32 device to your computer
2. Open ESP-IDF PowerShell or ESP-IDF CMD
3. Navigate to the project directory:
   ```bash
   cd <path-to-project>/esp32-crypto-api
   ```

4. Set the target device (first time only or when changing targets):
   ```bash
   idf.py set-target esp32c6
   ```

5. Build the project:
   ```bash
   idf.py build
   ```

6. Flash to the device:
   ```bash
   idf.py flash
   ```

7. Monitor the output:
   ```bash
   idf.py monitor
   ```

   Press `Ctrl+]` to exit the monitor.

### Using VSCode

1. Connect your ESP32 device
2. Open the project folder in VSCode
3. Use the ESP-IDF extension commands:
   - `Ctrl+Shift+P` → `ESP-IDF: Set Espressif Device Target` (first time only)
   - `Ctrl+Shift+P` → `ESP-IDF: Build your project`
   - `Ctrl+Shift+P` → `ESP-IDF: Flash your project`
   - `Ctrl+Shift+P` → `ESP-IDF: Monitor device`

### Quick Start

If you already have a build folder, you can flash and monitor directly:

```bash
idf.py flash monitor
```

If you encounter build errors, delete the `build` folder and rebuild:

```bash
rm -rf build
idf.py build
```

## Output Format

The benchmark outputs detailed results including:

### Memory Profile
- Heap and stack usage for each operation (init, key generation, signing, verification)
- Persistent heap allocation
- Peak stack usage
- Total memory footprint

### Performance Metrics
- Key generation statistics (min, max, avg, std deviation)
- Sign/verify operation timings for different message sizes
- CSV-formatted data for easy analysis

### Sample Output
```
=== PROFILING DE MEMÓRIA: WOLFSSL_RSA_2048_SHA256 ===
FOOTPRINT DE MEMÓRIA:
  Heap persistente:  12345 bytes
  Stack pico usado:  4567 bytes
  TOTAL:             16912 bytes
```

## Project Structure

```
esp32-crypto-api/
├── components/
│   ├── CryptoAPI/          # Main API implementation
│   │   ├── include/        # Header files
│   │   └── src/            # Source files
│   ├── micro-ecc/          # micro-ecc library
│   └── wolfssl/            # WolfSSL configuration
├── experiments/
│   └── test_strings_exact.h # Test data strings
├── main/
│   ├── main.cpp            # Benchmark implementation
│   └── CMakeLists.txt
├── CMakeLists.txt          # Project configuration
└── README.md
```

## Analyzing Results

The benchmark outputs CSV-formatted data that can be analyzed using Python scripts:

- `analyze_memory.py` - Memory usage analysis
- `analyze_memory_visual.py` - Visual memory analysis with charts

## Troubleshooting

### Common Issues

1. **Build fails with WolfSSL errors**
   - Ensure `WOLFSSL_ROOT` environment variable is set correctly
   - Verify WolfSSL version is v5.7.4-stable
   - Restart your terminal/IDE after setting the environment variable

2. **Flash fails or device not detected**
   - Check USB cable connection
   - Verify correct serial port in VSCode or menuconfig
   - Try pressing the BOOT button on ESP32 during flashing

3. **Out of memory errors**
   - Reduce the number of test iterations
   - Disable some test configurations
   - Check the `sdkconfig` for memory settings


## Author
Matheus Francisco Rodrigues Lima, forked from https://github.com/bristotgl/esp32-crypto-api
