# ESP32 Crypto API

Cryptographic benchmark framework for ESP32 devices, focused on digital signatures, execution time, and memory footprint (heap + stack). This project is based on the original repository: https://github.com/bristotgl/esp32-crypto-api.

## Overview

The project provides a unified API (`CryptoAPI`) to execute the same benchmark flow across multiple crypto libraries and algorithms. The current benchmark pipeline in `main/main.cpp` runs in three phases:

1. Memory profiling per configuration.
2. Silent performance measurements (keygen/sign/verify).
3. Aggregated report printing, including CSV lines in log output.

## Supported Libraries and Algorithms

### Libraries

- `mbedTLS`
- `wolfSSL`
- `micro-ecc`

### Algorithms currently configured in `main/main.cpp`

- `RSA` (mbedTLS and wolfSSL)
   - 2048 bits
   - 4096 bits (mbedTLS)
- `ECDSA`
   - `secp256r1` (P-256)
   - `secp521r1` (P-521)
   - `brainpoolP256r1`
   - `brainpoolP512r1`
- `EdDSA` (wolfSSL)
   - `Ed25519`
   - `Ed448`

### Hashes currently configured in benchmarks

- `SHA-256`
- `SHA-512`

## Main Features

- Unified benchmark API for different crypto backends.
- Detailed memory profiling using local heap monitoring and stack high-water mark.
- Performance measurements for key generation, signature, and verification.
- CSV output in logs for downstream analysis.
- Python helper scripts for post-processing.

## Requirements

### Hardware

- ESP32 board (the current benchmark header references ESP32-C6).
- USB cable for flashing/monitoring.

### Software

- ESP-IDF `5.3.1+` (recommended).
- Python environment provided by ESP-IDF tools.
- VS Code + ESP-IDF extension (recommended workflow).

## Setup

### 1. Install ESP-IDF

Follow the official documentation:
https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html

Use an ESP-IDF shell (`ESP-IDF PowerShell`, `ESP-IDF CMD`, or equivalent terminal with `idf.py` available).

### 2. Configure wolfSSL source location

This repository includes a local wolfSSL ESP-IDF component under `components/wolfssl`, but it still expects the wolfSSL source tree path via `WOLFSSL_ROOT`.

1. Download/extract wolfSSL source code.
2. Set environment variable `WOLFSSL_ROOT` to the wolfSSL root folder.

Windows (PowerShell, current session):

```powershell
$env:WOLFSSL_ROOT = "C:\path\to\wolfssl"
```

Linux/macOS (bash/zsh, current session):

```bash
export WOLFSSL_ROOT="/path/to/wolfssl"
```

If needed, persist the environment variable in your system/user profile.

### 3. Clone project

```bash
git clone <repository-url>
cd esp32-crypto-api
```

## Build and Run

### CLI flow

1. Set target (first build or when changing board):

```bash
idf.py set-target esp32c6
```

2. Build:

```bash
idf.py build
```

3. Flash and monitor:

```bash
idf.py flash monitor
```

To exit monitor, press `Ctrl+]`.

### Clean and rebuild

```bash
idf.py fullclean
idf.py build
```

If you prefer deleting the `build` directory manually:

Windows PowerShell:

```powershell
Remove-Item -Recurse -Force .\build
```

Linux/macOS:

```bash
rm -rf build
```

### VS Code tasks available in this workspace

- `Build - Build project`
- `Set ESP-IDF Target`
- `Clean - Clean the project`
- `Flash - Flash the device`
- `Monitor: Start the monitor`

## Benchmark Configuration

### Enable/disable test sets

Edit `test_configs[]` in `main/main.cpp`.

Each entry defines:

- library (`Libraries` enum)
- algorithm (`Algorithms` enum)
- hash (`Hashes` enum)
- RSA key size (or `0` for non-RSA)
- display name for logs

### Iteration counts

In `main/main.cpp`:

```cpp
#define NUM_KEY_GENERATIONS 10
#define NUM_SIGN_TESTS 10
#define NUM_VERIFY_TESTS 10
```

## Output and Metrics

The benchmark logs include:

- Memory footprint summary per configuration:
   - persistent heap delta
   - peak stack usage
   - total footprint
- Timing statistics for key generation:
   - average, minimum, maximum, standard deviation
- Per-message-size sign/verify timings.
- CSV records with schema:

```text
Config,Operation,StringSize,Type,Iteration,Time_us,HeapUsed,StackUsed
```

## Result Analysis Scripts

- `analyze_memory.py`
- `analyze_memory_visual.py`

These scripts can be used to process benchmark output files and generate summaries/visualizations.

## Project Structure

```text
esp32-crypto-api/
|- components/
|  |- CryptoAPI/
|  |  |- include/
|  |  |- src/
|  |- micro-ecc/
|  |- wolfssl/
|- experiments/
|  |- test_strings_exact.h
|- main/
|  |- main.cpp
|- CMakeLists.txt
|- partitions.csv
|- sdkconfig
|- README.md
```

## Troubleshooting

### Build fails with wolfSSL errors

- Validate `WOLFSSL_ROOT` path.
- Confirm ESP-IDF environment is loaded in the current shell.
- Ensure there is no component conflict between:
   - `components/wolfssl`
   - `managed_components/wolfssl__wolfssl`

### Flash or monitor issues

- Check USB cable and serial port.
- Verify selected port/target in ESP-IDF extension.
- Retry with board in bootloader mode when needed.

### Memory pressure during benchmarks

- Reduce `NUM_KEY_GENERATIONS`, `NUM_SIGN_TESTS`, and `NUM_VERIFY_TESTS`.
- Temporarily reduce enabled entries in `test_configs[]`.

## Credits

- Current work: Matheus Francisco Rodrigues Lima
- Based on: https://github.com/bristotgl/esp32-crypto-api
