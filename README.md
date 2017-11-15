![](https://user-images.githubusercontent.com/2534060/31044979-4694eee8-a604-11e7-8f0c-4b1e11f31e2f.png)

# Erpiko -- PKI made easy

## Goals

A decent C++ library with PKI functionalities is missing.
Erpiko wants to fill the gap and provide an easy to use C++ interfaces.

## Supported Features

- X509 Certificate
- CMP over HTTP (RFC-4210, RFC-6712) (*partial*)
- SIM (RFC-4683)
- PKCS#7 (*partial*)
- PKCS#10
- PKCS#12
- S/MIME sigining, verification, encryption and decryption
- TSA (request, response, and verification)
- Random number generator
- Message Digest (SHA1, SHA2, SHA512)
- Cipher (AES, RC2, RC4, CAST5, 3DES, DES)
- Crypto functions with CUDA when available and enabled (*WIP*)
- PKCS#11 client (which means your Erpiko can use PKCS#11 devices as backend)

## Backend

Erpiko uses LibreSSL as it's backend

## Building

CUDA support is automatically enabled by default if available. To disable CUDA, pass `DISABLE_CUDA` when
initializing CMAKE, eg: `cmake -DDISABLE_CUDA=1 ..`. If CUDA is not found in your system then it is not
needed to disable CUDA.

### Requirements

- cmake
- autoconf
- automake
- libtool

### Steps

This apply to Linux & macOS build. Please consult to `appveyor.yml` for Windows build.

```
./scripts/build-deps-unix.sh  # Download and compile the dependencies (LibreSSL, catch and patches) for GNU/Linux
./scripts/build-deps-mac.sh   # Download and compile the dependencies (LibreSSL, catch and patches) for Mac
./scripts/build.sh            # Compile the erpiko
```

## Compatibility with OpenSSL

Since Erpiko uses LibreSSL, it isn't ABI compatible with OpenSSL. If you work with an application that require a library that depends on OpenSSL, you need to relink the library to LibreSSL.
Please see also issue #6.

## License

Erpiko is BSD.

## History

Erpiko development was initiated under a sponsorship granted by the Ministry of Communication and Informatics of Indonesia,
then it is continued by the Erpiko contributors.
