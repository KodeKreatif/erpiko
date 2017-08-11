# Erpiko -- PKI made easy

## Goals

A decent C++ library with PKI functionalities is missing. 
Erpiko wants to fill the gap and provide an easy to use C++ interfaces.

## Supported Features

- X509 Certificate 
- CMP over HTTP (RFC-4210, RFC-6712) (*partial*)
- SIM (RFC-4683)
- PKCS#12
- PKCS#7 (*partial*)
- S/MIME sigining, verification, encryption and decryption
- TSA (request, response, and verification)
- Random number generator
- Crypto functions with CUDA when available and enabled

## Backend

Erpiko uses LibreSSL as it's backend

## Building

CUDA support is automatically enabled by default if available. To disable CUDA, pass `DISABLE_CUDA` when
initializing CMAKE, eg: `cmake -DDISABLE_CUDA=1 ..`. If CUDA is not found in your system then it is not
needed to disable CUDA.

## License

Erpiko is BSD.
