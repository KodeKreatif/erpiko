#include "erpiko/rng.h"
#include "erpiko/utils.h"
#include <openssl/rand.h>
#include <iostream>
#include <ctime>

#ifdef ENABLE_CUDA
#pragma GCC diagnostic push
#include <cuda.h>
#include <curand_kernel.h>
#pragma GCC diagnostic pop
#define SIZE 256
__global__ void setup_kernel_rng(curandStateMRG32k3a *state, unsigned int seed);
void run_kernel_rng(curandStateMRG32k3a *devMRGStates, unsigned int *results);
#endif

namespace Erpiko {

class Rng::Impl {
  public:
  std::function<void(void)> onEntropyFulfilled;
#ifdef ENABLE_CUDA
  int device;
  unsigned int *devResults, *hostResults, lastSeed = 0;
  curandStateMRG32k3a *devMRGStates;
  std::vector<unsigned char> buffer;

  Impl() {
    cudaGetDevice(&device);
    hostResults = (unsigned int *)calloc(SIZE * SIZE, sizeof(unsigned int)); 
    cudaMalloc((void **)&devResults, SIZE * SIZE * sizeof(unsigned int));
    cudaMemset(devResults, 0, SIZE * SIZE * sizeof(unsigned int));

    cudaMalloc((void **)&devMRGStates, SIZE * SIZE * sizeof(curandStateMRG32k3a));
    lastSeed = (unsigned int) std::time(nullptr);
  }

  ~Impl() {
    cudaFree(devResults);
    cudaFree(devMRGStates);
    free(hostResults);
  }
#else
  Impl() {
  }
#endif

  void seed(const void* buffer, const unsigned int length) {
    RAND_seed(buffer, length);
    if (RAND_status() == 1 && onEntropyFulfilled) {
      onEntropyFulfilled();
    }
  }

  std::vector<unsigned char> random(const unsigned int length) {
    std::vector<unsigned char> ret(length);

#ifdef ENABLE_CUDA
    unsigned int needed = 0;
    unsigned int prefillSize = 0;
    // There's some left over in the buffer
    if (buffer.size() > 0) {
      needed = length;
      // We only need some fractions of the buffer
      if (needed <= buffer.size()) {
         memcpy(ret.data(), buffer.data(), needed);
         std::vector<unsigned char>(buffer.begin() + needed, buffer.end()).swap(buffer);
         return ret;
      } else {
         // we need more than what the buffer provides
         // copy em all
         memcpy(ret.data(), buffer.data(), buffer.size());
         // then we need more data from the curand
         // later on
         needed = length - buffer.size();
         prefillSize = buffer.size();
         buffer.clear();
      }
    }

    unsigned int size = SIZE * SIZE * sizeof(unsigned int);
    unsigned int it = 0;
    if (needed == 0) {
      needed = length;
    }
    unsigned int maxLength = (needed > size) ? size : needed;
    unsigned int offset = 0;
    while (1) {
      setup_kernel_rng(devMRGStates, lastSeed);
      run_kernel_rng(devMRGStates, devResults);
      cudaMemcpy(hostResults, devResults, size, cudaMemcpyDeviceToHost);
      memcpy(ret.data() + prefillSize, hostResults + offset, maxLength);
      lastSeed = (unsigned int) std::time(nullptr) | hostResults[offset];
      if (maxLength < size) {
        // keep the unused data in the buffer
        buffer.resize(size - maxLength);
        memcpy(buffer.data(), hostResults + offset + maxLength, size - maxLength);
        break;
      }
      offset += maxLength;
      it ++;
      if (it > (length / size)) break;
    } 
#else
    RAND_bytes(ret.data(), length);
#endif
    return ret;
  }

};

Rng::Rng() : impl{std::make_unique<Impl>()} {
}

Rng::~Rng() = default;

void
Rng::seed(const void* buffer, const unsigned int length) {
  impl->seed(buffer, length);
}

std::vector<unsigned char>
Rng::random(const unsigned int length) {
  return impl->random(length);
}

void
Rng::onEntropyFulfilled(std::function<void(void)> f) {
  impl->onEntropyFulfilled = f;
}

} // namespace Erpiko
