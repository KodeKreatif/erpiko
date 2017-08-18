#ifdef ENABLE_CUDA
#pragma GCC diagnostic push
#include <cuda.h>
#include <curand_kernel.h>
#pragma GCC diagnostic pop
#endif


#define SIZE 256
__global__ void setup_kernel(curandStateMRG32k3a *state, unsigned int seed) {
  int id = threadIdx.x + blockIdx.x * SIZE; 
  curand_init(seed, id, 0, &state[id]);
} 

__global__ void run_kernel(curandStateMRG32k3a *state, unsigned int *result) { 
  int id = threadIdx.x + blockIdx.x * SIZE;
  curandStateMRG32k3a localState = state[id];
  unsigned int x = curand(&localState); 
  while (x == 0) {
    x = curand(&localState); 
  }
  state[id] = localState; 
  result[id] = x; 
}


void setup_kernel_rng(curandStateMRG32k3a *devMRGStates, unsigned int seed) {
  setup_kernel<<<SIZE, SIZE>>>(devMRGStates, seed);
}

void run_kernel_rng(curandStateMRG32k3a *devMRGStates, unsigned int *devResults) {
  run_kernel<<<SIZE, SIZE>>>(devMRGStates, devResults);
}
