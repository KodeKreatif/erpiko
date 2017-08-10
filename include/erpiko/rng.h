#ifndef _RNG_H
#define _RNG_H

#include <memory>
#include <vector>
#include <functional>

namespace Erpiko {

/**
 * Random number generator
 */
class Rng {
  public:
    Rng();
    virtual ~Rng();

    /**
     * Sets a callback when entropy is fulfilled
     * @param f function which is called when entropy is fulfilled
     */
    void onEntropyFulfilled(std::function<void(void)> f);

    /**
     * Seeds random number generator
     * @param buffer the buffer which contains the seed
     * @param length the length of the seed
     */
    void seed(const void* buffer, const unsigned int length);

    /**
     * Generates random bytes
     * @param length the length of the random bytes
     * @return a vector containing the random bytes
     */
    std::vector<unsigned char> random(unsigned int length);

  private:
    class Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace Erpiko
#endif // _RNG_H
