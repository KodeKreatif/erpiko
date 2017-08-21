#ifndef _DIGEST_H
#define _DIGEST_H

#include "erpiko/oid.h"
#include <vector>

namespace Erpiko {

/**
 * Message digest interface
 */
class Digest {

  public:
    Digest() {};
    virtual ~Digest() = default;

    static Digest* get(const ObjectId& algorithmId);

    /**
     * Adds a new data to be digested
     * @param data The data to be digested
     */
    virtual void update(std::vector<unsigned char> data) = 0;

    /**
     * Finalizes a digestion
     * @param data The data to be digested
     * @return the digest
     */
    virtual std::vector<unsigned char> finalize(std::vector<unsigned char> data) = 0;
};

} // namespace Erpiko
#endif // _DIGEST_H
