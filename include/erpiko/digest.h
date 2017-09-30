#ifndef _DIGEST_H
#define _DIGEST_H

#include "erpiko/oid.h"
#include <vector>

namespace Erpiko {

namespace DigestConstants {
  const char* const SHA1 = "1.3.14.3.2.26";
  const char* const SHA224 = "2.16.840.1.101.3.4.2.4";
  const char* const SHA256 = "2.16.840.1.101.3.4.2.1";
  const char* const SHA384 = "2.16.840.1.101.3.4.2.2";
  const char* const SHA512 = "2.16.840.1.101.3.4.2.3";
};

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
