#ifndef _OBJECT_ID_H_
#define _OBJECT_ID_H_

#include <string>
#include <memory>

namespace Erpiko {

/**
 * ASN1 Object ID
 */

class ObjectId {
  public:
    /**
     * Creates a new ObjectId from a string
     */
    ObjectId(const std::string fromString);
    virtual ~ObjectId();

    /**
     * Gets string representation of the object
     * @return string representation
     */
    const std::string toString() const;

    /**
     * Gets string representation of the object which we human is familiar with
     * @return string representation
     */
    const std::string humanize() const;

    /**
     * Operator ==
     **/
    bool operator== (const ObjectId& other) const;

    /**
     * Operator =
     **/
    void operator= (const ObjectId& other);

  private:
    class Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace Erpiko
#endif // _OBJECT_ID_H_
