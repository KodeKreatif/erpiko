#include "erpiko/oid.h"
#include <openssl/objects.h>

namespace Erpiko {

class ObjectId::Impl {

  public:
    ASN1_OBJECT *obj = nullptr;
    std::string string;
    Impl(const std::string fromString) : string(fromString) {
      obj = OBJ_txt2obj(fromString.c_str(), 0);
    }

    virtual ~Impl() {
      if (obj != nullptr) {
        free(obj);
        obj = nullptr;
      }
    }
};

ObjectId::ObjectId(const std::string fromString) : impl{std::make_unique<Impl>(fromString)} {
}

ObjectId::~ObjectId() = default;

const std::string ObjectId::toString() const {
  return impl->string;
}

const std::string ObjectId::humanize() const {
  unsigned char buffer[1024];
  int ret = OBJ_obj2txt((char*) buffer, 1024, impl->obj, 0);
  if (ret) {
    buffer[ret] = 0;
    std::string retval = (char*) buffer;
    return retval;
  }
  return "";
}


bool ObjectId::operator== (const ObjectId& other) const {
  return (OBJ_cmp(impl->obj, other.impl->obj) == 0);
}

void ObjectId::operator= (const ObjectId& other) {
  if (impl->obj != nullptr) {
    free(impl->obj);
  }
  impl->obj = OBJ_dup(other.impl->obj);
}

} // namespace Erpiko
