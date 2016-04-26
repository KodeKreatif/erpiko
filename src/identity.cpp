#include "erpiko/identity.h"
#include <string.h>
#include <openssl/x509.h>
#include <iostream>

namespace Erpiko {

class Identity::Impl {
  public:
    X509_NAME *name = nullptr;

    Impl() {
      name = X509_NAME_new();
    }

    virtual ~Impl() {
      X509_NAME_free(name);
      name = nullptr;
    }

    const std::string get(const std::string name) const {
      for (int i = 0; i < X509_NAME_entry_count(this->name); i++) {
        auto e = X509_NAME_get_entry(this->name, i);
        auto obj = X509_NAME_ENTRY_get_object(e);
        unsigned char buffer[1024];
        auto len = OBJ_obj2txt((char*) buffer, 1024, obj, 0);
        if (len <= 0) {
          continue;
        }
        buffer[len] = 0;
        std::string foundName = (char *) buffer;
        if (foundName == name) {
          auto data = X509_NAME_ENTRY_get_data(e);
          std::string s;
          s = (const char*) data->data;
          return s;
        }
      }
      return std::string("");
    }

};

Identity::Identity() : impl{std::make_unique<Impl>()} {
}

Identity::~Identity() = default;

bool Identity::operator== (const Identity& other) const {
  auto first = toDer();
  auto second = other.toDer();
  return first == second;
}

const std::string Identity::get(const std::string name) const {
  return impl->get(name);
}

void Identity::set(const std::string name, const std::string value) {
  for (int i = 0; i < X509_NAME_entry_count(impl->name); i++) {
    auto e = X509_NAME_get_entry(impl->name, i);
    auto obj = X509_NAME_ENTRY_get_object(e);
    unsigned char buffer[1024];
    auto len = OBJ_obj2txt((char*) buffer, 1024, obj, 0);
    if (len <= 0) {
      continue;
    }
    buffer[len] = 0;
    std::string foundName = (char *) buffer;
    if (foundName == name) {
      // found, then let's delete it
      auto del = X509_NAME_delete_entry(impl->name, i);
      free(del);
      break;
    }
  }
  if (value.length() > 0) {
    if (X509_NAME_add_entry_by_txt(impl->name, name.c_str(), MBSTRING_UTF8, (const unsigned char*) value.c_str(), -1, -1, 0)) {
    }
  }
}

const std::vector<unsigned char> Identity::toDer() const {
  std::vector<unsigned char> retval;

  auto length = i2d_X509_NAME(impl->name, 0);
  if (length) {
    unsigned char *der = (unsigned char*)malloc(length);
    unsigned char *start = der;
    i2d_X509_NAME(impl->name, &der);
    for (int i = 0; i < length; i ++) {
      retval.push_back(start[i]);
    }
    free(start);
  }
  return retval;


}

} // namespace Erpiko
