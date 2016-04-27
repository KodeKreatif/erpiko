#include "erpiko/data-source.h"
#include <ios>
#include <fstream>
#include <sstream>
#include <iostream>

namespace Erpiko {

class DataSource::Impl {
  public:
    std::vector<unsigned char> data;
    std::string filePath;
    std::ifstream stream;

    Impl() {
    }

    virtual ~Impl() {
      if (stream.is_open()) {
        stream.close();
      }
    }

    const std::vector<unsigned char>& readAll() {
      if (filePath.length() > 0) {
        return readAllFromFile();
      }
      return data;
    }

    const std::vector<unsigned char>& readAllFromFile() {
      data.assign((std::istreambuf_iterator<char>(stream)),
          std::istreambuf_iterator<char>());

      return data;
    }

    void loadFile(const std::string fileName) {
      try {
        stream.open(fileName, std::ifstream::binary);
        if (stream) {
          filePath = fileName;
        }
      } catch(std::system_error& e) {
        std::cout << e.what() <<"\n";

      }
    }
};

DataSource::DataSource() : impl{std::make_unique<Impl>()} {
}

DataSource::~DataSource() = default;

DataSource* DataSource::fromVector(const std::vector<unsigned char> data) {
  DataSource *src = new DataSource();
  src->impl->data = data;
  return src;
}

DataSource* DataSource::fromFile(const std::string fileName) {
  DataSource *src = new DataSource();
  src->impl->loadFile(fileName);
  if (src->impl->filePath != fileName) {
    delete(src);
    return nullptr;
  }
  return src;
}


const std::vector<unsigned char>& DataSource::readAll() {
  return impl->readAll();
}

} // namespace Erpiko
