#ifndef _ENGINE_P11_H
#define _ENGINE_P11_H

#include <map>
#include <string>
#include <iostream>
using namespace std;
namespace Erpiko {

class EngineP11 {
  bool initialized = false;
  void* lib = nullptr;
  unsigned long session = 0;
  string keyLabel;
  unsigned int keyId;

  private:
    EngineP11() { }

  public:
    static EngineP11& getInstance() {
      static EngineP11 me;

      return me;
    }

    EngineP11(EngineP11 const&) = delete;
    void operator=(EngineP11 const&) = delete;
    void init();
    bool load(const std::string path);
    void finalize();

    bool login(const unsigned long slot, const string& pin);
    bool logout();
    unsigned long getSession() {
      return session;
    }

    void setKeyLabel(const string& label) {
      keyLabel = label;
    }

    void setKeyId(const unsigned int id) {
      keyId = id;
    }

    const string& getKeyLabel() const {
      return keyLabel;
    }

    unsigned int getKeyId() const {
      return keyId;
    }
};

} // namespace Erpiko
#endif // _ENGINE_P11_H
