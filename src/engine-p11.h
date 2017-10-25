#ifndef _ENGINE_P11_H
#define _ENGINE_P11_H

#include <map>
#include <string>
using namespace std;
namespace Erpiko {

class EngineP11 {
  bool initialized = false;
  void* lib = nullptr;
  unsigned long session;
  string keyLabel;
  unsigned char keyId;

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
    unsigned long getSession() {
      return session;
    }

    void setKeyLabel(const string& label) {
      keyLabel = label;
    }

    void setKeyId(const unsigned char id) {
      keyId = id;
    }

    const string& getKeyLabel() const {
      return keyLabel;
    }

    unsigned char getKeyId() const {
      return keyId;
    }
};

} // namespace Erpiko
#endif // _ENGINE_P11_H
