#ifndef _ENGINE_P11_H
#define _ENGINE_P11_H

#include <string>
namespace Erpiko {

class EngineP11 {
  bool initialized = false;

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
};

} // namespace Erpiko
#endif // _ENGINE_P11_H
