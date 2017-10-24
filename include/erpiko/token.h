#ifndef _TOKEN_H_
#define _TOKEN_H_

#include <memory>
namespace Erpiko {

/**
 * Hardware token interface
 */
class Token {
  public:
    Token();
    virtual ~Token();
    bool load(const std::string path);
    bool isValid();

  private:
    class Impl;
    std::unique_ptr<Impl> impl;
};
} // namespace Erpiko
#endif // _TOKEN_H_
