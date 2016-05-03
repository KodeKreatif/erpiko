#ifndef _UTILS_H_
#define _UTILS_H_

#include <vector>
#include <sstream>
#include <iomanip>
#include <iostream>

namespace Erpiko {
namespace Utils {

inline std::string hexString(const unsigned char* buffer, const size_t length) {
  std::stringstream s;

  for (size_t i = 0; i < length; i ++) {
    s << std::hex << std::setfill('0') << std::setw(2) << (int) buffer[i];
  }
  return s.str();
}

inline std::string hexString(const std::vector<unsigned char> data) {
  return hexString(data.data(), data.size());
}


} // namespace Utils
} // namespace Erpiko
#endif // _UTILS_H_
