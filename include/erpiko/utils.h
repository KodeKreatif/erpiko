#ifndef _UTILS_H_
#define _UTILS_H_

#include <cctype>
#include <cstring>
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

inline std::vector<unsigned char> fromHexString(const char* buffer) {
  std::vector<unsigned char> ret;

  if (buffer == nullptr) return ret;
  int len = strlen(buffer);
  int i = 0;
  unsigned char t = 0;
  bool toAdd = false;
  while (i < len) {
    int l = tolower(buffer[i]);
    if ((isalpha(buffer[i]) && l >= 97 && l <=102) || isdigit(buffer[i])) {
      unsigned char v = l - 48;
      if (v > 9) {
        v = l - 97 + 10;
      }
      if ((i - 1) % 2 || i == 0) {
        t = v << 4;
        toAdd = true;
      } else {
        t += v;
        toAdd = false;
        ret.push_back(t);
      }
    } else {
      break;
    }

    i ++;
  }
  if (toAdd) {
    ret.push_back(t);
  }
  return ret;

}

} // namespace Utils
} // namespace Erpiko
#endif // _UTILS_H_
