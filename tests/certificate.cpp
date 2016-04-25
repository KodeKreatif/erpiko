#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include "erpiko/certificate.h"

namespace Erpiko {

SCENARIO("Basic certificate test") {
  GIVEN("A new certificate") {
    Certificate* cert = new Certificate();
  }
}

} //namespace Erpiko
