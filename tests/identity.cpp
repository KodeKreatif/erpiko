#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include "erpiko/identity.h"

namespace Erpiko {

SCENARIO("Basic identity test") {
  GIVEN("A new Identity") {
    Identity* cert = new Identity();
  }
}

} //namespace Erpiko
