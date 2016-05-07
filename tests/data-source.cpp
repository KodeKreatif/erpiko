#include "catch.hpp"

#include "erpiko/data-source.h"
#include "erpiko/utils.h"

namespace Erpiko {
SCENARIO("Basic vector test") {
  GIVEN("A new data source from vector") {
    std::vector<unsigned char> v;
    DataSource* src = DataSource::fromVector(v);
    THEN("There is nothing wrong") {
      REQUIRE_FALSE(src == nullptr);
      delete(src);
      src = nullptr;
      REQUIRE(src == nullptr);
    }
  }

  GIVEN("A new data source from vector") {
    std::vector<unsigned char> v;
    for (int i = 0; i < 120; i ++) {
      char c = (char) i;
      v.push_back(c);
    }
    DataSource* src = DataSource::fromVector(v);
    THEN("Data should be populated correctly") {
      auto vResult = src->readAll();
      REQUIRE(Utils::hexString(vResult) == Utils::hexString(v));
    }
  }

  GIVEN("A new data source from vector") {
    DataSource* src = DataSource::fromFile("assets/random1");
    THEN("Data should be populated correctly") {
      std::string s = "0c32328ce420ea18656ea078c581134fb40267f9d6a75a4e3cb1ee97ec0450482627e5a9120885254a641041b778950fa6866db41d0227dd414acf6b45f82477a24cfb119fe995b88f232968b24eaf3fb7dbdea564a70cbae16c0ca975506af117a47e96e61afa13bad3ef67b3d67416e3880ccb8498337cdf76d5a2721795f4ab3b6031bb0df70fa0f7f44dc1fc0c85fb1f7352c73498f5777b0acd659bb3c9969c812852879b7c78badf7cdf7b68d9df27a7adeffbb1e0275d926e7945d117";
      auto vResult = src->readAll();
      REQUIRE(Utils::hexString(vResult) == s);
    }
  }
}

} //namespace Erpiko
