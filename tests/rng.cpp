#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include <iostream>
#include "erpiko/rng.h"
#include "erpiko/utils.h"

namespace Erpiko {

SCENARIO("RNG 1") {
  GIVEN("Seed") {
    Rng rng;

    std::string s = "this is seed";
    int fulfilled = 0;
    rng.onEntropyFulfilled([&fulfilled]() -> void{
      fulfilled = 1;
    });
    rng.seed(s.data(), s.length());
    THEN("Entropy is fulfilled") {
      REQUIRE(fulfilled == 1);
    }
  }
}

SCENARIO("RNG 2") {
  GIVEN("Seed") {
    Rng rng;

    std::string s = "this is seed";
    int fulfilled = 0;
    rng.seed(s.data(), s.length());
    std::vector<std::vector<unsigned char>> r;
#define MAX_R 10000
    THEN("random bytes are generated") {
      for (auto i = 0; i < MAX_R; i ++) {
        auto r1 = rng.random(100);
        REQUIRE(r1.size() == 100);
        r.push_back(r1);
      }
      REQUIRE(r.size() == MAX_R);
      int found = 0;
      for (auto i = 0; i < MAX_R; i ++) {
        for (auto j = 0; j < MAX_R; j ++) {
          if (r[i] == r[j] && i != j) {
            found ++;
          }
        }
      }
      REQUIRE(found == 0);
    }
  }
}


} // namespace Erpiko
