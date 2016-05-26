#include "catch.hpp"

#include "erpiko/sim.h"
#include "erpiko/oid.h"
#include "erpiko/data-source.h"
#include "erpiko/utils.h"
#include <iostream>

namespace Erpiko {

SCENARIO("SIM") {
  GIVEN("siiType, sii, password, and authorityRandom") {
    ObjectId hash("2.16.840.1.101.3.4.2.1");
    ObjectId siiType("1.2.3.4.5");
    std::string sii("12345");
    std::string password("abcde12345");
    std::vector<unsigned char> r = {
      1, 2, 3, 4, 5, 6, 7, 8,
      1, 2, 3, 4, 5, 6, 7, 8,
      1, 2, 3, 4, 5, 6, 7, 8,
      1, 2, 3, 4, 5, 6, 7, 8 };

    Sim sim(hash, siiType, sii, password, r);
    THEN("SIM object is properly created") {
      REQUIRE(sim.isValid() == true);
      REQUIRE(Utils::hexString(sim.epepsi()) == "306006042a0304050c0531323334353051300b060960864801650304020104200102030405060708010203040506070801020304050607080102030405060708042060ac15b03093cc7e95d2083841b2cfb11dfca15a8d9d440771105bd047301bc3");
      REQUIRE(Utils::hexString(sim.toDer()) == "3051300b060960864801650304020104200102030405060708010203040506070801020304050607080102030405060708042060ac15b03093cc7e95d2083841b2cfb11dfca15a8d9d440771105bd047301bc3");
      REQUIRE(Utils::hexString(sim.pepsi()) == "60ac15b03093cc7e95d2083841b2cfb11dfca15a8d9d440771105bd047301bc3");
    }
  }

  GIVEN("siiType, sii, password, and authorityRandom") {
    ObjectId hash("2.16.840.1.101.3.4.2.1");
    ObjectId siiType("1.2.3.4.5");
    std::string sii("12345");
    std::string password("abcde12345");
    std::vector<unsigned char> r = {
      1, 2, 3, 4, 5, 6, 7, 8,
      1, 2, 3, 4, 5, 6, 7, 8,
      1, 2, 3, 4, 5, 6, 7, 8,
      1, 2, 3, 4, 5, 6, 7, 8 };

    THEN("A dynamic SIM object is properly created") {
      Sim* sim = new Sim(hash, siiType, sii, password, r);
      REQUIRE(sim->isValid() == true);
      delete sim;
      sim = nullptr;
      REQUIRE(sim == nullptr);
    }
  }



}


} //namespace Erpiko
