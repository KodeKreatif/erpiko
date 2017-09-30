#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include <iostream>
#include "erpiko/oid.h"
#include "erpiko/digest.h"
#include "erpiko/utils.h"

namespace Erpiko {

SCENARIO("Digest") {
  GIVEN("Object Id") {
    ObjectId o(DigestConstants::SHA1);
    Digest *d = Digest::get(o);

    REQUIRE(d != nullptr);
    delete d;
    REQUIRE("not-crashed-here" == std::string("not-crashed-here"));
  }
}

SCENARIO("Digest with update") {
  GIVEN("SHA1") {
    ObjectId o(DigestConstants::SHA1);
    Digest *d = Digest::get(o);

    std::vector<unsigned char>data = { 0x61, 0x62, 0x63 };
    std::vector<unsigned char>empty;
    d->update(data);
    auto ret = d->finalize(empty);
    REQUIRE(Utils::hexString(ret) == "a9993e364706816aba3e25717850c26c9cd0d89d");
    delete d;
    REQUIRE("not-crashed-here" == std::string("not-crashed-here"));
  }

  GIVEN("SHA224") {
    ObjectId o(DigestConstants::SHA224);
    Digest *d = Digest::get(o);

    std::vector<unsigned char>data = { 0x61, 0x62, 0x63 };
    std::vector<unsigned char>empty;
    d->update(data);
    auto ret = d->finalize(empty);
    REQUIRE(Utils::hexString(ret) == "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
    delete d;
    REQUIRE("not-crashed-here" == std::string("not-crashed-here"));
  }

  GIVEN("SHA256") {
    ObjectId o(DigestConstants::SHA256);
    Digest *d = Digest::get(o);

    std::vector<unsigned char>data = { 0x61, 0x62, 0x63 };
    std::vector<unsigned char>empty;
    d->update(data);
    auto ret = d->finalize(empty);
    REQUIRE(Utils::hexString(ret) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    delete d;
    REQUIRE("not-crashed-here" == std::string("not-crashed-here"));
  }

  GIVEN("SHA384") {
    ObjectId o(DigestConstants::SHA384);
    Digest *d = Digest::get(o);

    std::vector<unsigned char>data = { 0x61, 0x62, 0x63 };
    std::vector<unsigned char>empty;
    d->update(data);
    auto ret = d->finalize(empty);
    REQUIRE(Utils::hexString(ret) == "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
    delete d;
    REQUIRE("not-crashed-here" == std::string("not-crashed-here"));
  }

  GIVEN("SHA512") {
    ObjectId o(DigestConstants::SHA512);
    Digest *d = Digest::get(o);

    std::vector<unsigned char>data = { 0x61, 0x62, 0x63 };
    std::vector<unsigned char>empty;
    d->update(data);
    auto ret = d->finalize(empty);
    REQUIRE(Utils::hexString(ret) == "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    delete d;
    REQUIRE("not-crashed-here" == std::string("not-crashed-here"));
  }
}
} // namespace Erpiko
