#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include "erpiko/token.h"
#include "erpiko/rsakey.h"
#include "erpiko/utils.h"
#include "erpiko/digest.h"

#include <iostream>

using namespace std;
namespace Erpiko {

SCENARIO("Token init", "[.][p11]") {
  GIVEN("A token") {
    THEN("Token is initialized") {

      ObjectId o512(DigestConstants::SHA512);
      ObjectId o384(DigestConstants::SHA384);
      ObjectId o224(DigestConstants::SHA224);
      ObjectId o(DigestConstants::SHA256);

      std::string s = "data";

      Digest *d = Digest::get(o);
      std::vector<unsigned char> data(s.c_str(), s.c_str() + s.length());
      std::vector<unsigned char> empty;
      d->update(data);
      auto hash = d->finalize(empty);
      delete d;

      d = Digest::get(o224);
      d->update(data);
      auto hash224 = d->finalize(empty);
      delete d;

      d = Digest::get(o384);
      d->update(data);
      auto hash384 = d->finalize(empty);
      delete d;

      d = Digest::get(o512);
      d->update(data);
      auto hash512 = d->finalize(empty);
      delete d;





      int bits = 1024;
      RsaKey* k = RsaKey::create(bits);

      auto v = Utils::fromHexString("751965349686009581002736762779192355");
      auto enc = k->publicKey().encrypt(v);
      Token t;
      auto r = t.load("/home/mdamt/src/tmp/hsm/lib/softhsm/libsofthsm2.so");
      REQUIRE(r == true);
      r = t.login(933433059, "qwerty");
      REQUIRE(r == true);

      t.setKeyId(10, "erpik");
      k = RsaKey::create(1024);
      auto vec = k->toDer();
      REQUIRE(k->onDevice() == true);
      REQUIRE(vec.size() == 0);
      auto enc2 = k->publicKey().encrypt(v);
      auto enc3 = k->publicKey().encrypt(v);
      REQUIRE(enc2 != enc3);
      REQUIRE(enc2.size() == bits/8);

      auto dec3 = k->decrypt(enc2);
      REQUIRE(dec3 == v);

      auto signedData = k->sign(hash, o);
      REQUIRE(signedData.size() > 0);
      auto verified = k->publicKey().verify(signedData, hash, o);
      REQUIRE(verified == true);

      signedData = k->sign(hash224, o224);
      REQUIRE(signedData.size() > 0);
      verified = k->publicKey().verify(signedData, hash224, o224);
      REQUIRE(verified == true);

      signedData = k->sign(hash384, o384);
      REQUIRE(signedData.size() > 0);
      verified = k->publicKey().verify(signedData, hash384, o384);
      REQUIRE(verified == true);

      signedData = k->sign(hash512, o512);
      REQUIRE(signedData.size() > 0);
      verified = k->publicKey().verify(signedData, hash512, o512);
      REQUIRE(verified == true);




      REQUIRE(t.logout() == true);
      enc2 = k->publicKey().encrypt(v);
      REQUIRE(enc2.size() == 0);
    }
  }
}

} // namespace Erpiko
