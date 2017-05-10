#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include "erpiko/signed-data.h"
#include "erpiko/data-source.h"
#include "erpiko/utils.h"
#include <iostream>

namespace Erpiko {

SCENARIO("Signing") {
  GIVEN("Certificate and private key and data") {
    auto srcCert = DataSource::fromFile("assets/cert.pem");
    auto v = srcCert->readAll();
    std::string pemCert(v.begin(),v.end());
    auto cert = Certificate::fromPem(pemCert);

    auto srcKey = DataSource::fromFile("assets/private.key");
    v = srcKey->readAll();
    std::string pemKey(v.begin(),v.end());
    auto key = RsaKey::fromPem(pemKey);

    DataSource* src = DataSource::fromFile("assets/msg.txt");

    v = src->readAll();
    SignedData* p7 = new SignedData(*cert, *key);
    DataSource* data = DataSource::fromFile("assets/msg.txt");
    auto dataVector = data->readAll();
    p7->signSMime();
    p7->update(dataVector);
    THEN("Can produce S/MIME multipart signed message") {
      auto smime = p7->toSMime();
      REQUIRE_FALSE(smime.empty());
      REQUIRE(smime.find("application/pkcs7-signature") > 0);
      REQUIRE(smime.find("smime.p7s") > 0);
      REQUIRE(smime.find("smime.p7m") == std::string::npos);
    }
  }
}




} //namespace Erpiko
