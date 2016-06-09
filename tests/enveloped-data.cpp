#include "catch.hpp"

#include "erpiko/enveloped-data.h"
#include "erpiko/data-source.h"
#include "erpiko/utils.h"
#include <iostream>

namespace Erpiko {

SCENARIO("Construct EnvelopedData") {
  GIVEN("Certificate and private key and data") {
    auto srcCert = DataSource::fromFile("assets/cert.pem");
    auto v = srcCert->readAll();
    std::string pemCert(v.begin(),v.end());
    auto cert = Certificate::fromPem(pemCert);

    auto srcKey = DataSource::fromFile("assets/private.key");
    v = srcKey->readAll();
    std::string pemKey(v.begin(),v.end());
    auto key = RsaKey::fromPem(pemKey);

    DataSource* src = DataSource::fromFile("assets/data.txt");

    THEN("Create the EnvelopedData") {
      REQUIRE_FALSE(src == nullptr);
      auto v = src->readAll();
      EnvelopedData* p7 = new EnvelopedData(*cert, ObjectId("2.16.840.1.101.3.4.1.42"));
      DataSource* data = DataSource::fromFile("assets/data.txt");
      auto dataVector = data->readAll();
      p7->encrypt(dataVector);
      auto der = p7->toDer();
      THEN("And can be decrypted") {
        EnvelopedData* p7v = EnvelopedData::fromDer(der);
        auto data = p7v->decrypt(*cert, *key);
        REQUIRE(v == data);
      }
    }
  }
}

// TODO: test for importing data from DER

} //namespace Erpiko
