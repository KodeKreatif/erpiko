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

    auto srcCert1 = DataSource::fromFile("assets/certx1.pem");
    v = srcCert1->readAll();
    std::string pemCert1(v.begin(),v.end());
    auto cert1 = Certificate::fromPem(pemCert1);

    auto srcKey1 = DataSource::fromFile("assets/keyx1.pem");
    v = srcKey1->readAll();
    std::string pemKey1(v.begin(),v.end());
    auto key1 = RsaKey::fromPem(pemKey1);

    auto srcCert2 = DataSource::fromFile("assets/certx2.pem");
    v = srcCert2->readAll();
    std::string pemCert2(v.begin(),v.end());
    auto cert2 = Certificate::fromPem(pemCert2);

    auto srcKey2 = DataSource::fromFile("assets/keyx2.pem");
    v = srcKey2->readAll();
    std::string pemKey2(v.begin(),v.end());
    auto key2 = RsaKey::fromPem(pemKey2);

    auto srcCert3 = DataSource::fromFile("assets/certx3.pem");
    v = srcCert3->readAll();
    std::string pemCert3(v.begin(),v.end());
    auto cert3 = Certificate::fromPem(pemCert3);

    auto srcKey3 = DataSource::fromFile("assets/keyx3.pem");
    v = srcKey3->readAll();
    std::string pemKey3(v.begin(),v.end());
    auto key3 = RsaKey::fromPem(pemKey3);

    DataSource* src = DataSource::fromFile("assets/data.txt");

    THEN("Create the EnvelopedData") {
      REQUIRE_FALSE(src == nullptr);
      auto v = src->readAll();
      EnvelopedData* p7 = new EnvelopedData(*cert, ObjectId("2.16.840.1.101.3.4.1.42"));
      DataSource* data = DataSource::fromFile("assets/data.txt");
      auto dataVector = data->readAll();
      p7->addRecipient(*cert1);
      p7->addRecipient(*cert2);
      p7->addRecipient(*cert3);
      p7->encrypt(dataVector);
      auto der = p7->toDer();
      THEN("And can be decrypted by each recipient") {
        EnvelopedData* p7v = EnvelopedData::fromDer(der);
        auto data = p7v->decrypt(*cert, *key);
        REQUIRE(v == data);
        data.clear();


        EnvelopedData* p7v1 = EnvelopedData::fromDer(der);
        data = p7v1->decrypt(*cert1, *key1);
        REQUIRE(v == data);
        data.clear();

        EnvelopedData* p7v2 = EnvelopedData::fromDer(der);
        data = p7v2->decrypt(*cert2, *key2);
        REQUIRE(v == data);
        data.clear();

        EnvelopedData* p7v3 = EnvelopedData::fromDer(der);
        data = p7v3->decrypt(*cert3, *key3);
        REQUIRE(v == data);
      }
    }
  }
}

// TODO: test for importing data from DER

} //namespace Erpiko
