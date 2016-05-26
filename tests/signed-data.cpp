#include "catch.hpp"

#include "erpiko/signed-data.h"
#include "erpiko/data-source.h"
#include "erpiko/utils.h"
#include <iostream>

namespace Erpiko {

SCENARIO("Import signed data from DER test") {
  GIVEN("A DER SignedData") {
    auto srcCert = DataSource::fromFile("assets/cert.pem");
    auto v = srcCert->readAll();
    std::string pemCert(v.begin(),v.end());
    auto cert = Certificate::fromPem(pemCert);

    auto srcKey = DataSource::fromFile("assets/private.key");
    v = srcKey->readAll();
    std::string pemKey(v.begin(),v.end());
    auto key = RsaKey::fromPem(pemKey);

    DataSource* src = DataSource::fromFile("assets/data.txt.signed");

    THEN("The file is opened") {
      REQUIRE_FALSE(src == nullptr);
      auto v = src->readAll();
      SignedData* p7 = SignedData::fromDer(v, *cert);
      delete(src);
      THEN("There is nothing wrong") {
        REQUIRE_FALSE(p7 == nullptr);
        delete(p7);
        p7 = nullptr;
        REQUIRE(p7 == nullptr);
      }
    }
  }


  GIVEN("A DER SignedData") {
    auto srcCert = DataSource::fromFile("assets/cert.pem");
    auto v = srcCert->readAll();
    std::string pemCert(v.begin(),v.end());
    auto cert = Certificate::fromPem(pemCert);

    DataSource* src = DataSource::fromFile("assets/data.txt.signed");

    THEN("The file is opened") {
      REQUIRE_FALSE(src == nullptr);
      auto v = src->readAll();
      SignedData* p7 = SignedData::fromDer(v, *cert);
      DataSource* data = DataSource::fromFile("assets/data.txt");
      auto dataVector = data->readAll();
      p7->update(dataVector);
      delete(src);
      THEN("Basic info is checked") {
        REQUIRE(p7->isDetached() == true);
        REQUIRE(p7->verify() == true);
      }
    }
  }

}

SCENARIO("Construct SignedData") {
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

    THEN("Create the Signed Data") {
      REQUIRE_FALSE(src == nullptr);
      auto v = src->readAll();
      SignedData* p7 = new SignedData(*cert, *key);
      DataSource* data = DataSource::fromFile("assets/data.txt");
      auto dataVector = data->readAll();
      p7->update(dataVector);
      p7->signDetached();
      auto der = p7->toDer();
      THEN("And can be verified") {
        SignedData* p7v = SignedData::fromDer(der, *cert);
        p7v->update(dataVector);
        REQUIRE(p7v->isDetached() == true);
        REQUIRE(p7v->verify() == true);
      }
    }
  }


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


    THEN("Create the detached Signed Data") {
      REQUIRE_FALSE(src == nullptr);
      auto v = src->readAll();
      SignedData* p7 = new SignedData(*cert, *key);
      DataSource* data = DataSource::fromFile("assets/data.txt");
      auto dataVector = data->readAll();
      p7->update(dataVector);
      p7->signDetached();
      auto der = p7->toDer();
      THEN("And can be verified") {
        SignedData* p7v = SignedData::fromDer(der, *cert);
        p7v->update(dataVector);
        REQUIRE(p7v->isDetached() == true);
        REQUIRE(p7v->verify() == true);
      }
    }

  }
}


SCENARIO("Export SignedData to PEM") {
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

    THEN("Create the Signed Data") {
      REQUIRE_FALSE(src == nullptr);
      auto v = src->readAll();
      SignedData* p7 = new SignedData(*cert, *key);
      DataSource* data = DataSource::fromFile("assets/data.txt");
      auto dataVector = data->readAll();
      p7->update(dataVector);
      p7->signDetached();
      auto pem = p7->toPem();
      THEN("And can be verified") {
        SignedData* p7v = SignedData::fromPem(pem, *cert);
        p7v->update(dataVector);
        REQUIRE(p7v->isDetached() == true);
        REQUIRE(p7v->verify() == true);
      }
    }
  }
}



} //namespace Erpiko
