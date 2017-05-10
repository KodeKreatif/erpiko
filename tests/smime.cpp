#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include "erpiko/signed-data.h"
#include "erpiko/enveloped-data.h"
#include "erpiko/data-source.h"
#include "erpiko/utils.h"
#include <iostream>

namespace Erpiko {

std::string r1;
std::string r2;

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
      r1 = smime;
      REQUIRE_FALSE(smime.empty());
      REQUIRE(smime.find("application/pkcs7-signature") > 0);
      REQUIRE(smime.find("smime.p7s") > 0);
      REQUIRE(smime.find("smime.p7m") == std::string::npos);
    }
  }
}

SCENARIO("Verifying") {
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
    SignedData* p7 = SignedData::fromSMime(r1, *cert);
    DataSource* data = DataSource::fromFile("assets/msg.txt");
    auto dataVector = data->readAll();
    THEN("Can verify S/MIME multipart signed message") {
        REQUIRE_FALSE(p7 == nullptr);
        REQUIRE(p7->isDetached() == true);
        REQUIRE(p7->verify() == true);
    }
  }
}

SCENARIO("Encrypting") {
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
    EnvelopedData* p7 = new EnvelopedData(*cert, ObjectId("1.2.840.113549.3.7"));
    DataSource* data = DataSource::fromFile("assets/msg.txt");
    auto dataVector = data->readAll();
    p7->encryptSMime(dataVector);
    THEN("Can produce S/MIME multipart signed message") {
      auto smime = p7->toSMime();
      r2 = smime;
      REQUIRE_FALSE(smime.empty());
      REQUIRE(smime.find("application/pkcs7-signature") > 0);
      REQUIRE(smime.find("smime.p7m") > 0);
      REQUIRE(smime.find("smime.p7s") == std::string::npos);
    }
  }
}

SCENARIO("Decrypting") {
  GIVEN("Certificate and private key and data") {
    auto srcCert = DataSource::fromFile("assets/cert.pem");
    auto v = srcCert->readAll();
    std::string pemCert(v.begin(),v.end());
    auto cert = Certificate::fromPem(pemCert);

    auto srcKey = DataSource::fromFile("assets/private.key");
    v = srcKey->readAll();
    std::string pemKey(v.begin(),v.end());
    auto key = RsaKey::fromPem(pemKey);

    DataSource* data = DataSource::fromFile("assets/msg.txt");
    auto dataVector = data->readAll();

    EnvelopedData* p7 = EnvelopedData::fromSMime(r2);
    auto decrypted = p7->decrypt(*cert, *key);
    std::string s((const char*)decrypted.data(), decrypted.size());
    THEN("Can be decrypted back") {
      REQUIRE(dataVector == decrypted);
    }
  }
}




} //namespace Erpiko
