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
        REQUIRE(Utils::hexString(p7->digest(0)) == "97b1b133ecafe89f63668813072034ceaf4bb2d6de03b69b6fd6e3af3f76a08a90beef7dc5b8f3493f6ea40fbe7f4622c8ee367c85cf5dc8dcb31fd321e413d8c3de537617342d6012eaa5c33942d266d53a74dd8ed5e0750541aebdd5e477f9248f0b3517dfabbcadd9a4958fc8b43207899829737ead944e733e7e50a9a5441471a9682a76711fb9bce9887a0a5f3d42d46e129f9ebfa3c2c2fba7b5202d8422fc627900b07c1fe95ef518833a15e1463bf703f4af35b11ad020c7aaff33e96dc5348f0e2b90a0941d87a87fc2e0edfc4ceb208263176e05f2e9fd8eba734d88a28501ef0297c7d39a0d82690f7d045d3871238e600609735a481284097b3f2532d96d256283f8442219f2fa49b1cd935f7407f6a2f40f18aa9a9231868ceeb6875b07d0c65261b1a0857983b94f2e756e65bc51e56156ee59871fc3940daa5c34ca40c394e951ff467a4c6d583df26d091694cc15e032e427c84678bde708368c8161bd166b20e27ff2d40c7112f572262f900c33aaeb18ec71cef6f39c0d7387e262a27790d1665029ad3723070aad56cc1491141c12e3cdec8b0f71e0cc48cbbf2a8e1e3d41973fa1d1f4623ad3a3516271dba41f8820011537b15324f441b93805e7f6debf1ca283e29a07be51b49f2b74cc2d2e3c573875acc827fd083fad84f64c1b9aa5a4f6a98e64bacc17467f3adfa07a0ccee4193e5b35e6f272");
        REQUIRE(Utils::hexString(p7->digest(1)) == "");
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
    THEN("Create an Attached Signed Data") {
      REQUIRE_FALSE(src == nullptr);
      auto v = src->readAll();
      SignedData* p7 = new SignedData(*cert, *key);
      DataSource* data = DataSource::fromFile("assets/data.txt");
      auto dataVector = data->readAll();
      p7->update(dataVector);
      p7->sign();
      auto der = p7->toDer();
      THEN("And can be verified") {
        SignedData* p7v = SignedData::fromDer(der, *cert);
        REQUIRE(p7v->isDetached() == false);
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
        REQUIRE(p7v->isDetached() == true);
        p7v->update(dataVector);
        REQUIRE(p7v->verify() == true);
      }
    }
  }
}

SCENARIO("Get the signer's serial number") {
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
      p7->sign();
      THEN("And the signer serial number can be fetched") {
        auto der = p7->toDer();
        auto signers = p7->getSignerSerialNumbers();
        REQUIRE(signers.size() == 1);
        REQUIRE(cert->serialNumber().toHexString() == signers.at(0));
      }
    }
  }
}

SCENARIO("Read DER without certificate") {
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
      p7->sign();
      THEN("And reread the der") {
        auto der = p7->toDer();
        auto p7a = SignedData::fromDer(der);
        // Reread again
        auto der2 = p7a->toDer();
        auto p7b = SignedData::fromDer(der2);
        auto signers = p7b->getSignerSerialNumbers();
        REQUIRE(signers.size() == 1);
        REQUIRE(cert->serialNumber().toHexString() == signers.at(0));
        REQUIRE(p7b->verify() == true);
      }
    }
  }
}

} //namespace Erpiko
