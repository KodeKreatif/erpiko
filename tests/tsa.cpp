#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include "erpiko/tsa.h"
#include "erpiko/oid.h"
#include "erpiko/data-source.h"
#include "erpiko/utils.h"
#include <iostream>

namespace Erpiko {

SCENARIO("TsaRequest default values") {
  GIVEN("TsaRequest object") {
    ObjectId o("1.2.3.4");
    TsaRequest t(o);
    TsaRequest* t2 = new TsaRequest(o);
    THEN("default values must be valid") {
      REQUIRE(t.includeCertificate() == false);
      REQUIRE(t.noNonce() == false);
      REQUIRE(t.policyId().toString() == "0.0.0.0");

      ObjectId o1("1.2.3.4");
      t2->setIncludeCertificate(true);
      t2->setNoNonce(true);
      t2->setPolicyId(o1);
      REQUIRE(t2->includeCertificate() == true);
      REQUIRE(t2->noNonce() == true);
      REQUIRE(t2->policyId().toString() == "1.2.3.4");
      std::string reached("not reached");
      // make sure t2 is deletable and last line is reached
      delete(t2);
      reached = "reached";
      REQUIRE("reached" == reached);
    }
  }
}

SCENARIO("TsaRequest DER test") {
  GIVEN("TsaRequest object") {
    ObjectId o("2.16.840.1.101.3.4.2.1");
    TsaRequest t(o);
    THEN("default values must be valid") {
      std::vector<unsigned char> data = { 1, 2, 3, 4};
      t.update(data);
      t.setPolicyId(o);
      t.setIncludeCertificate(true);
      auto x = t.toDer();

      auto t2 = TsaRequest::fromDer(x);
      REQUIRE(t2->hashAlgorithm().toString() == t.hashAlgorithm().toString());
      REQUIRE(t2->policyId().toString() == t.policyId().toString());
      REQUIRE(t2->nonceValue() == t.nonceValue());
      REQUIRE(t2->digest() == t.digest());
      REQUIRE(t2->includeCertificate() == t.includeCertificate());
      REQUIRE(t2->toDer() == x);
    }
  }
}

SCENARIO("TsaRequest fed to TsaResponse test") {
  GIVEN("TsaRequest object") {
    ObjectId o("1.3.14.3.2.26");
    TsaRequest t(o);
    THEN("can be fed to TsaResponse") {
      std::vector<unsigned char> data = { 1, 2, 3, 4};
      t.update(data);
      t.setNoNonce(true);
      t.setIncludeCertificate(true);
      auto x = t.toDer();

      auto srcCert = DataSource::fromFile("assets/cert-ts.pem");
      auto v = srcCert->readAll();
      std::string pemCert(v.begin(),v.end());
      auto cert = Certificate::fromPem(pemCert);

      auto srcKey = DataSource::fromFile("assets/key-ts.pem");
      v = srcKey->readAll();
      std::string pemKey(v.begin(),v.end());
      auto key = RsaKey::fromPem(pemKey);

      TsaResponse r(*cert, *key, x);
      auto resp = r.toDer();
      REQUIRE(r.status() == TsaResponseStatus::SUCCESS);
      REQUIRE(resp.size() > 0);
      REQUIRE(r.pkiStatusInfo() == PkiStatus::GRANTED);

    }
  }
}

SCENARIO("TsaRequest with invalid cert type") {
  GIVEN("TsaRequest object") {
    ObjectId o("1.3.14.3.2.26");
    TsaRequest t(o);
    THEN("can be fed to TsaResponse") {
      std::vector<unsigned char> data = { 1, 2, 3, 4};
      t.update(data);
      t.setNoNonce(true);
      t.setIncludeCertificate(true);
      auto x = t.toDer();

      auto srcCert = DataSource::fromFile("assets/certx1.pem");
      auto v = srcCert->readAll();
      std::string pemCert(v.begin(),v.end());
      auto cert = Certificate::fromPem(pemCert);

      auto srcKey = DataSource::fromFile("assets/keyx1.pem");
      v = srcKey->readAll();
      std::string pemKey(v.begin(),v.end());
      auto key = RsaKey::fromPem(pemKey);

      TsaResponse r(*cert, *key, x);
      auto resp = r.toDer();
      REQUIRE(r.status() == TsaResponseStatus::INVALID_CERT);
      REQUIRE(r.pkiStatusInfo() == PkiStatus::UNKNOWN);

    }
  }
}

SCENARIO("TsaRequest with invalid algo") {
  GIVEN("TsaRequest object") {
    ObjectId o("1.2.840.113549.2.5"); // md5
    TsaRequest t(o);
    THEN("can be fed to TsaResponse") {
      std::vector<unsigned char> data = { 1, 2, 3, 4};
      t.update(data);
      t.setNoNonce(true);
      t.setIncludeCertificate(true);
      auto x = t.toDer();

      auto srcCert = DataSource::fromFile("assets/cert-ts.pem");
      auto v = srcCert->readAll();
      std::string pemCert(v.begin(),v.end());
      auto cert = Certificate::fromPem(pemCert);

      auto srcKey = DataSource::fromFile("assets/key-ts.pem");
      v = srcKey->readAll();
      std::string pemKey(v.begin(),v.end());
      auto key = RsaKey::fromPem(pemKey);

      TsaResponse r(*cert, *key, x);
      auto resp = r.toDer();
      REQUIRE(r.pkiStatusInfo() == PkiStatus::REJECTION);
      REQUIRE(r.pkiFailureInfo() == PkiFailureInfo::BAD_ALGORITHM);
    }
  }
}

SCENARIO("TsaRequest with invalid policy") {
  GIVEN("TsaRequest object") {
    ObjectId o("1.3.14.3.2.26");
    TsaRequest t(o);
    THEN("can be fed to TsaResponse") {
      std::vector<unsigned char> data = { 1, 2, 3, 4};
      t.update(data);
      t.setNoNonce(true);
      t.setIncludeCertificate(true);
      t.setPolicyId(o);
      auto x = t.toDer();

      auto srcCert = DataSource::fromFile("assets/cert-ts.pem");
      auto v = srcCert->readAll();
      std::string pemCert(v.begin(),v.end());
      auto cert = Certificate::fromPem(pemCert);

      auto srcKey = DataSource::fromFile("assets/key-ts.pem");
      v = srcKey->readAll();
      std::string pemKey(v.begin(),v.end());
      auto key = RsaKey::fromPem(pemKey);

      TsaResponse r(*cert, *key, x);
      auto resp = r.toDer();
      REQUIRE(r.pkiStatusInfo() == PkiStatus::REJECTION);
      REQUIRE(r.pkiFailureInfo() == PkiFailureInfo::UNACCEPTED_POLICY);

    }
  }
}


SCENARIO("TsaRequest with invalid request") {
  GIVEN("TsaRequest object") {
    std::vector<unsigned char> x = { 1, 2, 3, 4};
    THEN("can be fed to TsaResponse") {

      auto srcCert = DataSource::fromFile("assets/cert-ts.pem");
      auto v = srcCert->readAll();
      std::string pemCert(v.begin(),v.end());
      auto cert = Certificate::fromPem(pemCert);

      auto srcKey = DataSource::fromFile("assets/key-ts.pem");
      v = srcKey->readAll();
      std::string pemKey(v.begin(),v.end());
      auto key = RsaKey::fromPem(pemKey);

      TsaResponse r(*cert, *key, x);
      auto resp = r.toDer();
      REQUIRE(r.pkiStatusInfo() == PkiStatus::REJECTION);
      REQUIRE(r.pkiFailureInfo() == PkiFailureInfo::BAD_DATA_FORMAT);
    }
  }
}

SCENARIO("TsaRequest with custom serial number generator") {
  GIVEN("TsaRequest object") {
    ObjectId o("1.3.14.3.2.26");
    TsaRequest t(o);
    THEN("can be fed to TsaResponse") {
      std::vector<unsigned char> data = { 1, 2, 3, 4};
      t.update(data);
      t.setNoNonce(true);
      t.setIncludeCertificate(true);
      auto x = t.toDer();

      auto srcCert = DataSource::fromFile("assets/cert-ts.pem");
      auto v = srcCert->readAll();
      std::string pemCert(v.begin(),v.end());
      auto cert = Certificate::fromPem(pemCert);

      auto srcKey = DataSource::fromFile("assets/key-ts.pem");
      v = srcKey->readAll();
      std::string pemKey(v.begin(),v.end());
      auto key = RsaKey::fromPem(pemKey);

      TsaResponse r(*cert, *key, x);
      r.setSerialNumberGenerator([]()->long{
          return 1999;
          });
      auto resp = r.toDer();
      REQUIRE(r.serialNumber() == 1999);
      REQUIRE(r.pkiStatusInfo() == PkiStatus::GRANTED);
    }
  }
}

SCENARIO("TsaRequest can be verified") {
  GIVEN("TsaRequest object") {
    ObjectId o("1.3.14.3.2.26");
    TsaRequest t(o);
    THEN("can be fed to TsaResponse then verified") {
      std::vector<unsigned char> data = { 1, 2, 3, 4};
      t.update(data);
      t.setIncludeCertificate(true);
      auto x = t.toDer();

      auto srcCert = DataSource::fromFile("assets/cert-ts.pem");
      auto v = srcCert->readAll();
      std::string pemCert(v.begin(),v.end());
      auto cert = Certificate::fromPem(pemCert);

      auto srcKey = DataSource::fromFile("assets/key-ts.pem");
      v = srcKey->readAll();
      std::string pemKey(v.begin(),v.end());
      auto key = RsaKey::fromPem(pemKey);

      TsaResponse r(*cert, *key, x);
      r.setSerialNumberGenerator([]()->long{
          return 1999;
          });
      auto resp = r.toDer();

      auto r2 = TsaResponse::fromDer(resp, x);
      REQUIRE(r2->serialNumber() == 1999);
      REQUIRE(r2->pkiStatusInfo() == PkiStatus::GRANTED);

      REQUIRE(r2->verifyToken(*cert, "assets/chain-ts.pem") == TsaVerificationStatus::VERIFIED);
    }
  }
}

SCENARIO("TsaRequest without nonce can be verified ") {
  GIVEN("TsaRequest object") {
    ObjectId o("1.3.14.3.2.26");
    TsaRequest t(o);
    THEN("can be fed to TsaResponse then verified") {
      std::vector<unsigned char> data = { 1, 2, 3, 4};
      t.update(data);
      t.setNoNonce(true);
      t.setIncludeCertificate(true);
      auto x = t.toDer();

      auto srcCert = DataSource::fromFile("assets/cert-ts.pem");
      auto v = srcCert->readAll();
      std::string pemCert(v.begin(),v.end());
      auto cert = Certificate::fromPem(pemCert);

      auto srcKey = DataSource::fromFile("assets/key-ts.pem");
      v = srcKey->readAll();
      std::string pemKey(v.begin(),v.end());
      auto key = RsaKey::fromPem(pemKey);

      TsaResponse r(*cert, *key, x);
      r.setSerialNumberGenerator([]()->long{
          return 1999;
          });
      auto resp = r.toDer();

      auto r2 = TsaResponse::fromDer(resp, x);
      REQUIRE(r2->serialNumber() == 1999);
      REQUIRE(r2->pkiStatusInfo() == PkiStatus::GRANTED);

      REQUIRE(r2->verifyToken(*cert, "assets/chain-ts.pem") == TsaVerificationStatus::VERIFIED);
    }
  }
}





} // namespace Erpiko
