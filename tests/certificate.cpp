#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include "erpiko/certificate.h"
#include "erpiko/data-source.h"
#include "erpiko/utils.h"
#include <iostream>

namespace Erpiko {

SCENARIO("Basic certificate test") {
  GIVEN("A new certificate") {
    Certificate* cert = new Certificate();
    THEN("There is nothing wrong") {
      REQUIRE_FALSE(cert == nullptr);
      delete(cert);
      cert = nullptr;
      REQUIRE(cert == nullptr);
    }
  }
}

SCENARIO("Import certificate from DER test") {
  GIVEN("A DER certificate") {
    DataSource* src = DataSource::fromFile("assets/crt1.der");
    THEN("The file is opened") {
      REQUIRE_FALSE(src == nullptr);
      auto v = src->readAll();
      Certificate* cert = Certificate::fromDer(v);
      delete(src);
      THEN("There is nothing wrong") {
        REQUIRE_FALSE(cert == nullptr);
        delete(cert);
        cert = nullptr;
        REQUIRE(cert == nullptr);
      }
    }
  }

  GIVEN("A DER certificate") {
    DataSource* src = DataSource::fromFile("assets/crt1.der");
    THEN("The file is opened") {
      REQUIRE_FALSE(src == nullptr);
      auto v = src->readAll();
      Certificate* cert = Certificate::fromDer(v);
      delete(src);
      THEN("There cert can be queried") {
        REQUIRE("160324131946Z" == cert->notAfter().toString());
        REQUIRE("150325131946Z" == cert->notBefore().toString());
        REQUIRE("1003" == cert->serialNumber().toHexString());
        const Identity& subjectIdentity = cert->subjectIdentity();
        const Identity& issuerIdentity = cert->issuerIdentity();

        REQUIRE(subjectIdentity.get("commonName") == "soda.id");
        REQUIRE(subjectIdentity.get("countryName") == "ID");
        REQUIRE(subjectIdentity.get("organizationalUnitName") == "Es Soda");
        REQUIRE(subjectIdentity.get("organizationName") == "Soda Susu");
        REQUIRE(subjectIdentity.get("stateOrProvinceName") == "Bogor");
        REQUIRE(subjectIdentity.get("emailAddress") == "info@soda.id");

        REQUIRE(issuerIdentity.get("commonName") == "sertifikat.id");
        REQUIRE(issuerIdentity.get("countryName") == "ID");
        REQUIRE(issuerIdentity.get("organizationalUnitName") == "Unit Penerbitan Sertifikat");
        REQUIRE(issuerIdentity.get("organizationName") == "Badan Otoritas Sertifikat Digital");
        REQUIRE(issuerIdentity.get("stateOrProvinceName") == "DKI Jakarta");
        REQUIRE(issuerIdentity.get("localityName") == "Jakarta Pusat");
        REQUIRE(issuerIdentity.get("emailAddress") == "cert@sertifikat.id");

        const std::vector<unsigned char>& ski = cert->subjectKeyIdentifier();
        auto s = Utils::hexString(ski);
//        REQUIRE(s == "1");

      }
    }
  }

}





} //namespace Erpiko
