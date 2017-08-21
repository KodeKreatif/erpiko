#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include "erpiko/certificate.h"
#include "erpiko/certificate-extension.h"
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

        int numExts = cert->extensions().size();
        REQUIRE(numExts > 0);
        int allExtsInspected = 0;
        for (int i = 0; i < numExts; i ++) {
          const CertificateExtension* ext = cert->extensions().at(i);
          if (ext->objectId().toString() == "2.5.29.14") {
            const CertificateSubjectKeyIdentifierExtension& skid = dynamic_cast<const CertificateSubjectKeyIdentifierExtension&>(*ext);
            auto s = Utils::hexString(skid.value());
            REQUIRE(s == "47da867838ffc5bd44428fb0e18ad051051b27c3");
            REQUIRE(skid.critical() == false);
            allExtsInspected++;
          }
          else if (ext->objectId().toString() == "2.5.29.19") {
            const CertificateBasicConstraintsExtension& skid = dynamic_cast<const CertificateBasicConstraintsExtension&>(*ext);
            REQUIRE(skid.isCa() == false);
            REQUIRE(skid.pathLengthConstraints() == 0);
            allExtsInspected++;
          }

        }
        REQUIRE(allExtsInspected == 1);

      }
    }
  }
}

SCENARIO("Get the CRL uri from cert") {
  GIVEN("A DER certificate with CRL distribution point") {
    DataSource* src = DataSource::fromFile("assets/cert-with-crl.der");
    THEN("The file is opened") {
      REQUIRE_FALSE(src == nullptr);
      auto v = src->readAll();
      Certificate* cert = Certificate::fromDer(v);
      std::string uri = cert->crlDistPoint();
      REQUIRE(uri == "http://ca.tnisiberlab.xyz/ejbca/publicweb/webdist/certdist?cmd=crl&issuer=CN=TNISiberLabCA,O=TNI%20Siber%20Lab,C=ID");
    }
  }
}

SCENARIO("Import certificate from PEM test") {
  GIVEN("A PEM certificate") {
    DataSource* src = DataSource::fromFile("assets/cert.pem");
    THEN("The file is opened") {
      REQUIRE_FALSE(src == nullptr);
      auto v = src->readAll();
      std::string pem(v.begin(),v.end());
      Certificate* cert = Certificate::fromPem(pem);
      delete(src);
      THEN("There is nothing wrong") {
        REQUIRE_FALSE(cert == nullptr);
        delete(cert);
        cert = nullptr;
        REQUIRE(cert == nullptr);
      }
    }
  }

  GIVEN("A PEM certificate") {
    DataSource* src = DataSource::fromFile("assets/cert.pem");
    THEN("The file is opened") {
      REQUIRE_FALSE(src == nullptr);
      auto v = src->readAll();
      std::string pem(v.begin(),v.end());
      Certificate* cert = Certificate::fromPem(pem);
      delete(src);
      THEN("There cert can be queried") {
        REQUIRE("170501012102Z" == cert->notAfter().toString());
        REQUIRE("160501012102Z" == cert->notBefore().toString());
        REQUIRE("F1B40E1F1590B6A4" == cert->serialNumber().toHexString());
        const Identity& subjectIdentity = cert->subjectIdentity();
        const Identity& issuerIdentity = cert->issuerIdentity();

        REQUIRE(subjectIdentity.get("commonName") == "www.endpoint.com");

        REQUIRE(issuerIdentity.get("commonName") == "www.endpoint.com");
      }
    }
  }
}

SCENARIO("Export certificate to DER test") {
  GIVEN("A DER certificate") {
    DataSource* src = DataSource::fromFile("assets/crt1.der");
    THEN("The file is opened") {
      REQUIRE_FALSE(src == nullptr);
      auto v = src->readAll();
      Certificate* cert = Certificate::fromDer(v);
      delete(src);
      THEN("Export it again to DER") {
        auto der = cert->toDer();
        REQUIRE(der.size() > 0);
        THEN("Import again") {
          auto cert2 = Certificate::fromDer(der);
          REQUIRE_FALSE(cert2 == nullptr);
          THEN("Both certs must be the same") {
            REQUIRE(cert2->serialNumber() == cert->serialNumber());
          }
        }
      }
    }
  }
}

SCENARIO("Export certificate to PEM test") {
  GIVEN("A new certificate") {
    DataSource* src = DataSource::fromFile("assets/crt1.der");
    REQUIRE_FALSE(src == nullptr);
    auto v = src->readAll();
    Certificate* cert = Certificate::fromDer(v);
    delete(src);
    THEN("Export to PEM") {
      REQUIRE_FALSE(cert == nullptr);
      auto pem = cert->toPem();
      THEN("Import again") {
        Certificate* cert = Certificate::fromPem(pem);
        REQUIRE_FALSE(cert == nullptr);
      }
    }
  }
}


} //namespace Erpiko
