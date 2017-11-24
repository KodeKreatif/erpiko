#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include "erpiko/certificate.h"
#include "erpiko/certificate-extension.h"
#include "erpiko/certificate-request.h"
#include "erpiko/data-source.h"
#include "erpiko/utils.h"
#include "erpiko/rsakey.h"
#include "erpiko/oid.h"
#include "erpiko/digest.h"
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

SCENARIO("Generate a PKCS10 test") {
  GIVEN("A key, an identity and an algo") {

    ObjectId o(RsaAlgorithmConstants::RSA_SHA256);
    auto srcKey = DataSource::fromFile("assets/keyx1.pem");
    auto v = srcKey->readAll();
    std::string pemKey(v.begin(),v.end());
    auto key = RsaKey::fromPem(pemKey);

    ObjectId ox(DigestConstants::SHA256);
    Digest *d = Digest::get(ox);
    std::string s = "data";
    std::vector<unsigned char> data(s.c_str(), s.c_str() + s.length());
    std::vector<unsigned char> empty;
    d->update(data);
    auto hash = d->finalize(empty);

    auto sign = key->sign(hash, ox);

    Identity id;
    id.set("commonName", "omama");

    THEN("Can produce a CertificateRequest") {
      CertificateRequest* req = new CertificateRequest(id, *key, o);
      REQUIRE(req->isValid());
      const RsaPublicKey& pkey = req->publicKey();
      REQUIRE(id == req->subject());
      REQUIRE(pkey.verify(sign, hash, o) == true);

      CertificateRequest* req2 = CertificateRequest::fromDer(req->toDer());
      REQUIRE(req2->isValid());
      const RsaPublicKey& pkey2 = req2->publicKey();
      REQUIRE(id == req2->subject());
      REQUIRE(pkey2.verify(sign, hash, o) == true);

      delete(req);
      delete(req2);

    }
  }

  GIVEN("A key, an identity and an algo") {

    ObjectId o(RsaAlgorithmConstants::RSA_SHA256);
    auto srcKey = DataSource::fromFile("assets/keyx1.pem");
    auto v = srcKey->readAll();
    std::string pemKey(v.begin(),v.end());
    auto key = RsaKey::fromPem(pemKey);

    Identity id;
    id.set("commonName", "omama");

    THEN("Can produce a CertificateRequest and the PEM can be read back") {
      CertificateRequest* req = new CertificateRequest(id, *key, o);
      REQUIRE(req->isValid());

      auto req2 = CertificateRequest::fromPem(req->toPem());
      REQUIRE(req2 != nullptr);
      REQUIRE(req2->isValid());
      REQUIRE(req->subject() == req2->subject());

      delete(req);

    }

    THEN("Can produce a CertificateRequest and the DER can be read back") {
      CertificateRequest* req = new CertificateRequest(id, *key, o);
      REQUIRE(req->isValid());

      auto req2 = CertificateRequest::fromDer(req->toDer());
      REQUIRE(req2 != nullptr);
      REQUIRE(req2->isValid());
      REQUIRE(req->subject() == req2->subject());

      delete(req);

    }

  }

}

SCENARIO("Writing to certificate test") {
  GIVEN("A new certificate") {
    Certificate* cert = new Certificate();
    Time start("800212215620Z");
    Time end("800212215622Z");
    Identity subject;
    subject.set("commonName", "omama");
    Identity issuer;
    issuer.set("commonName", "olala");
    BigInt sn(123);
    RsaKey* pair = RsaKey::create(1024);

    THEN("can create a cert") {
      auto cert = Certificate::create(start, end, subject, issuer, sn, pair->publicKey(), *pair);
      if (cert) {
        auto c2 = Certificate::fromDer(cert->toDer());
        REQUIRE(c2->notBefore() == start);
        REQUIRE(c2->notAfter() == end);
        REQUIRE(c2->subjectIdentity().toString() == subject.toString());
        REQUIRE(c2->issuerIdentity().toString() == issuer.toString());
        REQUIRE(c2->serialNumber() == sn);
        REQUIRE(c2->publicKey().toDer() == pair->publicKey().toDer());
      }
      delete(pair);
    }
  }
}

/* Equivalent OpenSSL command : 
 *
 *     openssl verify -crl_check -CAfile caChain-crl.pem cert.pem
 *
 * See assets/verify/README.md for the combinations.
 */

SCENARIO("Verify cert") {
  GIVEN("A new certificate") {
    DataSource* src = DataSource::fromFile("assets/verify/originCa.crl.der");
    auto originCaCrlDer = src->readAll();
    
    src = DataSource::fromFile("assets/verify/otherCa.crl.der");
    auto otherCaCrlDer = src->readAll();

    src = DataSource::fromFile("assets/verify/pkitbverify1.pem");
    auto v = src->readAll();
    std::string pkitbverify1Pem(v.begin(),v.end());
    Certificate* pkitbverify1Cert = Certificate::fromPem(pkitbverify1Pem);
    REQUIRE_FALSE(pkitbverify1Cert == nullptr);
    
    src = DataSource::fromFile("assets/verify/pkitbverify2.pem");
    v = src->readAll();
    std::string pkitbverify2Pem(v.begin(),v.end());
    Certificate* pkitbverify2Cert = Certificate::fromPem(pkitbverify2Pem);
    REQUIRE_FALSE(pkitbverify2Cert == nullptr);

    src = DataSource::fromFile("assets/verify/pkitbverify3.pem");
    v = src->readAll();
    std::string pkitbverify3Pem(v.begin(),v.end());
    Certificate* pkitbverify3Cert = Certificate::fromPem(pkitbverify3Pem);
    REQUIRE_FALSE(pkitbverify3Cert == nullptr);

    src = DataSource::fromFile("assets/verify/pkitbverify4.pem");
    v = src->readAll();
    std::string pkitbverify4Pem(v.begin(),v.end());
    Certificate* pkitbverify4Cert = Certificate::fromPem(pkitbverify4Pem);
    REQUIRE_FALSE(pkitbverify4Cert == nullptr);

    src = DataSource::fromFile("assets/verify/pkitbverify5.pem");
    v = src->readAll();
    std::string pkitbverify5Pem(v.begin(),v.end());
    Certificate* pkitbverify5Cert = Certificate::fromPem(pkitbverify5Pem);
    REQUIRE_FALSE(pkitbverify5Cert == nullptr);

    src = DataSource::fromFile("assets/verify/pkitbverify6.pem");
    v = src->readAll();
    std::string pkitbverify6Pem(v.begin(),v.end());
    Certificate* pkitbverify6Cert = Certificate::fromPem(pkitbverify6Pem);
    REQUIRE_FALSE(pkitbverify6Cert == nullptr);

    src = DataSource::fromFile("assets/verify/pkitbverify7.pem");
    v = src->readAll();
    std::string pkitbverify7Pem(v.begin(),v.end());
    Certificate* pkitbverify7Cert = Certificate::fromPem(pkitbverify7Pem);
    REQUIRE_FALSE(pkitbverify7Cert == nullptr);

    src = DataSource::fromFile("assets/verify/pkitbverify8.pem");
    v = src->readAll();
    std::string pkitbverify8Pem(v.begin(),v.end());
    Certificate* pkitbverify8Cert = Certificate::fromPem(pkitbverify8Pem);
    REQUIRE_FALSE(pkitbverify8Cert == nullptr);
    
    src = DataSource::fromFile("assets/verify/originCa.pem");
    v = src->readAll();
    std::string originCa(v.begin(),v.end());
    Certificate* originCaCert = Certificate::fromPem(originCa);
    REQUIRE_FALSE(originCaCert == nullptr);
    
    src = DataSource::fromFile("assets/verify/originRootCa.pem");
    v = src->readAll();
    std::string originRootCa(v.begin(),v.end());
    Certificate* originRootCaCert = Certificate::fromPem(originRootCa);
    REQUIRE_FALSE(originRootCaCert == nullptr);

    THEN("verify the certs") {

      // pkitbverify1, should be Trusted
      auto isTrusted = pkitbverify1Cert->isTrusted(originRootCaCert->toDer(), originCaCrlDer, "assets/verify/originCa-chain.pem");
      REQUIRE(isTrusted == CertificateTrustState::TRUSTED);
      auto isRevoked = pkitbverify1Cert->isRevoked(originCaCert->toDer(), originCaCrlDer);
      REQUIRE(isRevoked != CertificateRevocationState::REVOKED);

      // pkitbverify2, should be EXPIRED
      isTrusted = pkitbverify2Cert->isTrusted(originRootCaCert->toDer(), originCaCrlDer, "assets/verify/originCa-chain.pem");
      REQUIRE(isTrusted == CertificateTrustState::NOT_TRUSTED);
      isRevoked = pkitbverify2Cert->isRevoked(originCaCert->toDer(), originCaCrlDer);
      REQUIRE(isRevoked != CertificateRevocationState::REVOKED);
      // To bring the expired state to user, the expiration date could be checked manually in the cert itself.

      // pkitbverify3, should be NOT TRUSTED
      isTrusted = pkitbverify3Cert->isTrusted(originRootCaCert->toDer(), otherCaCrlDer, "assets/verify/originCa-chain.pem");
      REQUIRE(isTrusted == CertificateTrustState::NOT_TRUSTED);
      isRevoked = pkitbverify3Cert->isRevoked(originCaCert->toDer(), otherCaCrlDer);
      REQUIRE(isRevoked != CertificateRevocationState::REVOKED);

      // pkitbverify4, should be NOT TRUSTED
      isTrusted = pkitbverify4Cert->isTrusted(originRootCaCert->toDer(), otherCaCrlDer, "assets/verify/originCa-chain.pem");
      REQUIRE(isTrusted == CertificateTrustState::NOT_TRUSTED);
      isRevoked = pkitbverify4Cert->isRevoked(originCaCert->toDer(), otherCaCrlDer);
      REQUIRE(isRevoked != CertificateRevocationState::REVOKED);

      // pkitbverify5, should be REVOKED
      isTrusted = pkitbverify5Cert->isTrusted(originRootCaCert->toDer(), originCaCrlDer, "assets/verify/originCa-chain.pem");
      REQUIRE(isTrusted == CertificateTrustState::TRUSTED);
      isRevoked = pkitbverify5Cert->isRevoked(originCaCert->toDer(), originCaCrlDer);
      REQUIRE(isRevoked == CertificateRevocationState::REVOKED);

      // pkitbverify6, should be REVOKED
      isTrusted = pkitbverify6Cert->isTrusted(originRootCaCert->toDer(), originCaCrlDer, "assets/verify/originCa-chain.pem");
      REQUIRE(isTrusted == CertificateTrustState::NOT_TRUSTED);
      isRevoked = pkitbverify6Cert->isRevoked(originCaCert->toDer(), originCaCrlDer);
      REQUIRE(isRevoked == CertificateRevocationState::REVOKED);

      // pkitbverify7, should be NOT TRUSTED
      isTrusted = pkitbverify7Cert->isTrusted(originRootCaCert->toDer(), otherCaCrlDer, "assets/verify/originCa-chain.pem");
      REQUIRE(isTrusted == CertificateTrustState::NOT_TRUSTED);
      isRevoked = pkitbverify7Cert->isRevoked(originCaCert->toDer(), otherCaCrlDer);
      REQUIRE(isRevoked == CertificateRevocationState::UNKNOWN);

      // pkitbverify8, should be NOT TRUSTED
      isTrusted = pkitbverify8Cert->isTrusted(originRootCaCert->toDer(), otherCaCrlDer, "assets/verify/originCa-chain.pem");
      REQUIRE(isTrusted == CertificateTrustState::NOT_TRUSTED);
      isRevoked = pkitbverify8Cert->isRevoked(originCaCert->toDer(), otherCaCrlDer);
      REQUIRE(isRevoked == CertificateRevocationState::UNKNOWN);
    }
  }
}

} //namespace Erpiko
