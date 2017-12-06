#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include "erpiko/p11-token.h"
#include "erpiko/rsakey.h"
#include "erpiko/utils.h"
#include "erpiko/data-source.h"
#include "erpiko/digest.h"
#include "erpiko/certificate.h"
#include <iostream>

using namespace std;

namespace Erpiko {
/*
 * This test supposed to be run against a newly initialized smartcard with empty storage
 *
 */

SCENARIO("Token init", "[.][p11]") {
  GIVEN("A token") {
    THEN("Token is initialized") {

      ObjectId o512(DigestConstants::SHA512);
      ObjectId o384(DigestConstants::SHA384);
      ObjectId o224(DigestConstants::SHA224);
      ObjectId o(DigestConstants::SHA256);

      std::string s = "data";

      Digest *d = Digest::get(o);
      std::vector<unsigned char> data(s.c_str(), s.c_str() + s.length());
      std::vector<unsigned char> empty;
      d->update(data);
      auto hash = d->finalize(empty);
      delete d;

      d = Digest::get(o224);
      d->update(data);
      auto hash224 = d->finalize(empty);
      delete d;

      d = Digest::get(o384);
      d->update(data);
      auto hash384 = d->finalize(empty);
      delete d;

      d = Digest::get(o512);
      d->update(data);
      auto hash512 = d->finalize(empty);
      delete d;

      int bits = 1024;
      RsaKey* k = RsaKey::create(bits);

      auto v = Utils::fromHexString("751965349686009581002736762779192355");
      auto enc = k->publicKey().encrypt(v);
      P11Token p11Token;
      Token& t = (Token&)p11Token;
#ifdef WIN32
	  //auto r = t.load("C:\\SoftHSM2\\lib\\softhsm2-x64.dll");
	  auto r = t.load("c:\\windows\\system32\\eTPKCS11.dll");
#else
	  auto r = t.load("/home/mdamt/src/tmp/hsm/lib/softhsm/libsofthsm2.so");
#endif
      REQUIRE(r == true);

      std::cout << "Please insert the smartcard to slot" << std::endl;


      int slotId;
#ifdef WIN32
      auto status = t.waitForCardStatus(slotId);
      REQUIRE(status == CardStatus::PRESENT);
      std::cout << "Slot event occured. Card is present on slot : " << slotId << std::endl;

      r = t.login(slotId, "qwerty");
#else
      auto status = t.waitForCardStatus(slotId);
      REQUIRE(status == CardStatus::PRESENT);
      std::cout << "Slot event occured. Card is present." << std::endl;

      r = t.login(933433059, "qwerty");
#endif
      REQUIRE(r == true);
      std::cout << "Smartcard has been inserted" << std::endl;

      REQUIRE(r == true);
      std::cout << "Logged in" << std::endl;

      t.setKeyId(02, "key2");
      k = RsaKey::create(1024, &t);

	    REQUIRE(k != nullptr);
      auto vec = k->toDer();

      REQUIRE(k->onDevice() == true);

      REQUIRE(vec.size() == 0);

      auto enc2 = k->publicKey().encrypt(v);

      auto enc3 = k->publicKey().encrypt(v);

      REQUIRE(enc2 != enc3);

      REQUIRE(enc2.size() == bits/8);

      auto dec3 = k->decrypt(enc2);

      REQUIRE(dec3 == v);


      auto signedData = k->sign(hash, o);

      REQUIRE(signedData.size() > 0);

      auto verified = k->publicKey().verify(signedData, hash, o);

      REQUIRE(verified == true);


#ifdef LINUX
      signedData = k->sign(hash224, o224);

      REQUIRE(signedData.size() > 0);

      verified = k->publicKey().verify(signedData, hash224, o224);

      REQUIRE(verified == true);
#endif

      signedData = k->sign(hash384, o384);

      REQUIRE(signedData.size() > 0);

      verified = k->publicKey().verify(signedData, hash384, o384);

      REQUIRE(verified == true);


      signedData = k->sign(hash512, o512);

      REQUIRE(signedData.size() > 0);

      verified = k->publicKey().verify(signedData, hash512, o512);

      REQUIRE(verified == true);

      REQUIRE(t.logout() == true);

      enc2 = k->publicKey().encrypt(v);

      REQUIRE(enc2.size() == 0);

    }
  }

  GIVEN("A token") {
    THEN("Token is initialized") {

      P11Token t;
#ifdef WIN32
	  //auto r = t.load("C:\\SoftHSM2\\lib\\softhsm2-x64.dll");
	  auto r = t.load("c:\\windows\\system32\\eTPKCS11.dll");
#else
	  auto r = t.load("/home/mdamt/src/tmp/hsm/lib/softhsm/libsofthsm2.so");
#endif
      REQUIRE(r == true);
#ifdef WIN32
      r = t.login(0, "qwerty");
#else
	    r = t.login(933433059, "qwerty");
#endif

      REQUIRE(r == true);

      std::vector<Erpiko::Certificate*> certs = t.getCertificates(); 
      int certsTotal = certs.size();

      auto src = DataSource::fromFile("assets/verify/pkitbverify1.pem");
      auto certData = src->readAll();
      std::string pkitbverify1Pem(certData.begin(),certData.end());
      Certificate* pkitbverify1Cert = Certificate::fromPem(pkitbverify1Pem);
      REQUIRE_FALSE(pkitbverify1Cert == nullptr);
      auto putCertResult = t.putCertificate(pkitbverify1Cert);

      std::cout << "put cert result : " << std::endl;
      if (putCertResult == TokenOpResult::SUCCESS) {
         std::cout << "success" << std::endl;
      } else if (putCertResult == TokenOpResult::GENERIC_ERROR) {
         std::cout << "generic error" << std::endl;
      } else if (putCertResult == TokenOpResult::TOO_LARGE) {
         std::cout << "too large" << std::endl;
      } else if (putCertResult == TokenOpResult::READ_ONLY) {
         std::cout << "read only" << std::endl;
      }

      certs = t.getCertificates(); 
      REQUIRE(certsTotal < certs.size());
      std::cout << "The certificates :"  << std::endl;
      for (auto const& cert : certs) {
        std::string cN = cert->subjectIdentity().get("commonName");
        std::cout << "- commonName : " << cN << std::endl;
        REQUIRE(cN.length() > 0);
      }

      putCertResult = t.putCertificate(pkitbverify1Cert);
      REQUIRE(putCertResult == TokenOpResult::GENERIC_ERROR);

      ObjectId o(DigestConstants::SHA256);
      std::string appName = "appName";
      std::string s = "data";
      std::string label = "label1";
      Digest *d = Digest::get(o);
      std::vector<unsigned char> data(s.c_str(), s.c_str() + s.length());
      std::vector<unsigned char> empty;
      d->update(data);
      auto hash = d->finalize(empty);
      delete d;

      r = t.putData(appName, label, hash);
      REQUIRE(r == TokenOpResult::SUCCESS);

      auto h = t.getData(appName, label);
      REQUIRE(h == hash);

    }
  }
}
} // namespace Erpiko
