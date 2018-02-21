#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include "erpiko/p11-token.h"
#include "erpiko/rsakey.h"
#include "erpiko/utils.h"
#include "erpiko/data-source.h"
#include "erpiko/digest.h"
#include "erpiko/certificate.h"
#include "erpiko/pkcs12.h"
#include "erpiko/enveloped-data.h"
#include "erpiko/signed-data.h"
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
	  //auto r = t.load("c:\\windows\\system32\\acospkcs11.dll");
	  auto r = t.load("c:\\windows\\system32\\eTPKCS11.dll");
	  //auto r = t.load("c:\\windows\\system32\\pkcs11-logger-x86.dll");

    // Logger midldeware from https://github.com/Pkcs11Interop/pkcs11-logger
	  //auto r = t.load("c:\\windows\\system32\\pkcs11-logger-x86.dll");
#else
	  auto r = t.load("/home/mdamt/src/tmp/hsm/lib/softhsm/libsofthsm2.so");
#endif
      REQUIRE(r == true);

      std::cout << "Please insert the smartcard to slot" << std::endl;

      int slotId;
#ifdef WIN32
      auto status = t.waitForCardStatus(slotId);
      if (status == CardStatus::NOT_PRESENT) {
          std::cout << "Token not present, please put it back...";
          status = t.waitForCardStatus(slotId);
      }
      REQUIRE(status == CardStatus::PRESENT);

      std::cout << "Logging in." << std::endl;
      r = t.login(slotId, "qwerty");
#else
      auto status = t.waitForCardStatus(slotId);
      REQUIRE(status == CardStatus::PRESENT);
      std::cout << "Slot event occured. Card is present." << std::endl;
      std::cout << "Smartcard has been inserted" << std::endl;

      r = t.login(933433059, "qwerty");
#endif

      REQUIRE(r == true);
      std::cout << "Logged in" << std::endl;

      std::vector<TokenInfo> slots = t.getAllTokensInfo();
      REQUIRE(sizeof(slots) > 0);
      for (auto const& slot : slots) {
        std::cout << "TokenInfo" << std::endl;
        std::cout << "Label : " << slot.label << std::endl;
        REQUIRE(slot.label.length() > 0);
        std::cout << "Manufacturer : " << slot.manufacturer << std::endl;
        REQUIRE(slot.manufacturer.length() > 0);
        std::cout << "Model : " << slot.model << std::endl;
        REQUIRE(slot.model.length() > 0);
        std::cout << "serialNumber : " << slot.serialNumber << std::endl;
        REQUIRE(slot.serialNumber.length() > 0);
      }

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

      std::vector<Erpiko::Certificate*> certs = t.getCertificates(false);
      int certsTotal = certs.size();

      auto src = DataSource::fromFile("assets/verify/pkitbverify1.pem");
      auto certData = src->readAll();
      std::string pkitbverify1Pem(certData.begin(),certData.end());
      Certificate* pkitbverify1Cert = Certificate::fromPem(pkitbverify1Pem);
      REQUIRE_FALSE(pkitbverify1Cert == nullptr);

      std::string serialNumberStr = pkitbverify1Cert->serialNumber().toHexString();
      t.removeCertificate(*pkitbverify1Cert); // ignore result

      auto putCertResult = t.putCertificate(*pkitbverify1Cert);
      REQUIRE(putCertResult == TokenOpResult::SUCCESS);
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

      putCertResult = t.putCertificate(*pkitbverify1Cert);
      REQUIRE(putCertResult == TokenOpResult::GENERIC_ERROR);

      auto res = t.removeCertificate(*pkitbverify1Cert); // now check result
      REQUIRE(res == true);

      certs = t.getCertificates(false);
      for (auto const& cert : certs) {
        std::string cN = cert->subjectIdentity().get("commonName");
        std::cout << "- commonName : " << cN << std::endl;
        REQUIRE(cN.length() > 0);
      }

      src = DataSource::fromFile("assets/verify/pkitbverify1.p12");
      auto p12Data = src->readAll();
      auto p12 = Erpiko::Pkcs12::fromDer(p12Data, "123456");
      const RsaKey& pk = p12->privateKey();
      const Certificate& certp12 = p12->certificate();

      t.removePrivateKey("omama"); // ignore result
      t.removePrivateKey("opapa"); // ignore result

      auto putPrivKeyResult = t.putPrivateKey(pk, "omama");
      REQUIRE(putPrivKeyResult == TokenOpResult::SUCCESS);
      std::cout << "put priv key result :" << std::endl;
      if (putPrivKeyResult == TokenOpResult::SUCCESS) {
         std::cout << "success" << std::endl;
      } else if (putCertResult == TokenOpResult::GENERIC_ERROR) {
         std::cout << "generic error" << std::endl;
      } else if (putCertResult == TokenOpResult::TOO_LARGE) {
         std::cout << "too large" << std::endl;
      } else if (putCertResult == TokenOpResult::READ_ONLY) {
         std::cout << "read only" << std::endl;
      }

      auto privKeyFromToken = t.getPrivateKey(certp12.publicKey());
      REQUIRE(privKeyFromToken != nullptr);
      REQUIRE(privKeyFromToken->onDevice() == true);

      auto der1_1 = privKeyFromToken->publicKey().toDer();
      auto der1_2 = certp12.publicKey().toDer();
      REQUIRE(der1_1 == der1_2);

      putPrivKeyResult = t.putPrivateKey(pk, "omama");
      REQUIRE(putPrivKeyResult == TokenOpResult::GENERIC_ERROR);

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

      // double check
      r = t.putData(appName, label, hash);
      REQUIRE(r == TokenOpResult::SUCCESS);

      h = t.getData(appName, label);
      REQUIRE(h == hash);

      res = t.removeData(appName, label); // check result
      REQUIRE(res == true);

      res = t.removePrivateKey("omama"); // check result
      REQUIRE(res == true);

      label = "unique";
      r = t.putData(appName, label, hash);
      r = t.putData(appName, label, hash);
      r = t.putData(appName, label, hash);

      auto v = t.getAllData(appName, label);
      REQUIRE(v.size() == 3);

      r = t.putUniqueData(appName, label, hash);
      v = t.getAllData(appName, label);
      REQUIRE(v.size() == 1);

      t.logout();
    }
  }
}
SCENARIO("PKCS7 / Enveloped Data", "[.][p11]") {
  GIVEN("An initialized token") {
    THEN("Encryption and decryption with key label") {
      P11Token p11Token;
      Token& t = (Token&)p11Token;

#ifdef WIN32
	  auto r = t.load("c:\\windows\\system32\\eTPKCS11.dll");
#else
	  auto r = t.load("/home/mdamt/src/tmp/hsm/lib/softhsm/libsofthsm2.so");
#endif
      REQUIRE(r == true);
      std::cout << "Please insert the smartcard to slot" << std::endl;
      int slotId;
#ifdef WIN32
      auto status = t.waitForCardStatus(slotId);
      if (status == CardStatus::NOT_PRESENT) {
          std::cout << "Token not present, please put it back...";
          status = t.waitForCardStatus(slotId);
      }
      REQUIRE(status == CardStatus::PRESENT);

      std::cout << "Logging in." << std::endl;
      r = t.login(slotId, "qwerty");
#else
      auto status = t.waitForCardStatus(slotId);
      REQUIRE(status == CardStatus::PRESENT);
      std::cout << "Slot event occured. Card is present." << std::endl;
      std::cout << "Smartcard has been inserted" << std::endl;

      r = t.login(933433059, "qwerty");
#endif

      REQUIRE(r == true);
      std::cout << "Logged in" << std::endl;

      auto src = DataSource::fromFile("assets/verify/pkitbverify1.p12");
      auto p12Data = src->readAll();
      auto p12 = Erpiko::Pkcs12::fromDer(p12Data, "123456");
      const RsaKey& pk = p12->privateKey();
      const Certificate& certp12 = p12->certificate();

      t.removePrivateKey("omama"); // ignore result
      auto putPrivKeyResult = t.putPrivateKey(pk, "omama");
      REQUIRE(putPrivKeyResult == TokenOpResult::SUCCESS);

      std::cout << "decrypt with privkey from token" << std::endl;
      src = DataSource::fromFile("assets/data.txt");
      auto v = src->readAll();

      t.unsetKey();
      t.setKeyLabel("omama"); // Do encrypt decrypt with the help of key label

      EnvelopedData* p7 = new EnvelopedData(certp12, ObjectId("2.16.840.1.101.3.4.1.42"));
      DataSource* toBeEncrypted = DataSource::fromFile("assets/data.txt");
      auto dataVector = toBeEncrypted->readAll();
      p7->addRecipient(certp12);
      p7->encrypt(dataVector);
      auto der = p7->toDer();

      EnvelopedData* p7v = EnvelopedData::fromDer(der);

      // Simulate that we didn't have the private key in memory help the decryption
      auto privKey = t.getPrivateKey(certp12.publicKey());
      // This could be an incomplete private key with empty private exponent and other secret components,
      // but it has onDevice() as true.
      auto decrypted = p7v->decrypt(certp12, *privKey);
      REQUIRE(v == decrypted);
      decrypted.clear();

      auto res = t.removePrivateKey("omama"); // check result
      REQUIRE(res == true);

      // Clean
      t.removePrivateKey("omama"); // ignore result
      t.logout();

    }

    THEN("Sign and verify without key label") {
      // The private key will be queried by public key's modulus and exponent
      P11Token p11Token;
      Token& t = (Token&)p11Token;

#ifdef WIN32
	  auto r = t.load("c:\\windows\\system32\\eTPKCS11.dll");
#else
	  auto r = t.load("/home/mdamt/src/tmp/hsm/lib/softhsm/libsofthsm2.so");
#endif
      REQUIRE(r == true);
      std::cout << "Please insert the smartcard to slot" << std::endl;
      int slotId;
#ifdef WIN32
      auto status = t.waitForCardStatus(slotId);
      if (status == CardStatus::NOT_PRESENT) {
          std::cout << "Token not present, please put it back...";
          status = t.waitForCardStatus(slotId);
      }
      REQUIRE(status == CardStatus::PRESENT);

      std::cout << "Logging in." << std::endl;
      r = t.login(slotId, "qwerty");
#else
      auto status = t.waitForCardStatus(slotId);
      REQUIRE(status == CardStatus::PRESENT);
      std::cout << "Slot event occured. Card is present." << std::endl;
      std::cout << "Smartcard has been inserted" << std::endl;

      r = t.login(933433059, "qwerty");
#endif

      REQUIRE(r == true);
      std::cout << "Logged in" << std::endl;

      auto src = DataSource::fromFile("assets/verify/pkitbverify1.p12");
      auto p12Data = src->readAll();
      auto p12 = Erpiko::Pkcs12::fromDer(p12Data, "123456");
      const RsaKey& pk = p12->privateKey();
      const Certificate& certp12 = p12->certificate();

      t.removePrivateKey("omama"); // ignore result
      auto putPrivKeyResult = t.putPrivateKey(pk, "omama");
      REQUIRE(putPrivKeyResult == TokenOpResult::SUCCESS);

      std::cout << "sign with privkey from token" << std::endl;
      src = DataSource::fromFile("assets/data.txt");
      auto v = src->readAll();

      t.unsetKey(); // Do encrypt decrypt without the help of key label

      const RsaKey* privKey = t.getPrivateKey(certp12.publicKey());
      SignedData* s7 = new SignedData(certp12, *privKey);
      DataSource* toBeSigned = DataSource::fromFile("assets/data.txt");
      auto dataVector = toBeSigned->readAll();
      s7->update(dataVector);
      s7->signDetached();
      auto der = s7->toDer();


      std::cout << "verify it" << std::endl;
      auto s7_2 = SignedData::fromDer(der, certp12);
      s7_2->update(dataVector);
      bool isVerified = s7_2->verify();
      REQUIRE(isVerified == true);

      // Clean
      t.removePrivateKey("omama"); // ignore result
      t.logout();

    }
  }
}
} // namespace Erpiko
