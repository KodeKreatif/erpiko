#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include "erpiko/cmp.h"
#include "erpiko/utils.h"
#include "erpiko/data-source.h"
#include "erpiko/rsakey.h"
#include "erpiko/certificate.h"

namespace Erpiko {

SCENARIO("CMP ir request") {
  GIVEN("A ca cert, a key and a subject") {
/*
    DataSource* src = DataSource::fromFile("assets/cacert.pem");
    auto v = src->readAll();
    std::string pem(v.begin(),v.end());
    Certificate* cacert = Certificate::fromPem(pem);
    REQUIRE_FALSE(cacert == nullptr);

    RsaKey* pair = RsaKey::create(4096);
    REQUIRE(pair->bits() == 4096);

    Identity* id = new Identity();
    REQUIRE_FALSE(id == nullptr);
    id->set("commonName", "testkk02");
    id->set("UID", "omama");

    auto cmp = new Cmp();
    We don't have mocking in place, so yeah...

    cmp->subject(*id);
    cmp->caCertificate(*cacert);
    cmp->serverName("ejbca.sandbox");
    cmp->serverPort(8181);
    cmp->serverPath("/ejbca/publicweb/cmp/CMP");
    cmp->referenceName("testkk02");
    cmp->secret("omama");
    cmp->privateKey(*pair);

    ObjectId hash("2.16.840.1.101.3.4.2.1");
    ObjectId siiType("1.2.3.4.5");
    std::string sii("12345");
    std::string password("abcde12345");
    std::vector<unsigned char> r = {
      1, 2, 3, 4, 5, 6, 7, 8,
      1, 2, 3, 4, 5, 6, 7, 8,
      1, 2, 3, 4, 5, 6, 7, 8,
      1, 2, 3, 4, 5, 6, 7, 8 };

    Sim sim(hash, siiType, sii, password, r);
    cmp->insertSim(sim);


    auto clCert = cmp->startInitRequest();
    REQUIRE_FALSE(clCert == nullptr);
    std::cout << Utils::hexString(clCert->toDer()) << "\n";
 */

  }
}

} // namespace Erpiko
