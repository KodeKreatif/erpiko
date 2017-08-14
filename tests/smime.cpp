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
  GIVEN("SMIME") {
    auto srcCert = DataSource::fromFile("assets/cert.pem");
    auto v = srcCert->readAll();
    std::string pemCert(v.begin(),v.end());
    auto cert = Certificate::fromPem(pemCert);

    auto srcKey = DataSource::fromFile("assets/private.key");
    v = srcKey->readAll();
    std::string pemKey(v.begin(),v.end());
    auto key = RsaKey::fromPem(pemKey);

    DataSource* src = DataSource::fromFile("assets/smime-signed.txt");
    auto s = src->readAll();
    std::string smimeStr(s.begin(),s.end());
    SignedData* p7 = SignedData::fromSMime(smimeStr, *cert);

    THEN("Can verify S/MIME multipart signed message") {
        REQUIRE_FALSE(p7 == nullptr);
        REQUIRE(p7->isDetached() == true);
        REQUIRE(p7->verify() == true);
    }
  }

  GIVEN("SMIME multipart/mixed with attachment") {
    auto srcCert = DataSource::fromFile("assets/cert.pem");
    auto v = srcCert->readAll();
    std::string pemCert(v.begin(),v.end());
    auto cert = Certificate::fromPem(pemCert);

    auto srcKey = DataSource::fromFile("assets/private.key");
    v = srcKey->readAll();
    std::string pemKey(v.begin(),v.end());
    auto key = RsaKey::fromPem(pemKey);

    DataSource* src = DataSource::fromFile("assets/smime-signed-with-attachment.txt");
    auto s = src->readAll();
    std::string smimeStr(s.begin(),s.end());
    SignedData* p7 = SignedData::fromSMime(smimeStr, *cert);

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
    EncryptingType::Value type = EncryptingType::TEXT;
    p7->encryptSMime(dataVector, type);
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
      //https://gitlab.com/KodeKreatif/erpiko/issues/4
      //REQUIRE(dataVector == decrypted);
    }
  }
}
SCENARIO("Decrypting short SMIME string") {
  GIVEN("Certificate and private key and data") {
    auto srcCert = DataSource::fromFile("assets/certx4.pem");
    auto v = srcCert->readAll();
    std::string pemCert(v.begin(),v.end());
    auto cert = Certificate::fromPem(pemCert);

    auto srcKey = DataSource::fromFile("assets/keyx4.pem");
    v = srcKey->readAll();
    std::string pemKey(v.begin(),v.end());
    auto key = RsaKey::fromPem(pemKey);

    EnvelopedData* p7 = EnvelopedData::fromSMimeFile("assets/smime-short.txt");
    auto decrypted = p7->decrypt(*cert, *key);
    std::string s((const char*)decrypted.data(), decrypted.size());
    THEN("Can be decrypted") {
      REQUIRE("MIAGCSqGSIb3DQEHAqCAMIACAQExDzANBglg\r\n\r\n\r\n" == s);
    }
  }
}

SCENARIO("Decrypting long SMIME string") {
  GIVEN("Certificate and private key and data") {
    auto srcCert = DataSource::fromFile("assets/certx4.pem");
    auto v = srcCert->readAll();
    std::string pemCert(v.begin(),v.end());
    auto cert = Certificate::fromPem(pemCert);

    auto srcKey = DataSource::fromFile("assets/keyx4.pem");
    v = srcKey->readAll();
    std::string pemKey(v.begin(),v.end());
    auto key = RsaKey::fromPem(pemKey);

    DataSource* data = DataSource::fromFile("assets/smime-long.txt");
    auto dataVector = data->readAll();
    std::string smimeStr(dataVector.begin(), dataVector.end());

    EnvelopedData* p7 = EnvelopedData::fromSMime(smimeStr);
    auto decrypted = p7->decrypt(*cert, *key);
    std::string s((const char*)decrypted.data(), decrypted.size());
    THEN("Can be decrypted") {
      std::string origin = "MIAGCSqGSIb3DQEHA6CAMIACAQAxggLKMIIBYQIBADBJMD0xFjAUBgNVBAMMDVRO\r\n";
      origin += "SVNpYmVyTGFiQ0ExFjAUBgNVBAoMDVROSSBTaWJlciBMYWIxCzAJBgNVBAYTAklE\r\n";
      origin += "AghVrQ4qSRJpujANBgkqhkiG9w0BAQEFAASCAQAFXm276uwWES/9zlC8atejdi4j\r\n";
      origin += "xVhZX2oT+uu5UNBNDstfNALJLyM3py+vnQDgLi7n6QZymdR42foNW7CL9PDczuXb\r\n";
      origin += "Sr/SQa7mcmMnFBT4mGFlepkRsKZgluE++b1XfIODEFvqTlKCyR/6gduUPRILfyOH\r\n";
      origin += "1R4h6CFFFjnvxJOuUVEUVU9PGT/lw/F7tH5cUGE+WHX+qA6zlVn+govFbfXgF0Gd\r\n";
      origin += "W7TJ9XcD0latkM4N/Ugw/XWoJMe2wFvCIMJ48+tdyIwmI+rKPYR3sqGVJiHqBaId\r\n";
      origin += "qnXGbLuxEH0c2B20ogxe+pgLwrpXf+tQraaiY0xVJLLNK5MBtBGgxr40wD/UMIIB\r\n";
      origin += "YQIBADBJMD0xFjAUBgNVBAMMDVROSVNpYmVyTGFiQ0ExFjAUBgNVBAoMDVROSSBT\r\n";
      origin += "aWJlciBMYWIxCzAJBgNVBAYTAklEAghtHKydrzmlKDANBgkqhkiG9w0BAQEFAASC\r\n";
      origin += "AQBky1Y0p8IRsnPDklXsYDWnXAz7LyQ7w+np6sQBAjxqTxhfnDPBC8SQ+PViTH3C\r\n";
      origin += "JODvjQ5/aB57ZzwrQwHVHbGUFB5i6Gs0j3ZinB5ImzrWuqOK8tRsAQ2nyU48+nrf\r\n";
      origin += "aa4QsjCr3pySMOairadwTP3A64CzE5v5kJSPKt6uQfGB+VEyNpo8MYx4CAc6eeww\r\n";
      origin += "syJqn6Kc+i/0TRQ4Ex7n8rC9ZO6CqmOEWkmtN2MeART2O07f/gStxYz2EL7RLlUi\r\n";
      origin += "3CLT+EOLXbcScPxwaWwy/kpixv3BZZjcDjIEikXfeK0rzs4rGe3lTHeYrMvsvn7s\r\n";
      origin += "v9xNwG5WMTtwk5cyXeyai6OSMIAGCSqGSIb3DQEHATAUBggqhkiG9w0DBwQIbvkM\r\n";
      origin += "DIwhiW+ggASBmJ21/fIKRO2SG4TZY2VWKjgRlNLikM5Q3KbHTO11i42B/RDsrHDh\r\n";
      origin += "AN3Ayq6SHZVRE/FjJBZRroPHzsWt56tQmvnPVuZA5EUpSRh0H/ir9Qt5rZUD03rS\r\n";
      origin += "RFDy3GYlRLgJURT48I6yg5FuKFQ0KNmhzkHM9hYQ4OZoMETgOodd80UFjuys/TZ2\r\n";
      origin += "z4VnUH45+cVsmtDcb0ArTuarBAg7J9F3iYZcxAAAAAAAAAAAAAA=3D\r\n\r\n\r\n";
      REQUIRE(origin == s);
    }
  }
}

SCENARIO("Decrypting long SMIME signed string") {
  GIVEN("Certificate and private key and data") {
    auto srcCert = DataSource::fromFile("assets/certx4.pem");
    auto v = srcCert->readAll();
    std::string pemCert(v.begin(),v.end());
    auto cert = Certificate::fromPem(pemCert);

    auto srcKey = DataSource::fromFile("assets/keyx4.pem");
    v = srcKey->readAll();
    std::string pemKey(v.begin(),v.end());
    auto key = RsaKey::fromPem(pemKey);

    DataSource* data = DataSource::fromFile("assets/smime-long-signed.txt");
    auto dataVector = data->readAll();
    std::string smimeStr(dataVector.begin(), dataVector.end());

    EnvelopedData* p7 = EnvelopedData::fromSMime(smimeStr);
    auto decrypted = p7->decrypt(*cert, *key);
    std::string s((const char*)decrypted.data(), decrypted.size());
    THEN("Can be decrypted") {
      std::string origin = "Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; ";
      origin += "micalg=sha-256; boundary=\"------------ms050609050905050905070900\"\r\n";
      origin += "\r\n";
      origin += "--------------ms050609050905050905070900\r\n";
      origin += "Content-Type: text/plain; charset=utf-8\r\n";
      origin += "Content-Transfer-Encoding: quoted-printable\r\n";
      origin += "\r\n";
      origin += "Hai\r\n";
      origin += "\r\n";
      origin += "\r\n";
      origin += "\r\n";
      origin += "--------------ms050609050905050905070900\r\n";
      origin += "Content-Type: application/pkcs7-signature; name=\"smime.p7s\"\r\n";
      origin += "Content-Transfer-Encoding: base64\r\n";
      origin += "Content-Disposition: attachment; filename=\"smime.p7s\"\r\n";
      origin += "Content-Description: S/MIME Cryptographic Signature\r\n";
      origin += "\r\n";
      origin += "MIAGCSqGSIb3DQEHAqCAMIACAQExDzANBglghkgBZQMEAgEFADCABgkqhkiG9w0BBwEAAKCC\r\n";
      origin += "COwwggQ8MIIDJKADAgECAgh4xB0ShXS0nzANBgkqhkiG9w0BAQsFADBBMRowGAYDVQQDDBFU\r\n";
      origin += "TklTaWJlckxhYlJvb3RDQTEWMBQGA1UECgwNVE5JIFNpYmVyIExhYjELMAkGA1UEBhMCSUQw\r\n";
      origin += "HhcNMTYwODE4MDkxMzA4WhcNMjEwODE4MDkxMzA4WjA9MRYwFAYDVQQDDA1UTklTaWJlckxh\r\n";
      origin += "YkNBMRYwFAYDVQQKDA1UTkkgU2liZXIgTGFiMQswCQYDVQQGEwJJRDCCASIwDQYJKoZIhvcN\r\n";
      origin += "AQEBBQADggEPADCCAQoCggEBAIWuOe4hDZmJzysvyG8j+8nQ3um8V5g5x3RMP9XAyG3Tw5H9\r\n";
      origin += "lLEpoFaJOk6eU/V6r8CvPsUFgQBF1yH2ETkva2ozD6r1cgqY47VD1gC2Oj/xCO1sr5sOJVJs\r\n";
      origin += "1OBVMJ17irvnpwkiIk1JTlaSvzgwsySBBUboUUsxkBNTPFBkv1t+AwoZXw0+sffvV3LYSMEa\r\n";
      origin += "9WGaq+sUGxHJXw1JyDvp+qhsBRSlb7DP+XmkD7Ojh2XJ0ckIWQQXRdPbdkK3RHFCJnNU9QQ2\r\n";
      origin += "T5j7KDc0YF/eIz7TruR3hfaMX4HPPuW7UyJwBhM4aE8MOphMdZ1IdDXhB/PjXYH98KfTLzM2\r\n";
      origin += "5RbAxTUCAwEAAaOCATowggE2MB0GA1UdDgQWBBSJ+LWy3SkCAHA5n2sn+0fc1g6s4zAPBgNV\r\n";
      origin += "HRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFKSsVBMck0NG1qTtM+QvlVZ1cPSBMIHSBgNVHR8E\r\n";
      origin += "gcowgccwgcSge6B5hndodHRwOi8vY2EudG5pc2liZXJsYWIueHl6L2VqYmNhL3B1YmxpY3dl\r\n";
      origin += "Yi93ZWJkaXN0L2NlcnRkaXN0P2NtZD1jcmwmaXNzdWVyPUNOPVROSVNpYmVyTGFiUm9vdENB\r\n";
      origin += "LE89VE5JJTIwU2liZXIlMjBMYWIsQz1JRKJFpEMwQTEaMBgGA1UEAwwRVE5JU2liZXJMYWJS\r\n";
      origin += "b290Q0ExFjAUBgNVBAoMDVROSSBTaWJlciBMYWIxCzAJBgNVBAYTAklEMA4GA1UdDwEB/wQE\r\n";
      origin += "AwIBhjANBgkqhkiG9w0BAQsFAAOCAQEAmFc+sSSiczQ+eKbmrD3UEc/7iGtmB6oWKh8IQInd\r\n";
      origin += "hZb+p00daqGkiS1y9g6Fe16bO/Tws0uXwzW1UbUNx5Yu8WITBha/ERtRcRdGZXm3lncbmjSC\r\n";
      origin += "ahWDgMoDH3sQ7S2n2Wg0NaAQHgaydDODpzfFOmY4FwDc0HgxbKuFLnuJUCPXiCWkJcVrliJV\r\n";
      origin += "xG1yT4hyXB9nStQidtkDwegfNd4yrOqUVHbqCtHFVVACMNFl+/5BkF4TDF/BTSrkS1uXLWKY\r\n";
      origin += "vhjPvoOKYl0g5nq4EFO7IC9kSkRxdcSIbmnp5wZQEkaNsY8hi+jQaip+1XMVDuYG/lomObaI\r\n";
      origin += "wuzd+egVod/YRzCCBKgwggOQoAMCAQICCFWtDipJEmm6MA0GCSqGSIb3DQEBCwUAMD0xFjAU\r\n";
      origin += "BgNVBAMMDVROSVNpYmVyTGFiQ0ExFjAUBgNVBAoMDVROSSBTaWJlciBMYWIxCzAJBgNVBAYT\r\n";
      origin += "AklEMB4XDTE3MDUxNzA0MTk1OFoXDTE5MDUxNzA0MTk1OFowRjEoMCYGCSqGSIb3DQEJARYZ\r\n";
      origin += "aGVycGlrby5hZ3Vub0B0bmlzaWJlci5pZDEaMBgGA1UEAwwRSGVycGlrbyBEd2kgQWd1bm8w\r\n";
      origin += "ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCGYXotvOWAQIQczCMF1y9iDlVfXpy8\r\n";
      origin += "KkiK3rX1bs4U7+ChVte/7JVY30snepZENGjaso8s0VAS6LQUZ1zCVtsv3ka1U/gmGSkbWjtP\r\n";
      origin += "kCgwGULuKuADORljrKCI2DTCWjOPQ56BJg4HN0+Q9bAZrXEjYjeplN+3JqV+chqRn1p41ElR\r\n";
      origin += "e1jz3HsTwh54BffwWQYdrg8WqNb9guTF3uZrF/8brPpaDwsGaq//62rPlXBZ30wtDPxUQzxL\r\n";
      origin += "vhw/6XLoXuXuwCWhUOFFDae4x37Rp9fj7HHCh5rBoJxS1kmwco39blrIkVfKQoAMKoa9NU9f\r\n";
      origin += "VyZolaz3n3+gbz4haYi09k7BAgMBAAGjggGhMIIBnTBRBggrBgEFBQcBAQRFMEMwQQYIKwYB\r\n";
      origin += "BQUHMAGGNWh0dHA6Ly9jYS50bmlzaWJlcmxhYi54eXovZWpiY2EvcHVibGljd2ViL3N0YXR1\r\n";
      origin += "cy9vY3NwMB0GA1UdDgQWBBSppD0uSp/LV22Pmqq7wX1oe3SYiDAMBgNVHRMBAf8EAjAAMB8G\r\n";
      origin += "A1UdIwQYMBaAFIn4tbLdKQIAcDmfayf7R9zWDqzjMIHKBgNVHR8EgcIwgb8wgbygd6B1hnNo\r\n";
      origin += "dHRwOi8vY2EudG5pc2liZXJsYWIueHl6L2VqYmNhL3B1YmxpY3dlYi93ZWJkaXN0L2NlcnRk\r\n";
      origin += "aXN0P2NtZD1jcmwmaXNzdWVyPUNOPVROSVNpYmVyTGFiQ0EsTz1UTkklMjBTaWJlciUyMExh\r\n";
      origin += "YixDPUlEokGkPzA9MRYwFAYDVQQDDA1UTklTaWJlckxhYkNBMRYwFAYDVQQKDA1UTkkgU2li\r\n";
      origin += "ZXIgTGFiMQswCQYDVQQGEwJJRDAOBgNVHQ8BAf8EBAMCBeAwHQYDVR0lBBYwFAYIKwYBBQUH\r\n";
      origin += "AwIGCCsGAQUFBwMEMA0GCSqGSIb3DQEBCwUAA4IBAQBduablEFOmJ4yuiL1DSX8BGwsFBZlT\r\n";
      origin += "pAGzehDUVRqEIhuYcqSw5d0dVnBqXoHcxjyiRa5bWW4aAYeT6jSeKhWtEwl1QtACLz7849/R\r\n";
      origin += "1NQw4GFPyzyoxnheh1SaFsW0p9XnD0JCOsfUbuFAVqovAXAfUwOAA0Lj9wb9y0W1w0+2nL46\r\n";
      origin += "SYtk3DOhVSRdqaYrDJgXaZJSkZzOZi17P6gATr4ByL9AdGqewDlcGwOjO9EXFEUmLMdbIMNj\r\n";
      origin += "ngkPTrgucOs0c0iflbzUOw1UGv1H+mcf63s1MM3nklP6vhZ8FXF4KGL4AgteibIsP+xj/KAi\r\n";
      origin += "3lsF7s/uIST5s99OX0qxbTXVMYIDBTCCAwECAQEwSTA9MRYwFAYDVQQDDA1UTklTaWJlckxh\r\n";
      origin += "YkNBMRYwFAYDVQQKDA1UTkkgU2liZXIgTGFiMQswCQYDVQQGEwJJRAIIVa0OKkkSabowDQYJ\r\n";
      origin += "YIZIAWUDBAIBBQCgggGNMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkF\r\n";
      origin += "MQ8XDTE3MDYwNTA2MDYxOFowLwYJKoZIhvcNAQkEMSIEIOWB1pwAi/DHMic8XPkTo3IWjbe7\r\n";
      origin += "cW/GxdMlkKgStAKSMFgGCSsGAQQBgjcQBDFLMEkwPTEWMBQGA1UEAwwNVE5JU2liZXJMYWJD\r\n";
      origin += "QTEWMBQGA1UECgwNVE5JIFNpYmVyIExhYjELMAkGA1UEBhMCSUQCCFWtDipJEmm6MFoGCyqG\r\n";
      origin += "SIb3DQEJEAILMUugSTA9MRYwFAYDVQQDDA1UTklTaWJlckxhYkNBMRYwFAYDVQQKDA1UTkkg\r\n";
      origin += "U2liZXIgTGFiMQswCQYDVQQGEwJJRAIIVa0OKkkSabowbAYJKoZIhvcNAQkPMV8wXTALBglg\r\n";
      origin += "hkgBZQMEASowCwYJYIZIAWUDBAECMAoGCCqGSIb3DQMHMA4GCCqGSIb3DQMCAgIAgDANBggq\r\n";
      origin += "hkiG9w0DAgIBQDAHBgUrDgMCBzANBggqhkiG9w0DAgIBKDANBgkqhkiG9w0BAQEFAASCAQAS\r\n";
      origin += "gasyB8kUQnrdteewwwmPvFCo6RrT2MaF0vWwp36+h4s8YaS7GqSvIt5A4I3apXKdXoxWbnEL\r\n";
      origin += "T9Pf7UhjD4OZjXj+g36GWq+8+pRhgomQwm4ircNocs1ssrCC2yaNEV6/FXImBEoWlxUFc+td\r\n";
      origin += "+CpqsHy267VFH1pJZybxfm5OaP9TzCXf26Y1B8mSGN9OA1e1xq1qAkY90XVrOBP/6X7tfgRL\r\n";
      origin += "U+pnbR5baTMFlVEjQqJ4fGUeVruHxR2cgyKcFBx4jy71zZS5NPgtcON2TWlv2RgSK4wK3+6H\r\n";
      origin += "XDy4LqGMltPAxAQ2VPfa9++YXu8HHlA9nAurs6Ch3pnVNWEvrTLrAAAAAAAA\r\n";
      origin += "--------------ms050609050905050905070900--\r\n";
      REQUIRE(origin == s);
    }
  }
}
/*
  */
SCENARIO("List enclosed certificates") {
  GIVEN("Certificate in pem") {
    auto srcCert = DataSource::fromFile("assets/cert.pem");
    auto v = srcCert->readAll();
    std::string pemCert(v.begin(),v.end());
    auto cert = Certificate::fromPem(pemCert);

    auto srcData = DataSource::fromFile("assets/smime-signed-with-cert.pem");
    v = srcData->readAll();
    std::string pemData(v.begin(),v.end());

    SignedData* p7 = SignedData::fromSMime(pemData, *cert);

    THEN("Check the certificate") {
      auto list = p7->certificates();
      REQUIRE(list.size() == 1);
      for (auto i : list) {
        auto t = i->subjectIdentity().toString();
        REQUIRE(t == "/emailAddress=herpiko.email.testing@gmail.com/CN=herpikotesting1");
      }
      delete p7;
      // test SignedData's destructor
      REQUIRE(std::string("here-not-crashed") == std::string("here-not-crashed"));
    }
  }
}

SCENARIO("Import SMime without the cert") {
  GIVEN("SMime in pem") {
    auto srcData = DataSource::fromFile("assets/smime-signed-with-cert.pem");
    auto v = srcData->readAll();
    std::string pemData(v.begin(),v.end());

    SignedData* p7 = SignedData::fromSMime(pemData);

    THEN("Check the certificate") {
      auto list = p7->certificates();
      REQUIRE(list.size() == 1);
      for (auto i : list) {
        auto t = i->subjectIdentity().toString();
        REQUIRE(t == "/emailAddress=herpiko.email.testing@gmail.com/CN=herpikotesting1");
      }
      delete p7;
      // test SignedData's destructor
      REQUIRE(std::string("here-not-crashed") == std::string("here-not-crashed"));
    }
  }
}




} //namespace Erpiko
