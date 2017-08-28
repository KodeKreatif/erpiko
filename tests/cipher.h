#ifndef _TEST_CIPHER_H
#define _TEST_CIPHER_H
#define TestCipher(T, CIPHER, MODE, KEY, IV, D1, D2) \
SCENARIO(T) { \
  GIVEN("Object Id") { \
    ObjectId o(CipherConstants::CIPHER); \
    std::vector<unsigned char>iv = Utils::fromHexString(IV); \
    std::vector<unsigned char>key =  Utils::fromHexString(KEY); \
    std::vector<unsigned char>data1 = Utils::fromHexString(D1); \
    std::vector<unsigned char>data2 = Utils::fromHexString(D2); \
    Cipher *d = Cipher::get(o, CipherConstants::MODE, key, iv); \
    REQUIRE_FALSE(d == nullptr); \
    d->enablePadding(false); \
    auto f = d->update(data1); \
    auto f2 = d->finalize(); \
    REQUIRE(f == data2); \
 \
    delete d; \
    REQUIRE("not-crashed-here" == std::string("not-crashed-here")); \
  } \
}

#define TestDecryptAuth(T, CIPHER, KEY, IV, AAD, TAG, PT, CT) \
SCENARIO(T) { \
  GIVEN("Object Id") { \
    ObjectId o(CipherConstants::CIPHER); \
    std::vector<unsigned char>iv = Utils::fromHexString(IV); \
    std::vector<unsigned char>key =  Utils::fromHexString(KEY); \
    std::vector<unsigned char>pt = Utils::fromHexString(PT); \
    std::vector<unsigned char>ct = Utils::fromHexString(CT); \
    std::vector<unsigned char>aad = Utils::fromHexString(AAD); \
    std::vector<unsigned char>tag = Utils::fromHexString(TAG); \
    Cipher *d = Cipher::get(o, CipherConstants::DECRYPT, key, iv); \
    REQUIRE_FALSE(d == nullptr); \
    d->setAad(aad); \
    d->enablePadding(false); \
    auto f1 = d->update(ct); \
    d->setTag(tag); \
    auto f2 = d->finalize(); \
    f1.insert(f1.end(), f2.begin(), f2.end()); \
    REQUIRE(f1 == pt); \
    delete d; \
    REQUIRE("not-crashed-here" == std::string("not-crashed-here")); \
  } \
}

#define TestEncryptAuth(T, CIPHER, KEY, IV, AAD, TAG, PT, CT) \
SCENARIO(T) { \
  GIVEN("Object Id") { \
    ObjectId o(CipherConstants::CIPHER); \
    std::vector<unsigned char>iv = Utils::fromHexString(IV); \
    std::vector<unsigned char>key =  Utils::fromHexString(KEY); \
    std::vector<unsigned char>pt = Utils::fromHexString(PT); \
    std::vector<unsigned char>ct = Utils::fromHexString(CT); \
    std::vector<unsigned char>aad = Utils::fromHexString(AAD); \
    std::vector<unsigned char>tag = Utils::fromHexString(TAG); \
    Cipher *d = Cipher::get(o, CipherConstants::ENCRYPT, key, iv); \
    REQUIRE_FALSE(d == nullptr); \
    d->setAad(aad); \
    d->enablePadding(false); \
    auto f1 = d->update(pt); \
    auto f2 = d->finalize(); \
    auto tag2 = d->getTag(); \
    REQUIRE(f1 == ct); \
    REQUIRE(tag2 == tag); \
    delete d; \
    REQUIRE("not-crashed-here" == std::string("not-crashed-here")); \
  } \
}

#define TestCipherAuth(T, CIPHER, KEY, IV, AAD, TAG, PT, CT) \
  TestEncryptAuth("E" T, CIPHER, KEY, IV, AAD, TAG, PT, CT) \
  TestDecryptAuth("D" T, CIPHER, KEY, IV, AAD, TAG, PT, CT) \


#define TestEncryptIv(T, CIPHER, KEY, IV, D1, D2) \
  TestCipher(T, CIPHER, ENCRYPT, KEY, IV, D1, D2)
#define TestEncrypt(T, CIPHER, KEY, D1, D2) \
  TestEncryptIv(T, CIPHER, KEY, "", D1, D2)
#define TestDecryptIv(T, CIPHER, KEY, IV, D1, D2) \
  TestCipher(T, CIPHER, DECRYPT, KEY, IV, D1, D2)
#define TestDecrypt(T, CIPHER, KEY, D1, D2) \
  TestDecryptIv(T, CIPHER, KEY, "", D1, D2)


#endif // _TEST_CIPHER_H
