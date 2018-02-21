#include "converters.h"
#include "erpiko/utils.h"
#include "erpiko/bigint.h"
#include <iostream>
#include <string>
#include "engine-p11.h"
#include "pkcs11/cryptoki.h"
#include <openssl/rsa.h>
#include "openssl/bn.h"
#include <openssl/evp.h>
#ifdef WIN32
#include <Windows.h>
#else
#include <dlfcn.h>
#endif

CK_FUNCTION_LIST_PTR F = nullptr;

using namespace std;
using namespace Erpiko;

#define PUT(var, from) \
  std::vector<unsigned char> var(BN_num_bytes(from)); \
  BN_bn2bin(from, var.data());

int rsaKeygen(RSA *rsa, int bits, BIGNUM *exp, BN_GENCB *cb) {
  (void) cb;

  char* eStr = BN_bn2hex(exp);
  if (!eStr) return 0;
  auto v = Utils::fromHexString(eStr);
  const unsigned int size = v.size();
  CK_BYTE* publicExponent = new CK_BYTE[size];
  for (unsigned int i = 0; i < size; i ++) {
    publicExponent[i] = v.at(i);
  }
  free(eStr);

  EngineP11& p11 = EngineP11::getInstance();

  CK_OBJECT_HANDLE publicKey, privateKey;
  CK_MECHANISM mechanism = {
    CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0
  };
  CK_ULONG modulusBits = bits;
  CK_BYTE* subject = reinterpret_cast<unsigned char*>(const_cast<char*>(p11.getKeyLabel().c_str()));
  CK_BYTE id[] = { (unsigned char)p11.getKeyId() };
  CK_BBOOL trueValue = CK_TRUE;
  CK_OBJECT_CLASS privateClass = CKO_PRIVATE_KEY;
  CK_OBJECT_CLASS publicClass = CKO_PUBLIC_KEY;
  CK_ATTRIBUTE publicKeyTemplate[] = {
    {CKA_ID, id, sizeof(CK_BYTE)},
    {CKA_LABEL, subject, p11.getKeyLabel().size()},
	{CKA_CLASS, &publicClass, sizeof(publicClass) },
    {CKA_TOKEN, &trueValue, sizeof(trueValue)},
    {CKA_ENCRYPT, &trueValue, sizeof(trueValue)},
    {CKA_VERIFY, &trueValue, sizeof(trueValue)},
    {CKA_WRAP, &trueValue, sizeof(trueValue)},
    {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
    {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(CK_BYTE) * size}
  };
  CK_ATTRIBUTE privateKeyTemplate[] = {
    {CKA_ID, id, sizeof(CK_BYTE)},
    {CKA_LABEL, subject, p11.getKeyLabel().size()},
	{CKA_CLASS, &privateClass, sizeof(privateClass)},
    {CKA_TOKEN, &trueValue, sizeof(trueValue)},
    {CKA_PRIVATE, &trueValue, sizeof(trueValue)},
    {CKA_SENSITIVE, &trueValue, sizeof(trueValue)},
    {CKA_DECRYPT, &trueValue, sizeof(trueValue)},
    {CKA_SIGN, &trueValue, sizeof(trueValue)},
    {CKA_UNWRAP, &trueValue, sizeof(trueValue)}
  };

  CK_RV rv = CKR_OK;
  rv = F->C_GenerateKeyPair(p11.getSession(),
      &mechanism,
      publicKeyTemplate, 9,
      privateKeyTemplate, 9,
      &publicKey,
      &privateKey);

  if (rv != CKR_OK) {
	  return 0;
  }

  delete[] publicExponent;
  CK_BYTE* n = new CK_BYTE[bits];
  CK_ATTRIBUTE pubValueT[] = {
    {CKA_MODULUS, n, sizeof(CK_BYTE) * bits}
  };

  rv = F->C_GetAttributeValue(p11.getSession(), publicKey, pubValueT, 1);
  if (rv == CKR_OK)
  if ((rsa->e = BN_bin2bn(publicExponent, size, nullptr)) != nullptr)
  if ((rsa->n = BN_bin2bn(n, pubValueT[0].ulValueLen, nullptr)) != nullptr)
  {
    return 1;
  }
  return 0;
}

CK_OBJECT_HANDLE findPrivateKey(const RsaPublicKey& publicKey) {
  CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
  CK_KEY_TYPE pKeyType = CKK_RSA;
  auto modulus = publicKey.modulus().dump();
  auto exponent = publicKey.exponent().dump();
  CK_ATTRIBUTE t[] = {
    { CKA_CLASS, &keyClass, sizeof(keyClass) },
    { CKA_KEY_TYPE,  &pKeyType, sizeof(pKeyType) },
    { CKA_MODULUS, modulus.data(), modulus.size() },
    { CKA_PUBLIC_EXPONENT, exponent.data(), exponent.size() },
  };
  CK_ULONG objectCount;
  CK_OBJECT_HANDLE key;
  EngineP11& p11 = EngineP11::getInstance();

  CK_RV rv = CKR_OK;
  rv = F->C_FindObjectsInit(p11.getSession(), t, 4);
  if (rv != CKR_OK) {
    return 0;
  }

  rv = F->C_FindObjects(p11.getSession(), &key, 1, &objectCount);
  if (rv != CKR_OK) {
    return 0;
  }

  rv = F->C_FindObjectsFinal(p11.getSession());
  if (objectCount == 0) {
    return 0;
  }
  return key;
}

CK_OBJECT_HANDLE findPrivateKey(const RSA* rsa) {
  CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
  CK_KEY_TYPE pKeyType = CKK_RSA;
  PUT(modulus, rsa->n);
  PUT(exponent, rsa->e);
  CK_ATTRIBUTE t[] = {
    { CKA_CLASS, &keyClass, sizeof(keyClass) },
    { CKA_KEY_TYPE,  &pKeyType, sizeof(pKeyType) },
    { CKA_MODULUS, modulus.data(), modulus.size() },
    { CKA_PUBLIC_EXPONENT, exponent.data(), exponent.size() },
  };
  CK_ULONG objectCount;
  CK_OBJECT_HANDLE key;
  EngineP11& p11 = EngineP11::getInstance();

  CK_RV rv = CKR_OK;
  rv = F->C_FindObjectsInit(p11.getSession(), t, 4);
  if (rv != CKR_OK) {
    return 0;
  }

  rv = F->C_FindObjects(p11.getSession(), &key, 1, &objectCount);
  if (rv != CKR_OK) {
    return 0;
  }

  rv = F->C_FindObjectsFinal(p11.getSession());
  if (objectCount == 0) return 0;
  return key;
}

CK_OBJECT_HANDLE findPublicKey(const RSA* rsa) {
  CK_OBJECT_CLASS keyClass = CKO_PUBLIC_KEY;
  CK_KEY_TYPE pKeyType = CKK_RSA;
  PUT(modulus, rsa->n);
  PUT(exponent, rsa->e);
  CK_ATTRIBUTE t[] = {
    { CKA_CLASS, &keyClass, sizeof(keyClass) },
    { CKA_KEY_TYPE,  &pKeyType, sizeof(pKeyType) },
    { CKA_MODULUS, modulus.data(), modulus.size() },
    { CKA_PUBLIC_EXPONENT, exponent.data(), exponent.size() },
  };
  CK_ULONG objectCount;
  CK_OBJECT_HANDLE key;
  EngineP11& p11 = EngineP11::getInstance();

  CK_RV rv = CKR_OK;
  rv = F->C_FindObjectsInit(p11.getSession(), t, 4);
  if (rv != CKR_OK) {
    return 0;
  }

  rv = F->C_FindObjects(p11.getSession(), &key, 1, &objectCount);
  if (rv != CKR_OK) {
    return 0;
  }

  rv = F->C_FindObjectsFinal(p11.getSession());
  if (objectCount == 0) return 0;
  return key;
}

CK_OBJECT_HANDLE keyFromRSA(const RSA* rsa) {
  CK_OBJECT_CLASS keyClass = CKO_PUBLIC_KEY;
  CK_KEY_TYPE pKeyType = CKK_RSA;
  std::string label = "A RSA public key object";
  CK_BYTE* labelByte = reinterpret_cast<unsigned char*>(const_cast<char*>(label.c_str()));
  CK_BBOOL trueValue = CK_TRUE;
  CK_BBOOL falseValue = CK_FALSE;
  PUT(modulus, rsa->n);
  PUT(exponent, rsa->e);
  CK_ATTRIBUTE t[] = {
    { CKA_CLASS, &keyClass, sizeof(keyClass) },
    { CKA_KEY_TYPE,  &pKeyType, sizeof(pKeyType) },
    { CKA_TOKEN, &falseValue, sizeof(falseValue) },
    { CKA_LABEL, labelByte, label.size() },
    { CKA_WRAP, &trueValue, sizeof(trueValue) },
    { CKA_ENCRYPT, &trueValue, sizeof(trueValue) },
    { CKA_MODULUS, modulus.data(), modulus.size() },
    { CKA_PUBLIC_EXPONENT, exponent.data(), exponent.size() },
  };

  CK_OBJECT_HANDLE key;
  EngineP11& p11 = EngineP11::getInstance();

  CK_RV rv = CKR_OK;
  rv = F->C_CreateObject(p11.getSession(), t, 8, &key);
  if (rv != CKR_OK) {
    return 0;
  }
  return key;
}

CK_OBJECT_HANDLE findKey(CK_OBJECT_CLASS type, int keyId, const string& label) {
  int attrLen = 3;
  CK_BYTE id[] = { (unsigned char) keyId };
  CK_BYTE* subject = reinterpret_cast<unsigned char*>(const_cast<char*>(label.c_str()));
  CK_OBJECT_CLASS keyClass = type;
  CK_KEY_TYPE pKeyType = CKK_RSA;
  CK_ATTRIBUTE t[] = {
    { CKA_CLASS, &keyClass, sizeof(keyClass) },
    { CKA_KEY_TYPE,  &pKeyType, sizeof(pKeyType) },
    { CKA_LABEL, subject, label.size()},
    { CKA_ID, id, sizeof(id) },
  };
  if (keyId > -1) {
    t[3] = { CKA_ID, id, sizeof(id) };
    attrLen = 4;
  }
  CK_ULONG objectCount;
  CK_OBJECT_HANDLE key;
  EngineP11& p11 = EngineP11::getInstance();

  CK_RV rv = CKR_OK;
  rv = F->C_FindObjectsInit(p11.getSession(), t, attrLen);
  if (rv != CKR_OK) {
    return 0;
  }

  rv = F->C_FindObjects(p11.getSession(), &key, 1, &objectCount);
  if (rv != CKR_OK) {
    return 0;
  }

  rv = F->C_FindObjectsFinal(p11.getSession());
  if (objectCount == 0) return 0;
  return key;
}

CK_OBJECT_HANDLE findKey(CK_OBJECT_CLASS type, const string& label) {
  return findKey(type, -1, label);
}


int rsaPubEncrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding) {
  (void) rsa;
  (void) padding;

  EngineP11& p11 = EngineP11::getInstance();
  CK_RSA_PKCS_OAEP_PARAMS oaepParams = {CKM_SHA_1, CKG_MGF1_SHA1, 1, nullptr, 0 };
  CK_MECHANISM mechanism = {
    CKM_RSA_PKCS_OAEP, &oaepParams, sizeof(oaepParams)
  };

  CK_OBJECT_HANDLE key;
  if ((int)p11.getKeyId() > -1 || strlen(p11.getKeyLabel().c_str()) > 0) {
    key = findKey(CKO_PUBLIC_KEY, p11.getKeyId(), p11.getKeyLabel().c_str());
  } else {
    key = findPublicKey(rsa);
  }

  if (key == 0) {
    key = keyFromRSA(rsa); // Try to make up one then
    if (key == 0) {
      return 0;
    }
  }

  CK_RV rv = F->C_EncryptInit(p11.getSession(), &mechanism, key);
  if (rv != CKR_OK) {
    return 0;
  }

  CK_ULONG outLength;
  rv = F->C_Encrypt(p11.getSession(), const_cast<unsigned char*>(from), flen, to, &outLength);
  if (rv != CKR_OK) {
    return 0;
  }

  return outLength;
}


int rsaPrivDecrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding) {
  (void) rsa;
  (void) padding;

  EngineP11& p11 = EngineP11::getInstance();
  CK_RSA_PKCS_OAEP_PARAMS oaepParams = {CKM_SHA_1, CKG_MGF1_SHA1, 1, nullptr, 0 };
  CK_MECHANISM mechanism = {
    CKM_RSA_PKCS_OAEP, &oaepParams, sizeof(oaepParams)
  };

  CK_OBJECT_HANDLE key;
  if ((int)p11.getKeyId() > -1 || strlen(p11.getKeyLabel().c_str()) > 0) {
    key = findKey(CKO_PRIVATE_KEY, p11.getKeyId(), p11.getKeyLabel().c_str());
  } else {
    key = findPrivateKey(rsa);
  }
  if (key == 0) {
    return 0;
  }

  CK_RV rv = F->C_DecryptInit(p11.getSession(), &mechanism, key);
  if (rv != CKR_OK) {
    return 0;
  }

  CK_ULONG outLength = flen;
  rv = F->C_Decrypt(p11.getSession(), const_cast<unsigned char*>(from), flen, to, &outLength);

  return outLength;
}

bool populateMechanism(CK_MECHANISM* m, int type) {
  (void) m;
  (void) type;
  bool retval = false;
  switch (type) {
  case NID_sha224:
      m->mechanism = CKM_SHA224_RSA_PKCS;
      retval = true;
      break;
  case NID_sha256:
      m->mechanism = CKM_SHA256_RSA_PKCS;
      retval = true;
      break;
  case NID_sha384:
      m->mechanism = CKM_SHA384_RSA_PKCS;
      retval = true;
      break;
  case NID_sha512:
      m->mechanism = CKM_SHA512_RSA_PKCS;
      retval = true;
      break;
  case NID_sha1:
      m->mechanism = CKM_SHA1_RSA_PKCS;
      retval = true;
      break;
  }
  return retval;
}

int rsaSign(int type, const unsigned char *from, unsigned int flen, unsigned char *to, unsigned int *siglen, const RSA *rsa) {
  (void) rsa;

  EngineP11& p11 = EngineP11::getInstance();
  CK_MECHANISM mechanism = {
    CKM_SHA256_RSA_PKCS, nullptr, 0
  };

  if (!populateMechanism(&mechanism, type)) {
    return 0;
  }

  CK_OBJECT_HANDLE key;
  if ((int)p11.getKeyId() > -1 || strlen(p11.getKeyLabel().c_str()) > 0) {
    key = findKey(CKO_PRIVATE_KEY, p11.getKeyId(), p11.getKeyLabel().c_str());
  } else {
    key = findPrivateKey(rsa);
  }
  if (key == 0) {
    return 0;
  }

  CK_OBJECT_HANDLE pubKey = findKey(CKO_PUBLIC_KEY, p11.getKeyId(), p11.getKeyLabel().c_str());
  if (pubKey == 0) {
    pubKey = findPublicKey(rsa);
    if (pubKey == 0) {
      return 0;
    }
  }

  CK_ULONG bits;
  CK_ATTRIBUTE pubValueT[] = {
    {CKA_MODULUS_BITS, &bits, sizeof(bits)}
  };

  CK_RV rv = F->C_GetAttributeValue(p11.getSession(), pubKey, pubValueT, 1);
  if (rv != CKR_OK) {
    return 0;
  }

  rv = F->C_SignInit(p11.getSession(), &mechanism, key);
  if (rv != CKR_OK) {
    return 0;
  }
  CK_ULONG outLength = bits/8;
  rv = F->C_Sign(p11.getSession(), const_cast<unsigned char*>(from), flen, to, &outLength);
  if (rv != CKR_OK) {
    return 0;
  }

  *siglen = (unsigned int) outLength;

  return 1;
}

// Currently unused since it can be done outside the token and it only requires a public key
int rsaVerify(int type, const unsigned char *from, unsigned int flen, const unsigned char *sig, unsigned int siglen, const RSA *rsa) {
  (void) rsa;
  (void) type;

  EngineP11& p11 = EngineP11::getInstance();
  CK_MECHANISM mechanism = {
     CKM_SHA256_RSA_PKCS, nullptr, 0
  };
  if (!populateMechanism(&mechanism, type)) {
    return 0;
  }

  CK_OBJECT_HANDLE key = findKey(CKO_PUBLIC_KEY, p11.getKeyId(), p11.getKeyLabel().c_str());

  if (key == 0) {
    key = keyFromRSA(rsa); // Try to make up one then
    if (key == 0) {
      return 0;
    }
  }

  CK_RV rv = F->C_VerifyInit(p11.getSession(), &mechanism, key);
  if (rv != CKR_OK) {
    return 0;
  }
  rv = F->C_Verify(p11.getSession(), const_cast<unsigned char*>(from), flen, const_cast<unsigned char*>(sig), siglen);
  if (rv != CKR_OK) {
    return 0;
  }

  return 1;
}




const RSA_METHOD* rsaMethod() {
  static RSA_METHOD* m = nullptr;

  if (m == nullptr) {
    m = const_cast<RSA_METHOD*>(RSA_get_default_method());
    m->flags = RSA_FLAG_SIGN_VER;
    m->rsa_keygen = rsaKeygen;
    m->rsa_pub_enc = rsaPubEncrypt;
    m->rsa_priv_dec = rsaPrivDecrypt;
    m->rsa_sign = rsaSign;
    m->rsa_verify = rsaVerify;
  }
  return m;
}

static const int meths[] = {
  EVP_PKEY_RSA,
};

static int pkey_meths(ENGINE*e, EVP_PKEY_METHOD** meth, const int** nids, int nid) {
  (void) e;
  (void) meth;
  (void) nids;
  (void) nid;

  if (nid == EVP_PKEY_RSA) {
    *meth = const_cast<EVP_PKEY_METHOD*>(EVP_PKEY_meth_find(nid));
    return 1;
  } else if (nid != 0) {
    return 0;
  }
  if (nids != NULL) {
    *nids = meths;
    return 1;
  }
  return 0;
}


int e_init(ENGINE* e) {
  (void) e;

  return 1;
}

namespace Erpiko {

void
EngineP11::init() {
  if (initialized) return;
  if (erpikoEngine != nullptr) {
    ENGINE_free(erpikoEngine);
    erpikoEngine = nullptr;
  }
  erpikoEngine = ENGINE_new();
  if (
      ENGINE_set_id(erpikoEngine, "Erpiko-P11") &&
      ENGINE_set_name(erpikoEngine, "Erpiko-P11 Engine") &&
      ENGINE_set_init_function(erpikoEngine, e_init) &&
      ENGINE_set_RSA(erpikoEngine, rsaMethod()) &&
      ENGINE_set_pkey_meths(erpikoEngine, pkey_meths)
      )
  {
    if (ENGINE_init(erpikoEngine)) {
      initialized = true;
    }
  }
}

bool
EngineP11::load(const string path) {
  if (lib && F) return true;

#ifdef WIN32
  if (lib != nullptr) {
	  FreeLibrary(lib);
	  lib = nullptr;
  }
  lib = LoadLibrary(TEXT(path.c_str()));

  if (!lib) {
	  DWORD dw = GetLastError();
	  std::cout << "Could not load the dynamic library: " << path << ": 0x" << hex << dw << std::endl;

	  return false;
  }

  CK_C_GetFunctionList getF = (CK_C_GetFunctionList)GetProcAddress(lib, "C_GetFunctionList");


#else
  if (lib) {
    dlclose(lib);
    lib = nullptr;
  }

  lib = dlopen(path.c_str(), RTLD_LAZY);
  if (!lib) {
    return false;
  }
  auto getF = reinterpret_cast<CK_C_GetFunctionList> (reinterpret_cast<long long> (dlsym(lib, "C_GetFunctionList")));
#endif

  if (getF != nullptr) {
    CK_RV rv = getF(&F);
    if (rv != CKR_OK) {
      lib = nullptr;
      F = nullptr;
		return false;
    }
	rv = F->C_Initialize(nullptr);
	if (rv != CKR_OK) {
      lib = nullptr;
      F = nullptr;
		return false;
	}
	return true;
  }
  cout << "This is not a PKCS#11 library\n";

  lib = nullptr;
  F = nullptr;
  return false;
}

void
EngineP11::finalize() {
  if (F != nullptr) {
    F->C_Finalize(nullptr);
    F = nullptr;
#ifdef WIN32
	FreeLibrary(lib);
#else
    dlclose(lib);
#endif
    lib = nullptr;
  }
}

bool
EngineP11::logout() {
  if (F->C_Logout(session) == CKR_OK &&
      F->C_CloseSession(session) == CKR_OK) {
    session = 0;
    return true;
  }
  return false;
}

CardStatus::Value EngineP11::waitForCardStatus(int &slot) {
  std::cout << "Waiting for the slot event...\n";
  CK_SLOT_ID slotId;
  CK_RV rvslot = F->C_WaitForSlotEvent(0, &slotId, nullptr);

  // Some driver like acospkcs11.dll could not handle C_WaitForSlotEvent
  if (rvslot != CKR_TOKEN_NOT_PRESENT
  && rvslot != CKR_ARGUMENTS_BAD
  && rvslot != CKR_CRYPTOKI_NOT_INITIALIZED
  && rvslot != CKR_FUNCTION_FAILED
  && rvslot != CKR_GENERAL_ERROR
  && rvslot != CKR_HOST_MEMORY
  && rvslot != CKR_NO_EVENT
  && rvslot != CKR_OK
  ) {
    return CardStatus::NOT_SUPPORTED;
  }
  if (rvslot != CKR_OK) {
    return CardStatus::NOT_PRESENT;
  }

  CK_TOKEN_INFO pInfo;
  slot = (int)slotId;
  CK_RV rv = F->C_GetTokenInfo(slotId, &pInfo);
  if (rv == CKR_TOKEN_NOT_PRESENT) {
    return CardStatus::NOT_PRESENT;
  }

  return CardStatus::PRESENT;
}

bool
EngineP11::login(const unsigned long slot, const string& pin) {
  if (!F && !F->C_OpenSession) return false;
  if (!F && !F->C_Login) return false;

  CK_RV rv = F->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                          nullptr, nullptr, &session);
  if (rv != CKR_OK) return false;
  rv = F->C_Login(session, CKU_USER, reinterpret_cast<unsigned char*>(const_cast<char*>(pin.c_str())), pin.size());
  if (rv != CKR_OK) return false;
  return true;
}


TokenOpResult::Value
EngineP11::putData(const std::string& applicationName, std::string& label, std::vector<unsigned char> data, bool isUnique) {
  CK_OBJECT_CLASS keyClass = CKO_DATA;
  CK_BBOOL trueValue = CK_TRUE;
  CK_BYTE* labelByte = reinterpret_cast<unsigned char*>(const_cast<char*>(label.c_str()));
  CK_BYTE* appNameByte = reinterpret_cast<unsigned char*>(const_cast<char*>(applicationName.c_str()));
  CK_RV rv = CKR_OK;

  EngineP11& p11 = EngineP11::getInstance();

  if (isUnique) {
    CK_ATTRIBUTE t[] = {
      { CKA_CLASS, &keyClass, sizeof(keyClass) },
      { CKA_TOKEN, &trueValue, sizeof(trueValue) },
      { CKA_PRIVATE, &trueValue, sizeof(trueValue) },
      { CKA_APPLICATION, appNameByte, applicationName.size()},
      { CKA_LABEL, labelByte, label.size()}
    };
    CK_OBJECT_HANDLE obj;

    rv = F->C_FindObjectsInit(p11.getSession(), t, 5);
    if (rv != CKR_OK) {
      return TokenOpResult::GENERIC_ERROR;
    }

    CK_ULONG objectCount;
    bool first = true;
    bool found = false;
    while (true) {
      rv = F->C_FindObjects(p11.getSession(), &obj, 1, &objectCount);
      if (rv != CKR_OK) {
        return TokenOpResult::GENERIC_ERROR;
      }

      if (objectCount == 1) {
        // Override value
        found = true;
        if (first) {
          CK_ATTRIBUTE setTemplate[] = {
            CKA_VALUE, data.data(), (CK_ULONG) data.size()
          };
          rv = F->C_SetAttributeValue(p11.getSession(), obj, setTemplate, 1);
          if (rv != CKR_OK) {
            switch (rv) {
              case CKR_DATA_LEN_RANGE:
              case CKR_DEVICE_MEMORY:
                return TokenOpResult::TOO_LARGE;
                break;
              case CKR_SESSION_READ_ONLY:
              case CKR_TOKEN_WRITE_PROTECTED:
                return TokenOpResult::READ_ONLY;
                break;
              default:
                return TokenOpResult::GENERIC_ERROR;
                break;
            }
          }

          first = false;
        } else {
          // Destroy all other occurences
          F->C_DestroyObject(p11.getSession(), obj);
        }
      } else {
        break;
      }
    }
    F->C_FindObjectsFinal(p11.getSession());
    if (found) {
      return TokenOpResult::SUCCESS;
    }
    // fall through if label was not found
  }

  CK_ATTRIBUTE t[] = {
    { CKA_CLASS, &keyClass, sizeof(keyClass) },
    { CKA_TOKEN, &trueValue, sizeof(trueValue) },
    { CKA_PRIVATE, &trueValue, sizeof(trueValue) },
    { CKA_LABEL, labelByte, label.size()},
    { CKA_APPLICATION, appNameByte, applicationName.size()},
    { CKA_VALUE, data.data(), (CK_ULONG) data.size() }
  };

  CK_OBJECT_HANDLE obj;

  rv = F->C_CreateObject(p11.getSession(), t, 6, &obj);
  if (rv != CKR_OK) {
    switch (rv) {
      case CKR_DATA_LEN_RANGE:
      case CKR_DEVICE_MEMORY:
        return TokenOpResult::TOO_LARGE;
        break;
      case CKR_SESSION_READ_ONLY:
      case CKR_TOKEN_WRITE_PROTECTED:
        return TokenOpResult::READ_ONLY;
        break;
      default:
        return TokenOpResult::GENERIC_ERROR;
        break;
    }
  }

  return TokenOpResult::SUCCESS;
}

std::vector<unsigned char> EngineP11::getData(const std::string& applicationName, std::string& label) {
  CK_OBJECT_CLASS keyClass = CKO_DATA;
  CK_BBOOL trueValue = CK_TRUE;
  CK_BYTE* labelByte = reinterpret_cast<unsigned char*>(const_cast<char*>(label.c_str()));
  CK_BYTE* appNameByte = reinterpret_cast<unsigned char*>(const_cast<char*>(applicationName.c_str()));
  CK_ATTRIBUTE t[] = {
    { CKA_CLASS, &keyClass, sizeof(keyClass) },
    { CKA_TOKEN, &trueValue, sizeof(trueValue) },
    { CKA_PRIVATE, &trueValue, sizeof(trueValue) },
    { CKA_APPLICATION, appNameByte, applicationName.size()},
    { CKA_LABEL, labelByte, label.size()}
  };
  CK_OBJECT_HANDLE obj;
  EngineP11& p11 = EngineP11::getInstance();

  std::vector<unsigned char> v;
  CK_RV rv = CKR_OK;
  rv = F->C_FindObjectsInit(p11.getSession(), t, 5);
  if (rv != CKR_OK) {
    return v;
  }

  CK_ULONG objectCount;
  rv = F->C_FindObjects(p11.getSession(), &obj, 1, &objectCount);
  if (rv != CKR_OK) {
    return v;
  }

  F->C_FindObjectsFinal(session);
  CK_ATTRIBUTE attribute;
  attribute.type = CKA_VALUE;
  attribute.pValue = NULL_PTR;
  rv = F->C_GetAttributeValue(p11.getSession(), obj, &attribute, 1);
  if (rv != CKR_OK) {
    return v;
  }

  if (attribute.ulValueLen == 0) {
    return v;
  }

  v.resize(attribute.ulValueLen);
  attribute.pValue = &v.front();
  rv = F->C_GetAttributeValue(p11.getSession(), obj, &attribute, 1);
  if (rv != CKR_OK) {
    return v;
  }

  return v;
}

std::vector<std::vector<unsigned char>> EngineP11::getAllData(const std::string& applicationName, std::string& label) {
  CK_OBJECT_CLASS keyClass = CKO_DATA;
  CK_BBOOL trueValue = CK_TRUE;
  CK_BYTE* labelByte = reinterpret_cast<unsigned char*>(const_cast<char*>(label.c_str()));
  CK_BYTE* appNameByte = reinterpret_cast<unsigned char*>(const_cast<char*>(applicationName.c_str()));
  CK_ATTRIBUTE t[] = {
    { CKA_CLASS, &keyClass, sizeof(keyClass) },
    { CKA_TOKEN, &trueValue, sizeof(trueValue) },
    { CKA_PRIVATE, &trueValue, sizeof(trueValue) },
    { CKA_APPLICATION, appNameByte, applicationName.size()},
    { CKA_LABEL, labelByte, label.size()}
  };
  CK_OBJECT_HANDLE obj;
  EngineP11& p11 = EngineP11::getInstance();

  std::vector<std::vector<unsigned char>> v;
  CK_RV rv = CKR_OK;
  rv = F->C_FindObjectsInit(p11.getSession(), t, 5);
  if (rv != CKR_OK) {
    return v;
  }

  CK_ULONG objectCount;
  while (true) {
    rv = F->C_FindObjects(p11.getSession(), &obj, 1, &objectCount);
    if (rv != CKR_OK) {
      return v;
    }

    if (objectCount != 1) {
      break;
    }

    CK_ATTRIBUTE attribute;
    attribute.type = CKA_VALUE;
    attribute.pValue = NULL_PTR;
    rv = F->C_GetAttributeValue(p11.getSession(), obj, &attribute, 1);
    if (rv != CKR_OK) {
      return v;
    }

    if (attribute.ulValueLen == 0) {
      return v;
    }

    std::vector<unsigned char> value;
    value.resize(attribute.ulValueLen);
    attribute.pValue = &value.front();
    rv = F->C_GetAttributeValue(p11.getSession(), obj, &attribute, 1);
    if (rv != CKR_OK) {
      return v;
    }

    v.push_back(value);
  }

  F->C_FindObjectsFinal(session);
  return v;
}

bool EngineP11::removeData(const std::string& applicationName, const std::string& label) {
  CK_OBJECT_CLASS keyClass = CKO_DATA;
  CK_BBOOL trueValue = CK_TRUE;
  CK_BYTE* labelByte = reinterpret_cast<unsigned char*>(const_cast<char*>(label.c_str()));
  CK_BYTE* appNameByte = reinterpret_cast<unsigned char*>(const_cast<char*>(applicationName.c_str()));
  CK_ATTRIBUTE t[] = {
    { CKA_CLASS, &keyClass, sizeof(keyClass) },
    { CKA_TOKEN, &trueValue, sizeof(trueValue) },
    { CKA_PRIVATE, &trueValue, sizeof(trueValue) },
    { CKA_APPLICATION, appNameByte, applicationName.size()},
    { CKA_LABEL, labelByte, label.size()}
  };
  CK_OBJECT_HANDLE obj;
  EngineP11& p11 = EngineP11::getInstance();

  std::vector<unsigned char> v;
  CK_RV rv = CKR_OK;
  rv = F->C_FindObjectsInit(p11.getSession(), t, 5);
  if (rv != CKR_OK) {
    return false;
  }

  CK_ULONG objectCount;
  rv = F->C_FindObjects(p11.getSession(), &obj, 1, &objectCount);
  if (rv != CKR_OK) {
    return false;
  }

  F->C_FindObjectsFinal(session);
  return F->C_DestroyObject(p11.getSession(), obj) == CKR_OK ?  true : false;
}

bool EngineP11::parseAttr(CK_OBJECT_HANDLE obj, CK_ATTRIBUTE &attr, std::vector<unsigned char> *value) {
  CK_RV rv;
  rv = F->C_GetAttributeValue(session, obj, &attr, 1);
  if (rv == CKR_OK) {
    if (attr.ulValueLen == (CK_ULONG)(-1)) {
      return false;
    }
    if (attr.type == CKA_LABEL) {
      if (!(attr.pValue = calloc(1, attr.ulValueLen + 1))) {
        // Out of memory
        return false;
      }
    } else if (attr.type == CKA_VALUE) {
      value->resize(attr.ulValueLen);
      attr.pValue = &value->front();
    }

    rv = F->C_GetAttributeValue(session, obj, &attr, 1);
    if (attr.ulValueLen == (CK_ULONG)(-1)) {
      free(attr.pValue);
      return false;
    }
  }
  return true;
}

std::vector<Certificate*> EngineP11::getCertificates(bool withPrivateKey) {
  std::vector<Certificate*> certs;
  std::vector<Certificate*> results;
  CK_OBJECT_HANDLE object;
  CK_ULONG count;
  CK_RV rv;

  CK_OBJECT_CLASS keyClass = CKO_CERTIFICATE;
  CK_CERTIFICATE_TYPE certType =  CKC_X_509;
  CK_BBOOL trueValue = CK_TRUE;

  CK_ATTRIBUTE t[] = {
    { CKA_TOKEN, &trueValue, sizeof(trueValue) },
    { CKA_CLASS, &keyClass, sizeof(keyClass) },
    { CKA_CERTIFICATE_TYPE, &certType, sizeof(certType) },
  };

  rv = F->C_FindObjectsInit(session, t, 3);
  if (rv != CKR_OK) {
    return certs;
  }
  while (true) {
    rv = F->C_FindObjects(session, &object, 1, &count);
    if (rv != CKR_OK) {
      break;
    }
    if (count == 0) {
      break;
    }

    CK_ATTRIBUTE certAttr = {CKA_VALUE, NULL_PTR, 1};
    std::vector<unsigned char> value;
    auto r = parseAttr(object, certAttr, &value);
    if (r && sizeof(value) > 0) {
      auto cert = Certificate::fromDer(value);
      certs.push_back(cert);
    }
  }
  F->C_FindObjectsFinal(session);

  if (withPrivateKey) {
    for (auto const& cert : certs) {
      auto rsaKey = findPrivateKey(cert->publicKey());
      if (rsaKey != 0) {
        results.push_back(cert);
      }
    }
    return results;
  } else {
    return certs;
  }

}

bool EngineP11::removeCertificate(const Certificate& cert) {
  std::string serialNumberStr = cert.serialNumber().toHexString();

  CK_OBJECT_CLASS keyClass = CKO_CERTIFICATE;
  CK_CERTIFICATE_TYPE certType =  CKC_X_509;
  CK_BBOOL trueValue = CK_TRUE;
  CK_BYTE* labelByte = reinterpret_cast<unsigned char*>(const_cast<char*>(serialNumberStr.c_str()));
  CK_ATTRIBUTE t[] = {
    { CKA_CLASS, &keyClass, sizeof(keyClass) },
    { CKA_CERTIFICATE_TYPE, &certType, sizeof(certType) },
    { CKA_TOKEN, &trueValue, sizeof(trueValue) },
    { CKA_LABEL, labelByte, serialNumberStr.size()}
  };
  CK_OBJECT_HANDLE obj;

  std::vector<unsigned char> v;
  CK_RV rv = CKR_OK;
  rv = F->C_FindObjectsInit(session, t, 4);
  if (rv != CKR_OK) {
    return false;
  }

  CK_ULONG objectCount;
  rv = F->C_FindObjects(session, &obj, 1, &objectCount);
  if (rv != CKR_OK) {
    return false;
  }

  F->C_FindObjectsFinal(session);
  return F->C_DestroyObject(session, obj) == CKR_OK ?  true : false;
}

TokenOpResult::Value
EngineP11::putCertificate(const Certificate& cert) {
  auto subjectDer = cert.subjectIdentity().toDer();
  auto serialNumberDer = cert.serialNumber().dump();
  std::string serialNumberStr = cert.serialNumber().toHexString();
  std::vector<unsigned char> data = cert.toDer();

  CK_OBJECT_CLASS keyClass = CKO_CERTIFICATE;
  CK_CERTIFICATE_TYPE certType =  CKC_X_509;
  CK_BBOOL trueValue = CK_TRUE;
  CK_BBOOL falseValue = CK_FALSE;
  // Use serial number hex string as certificate label
  CK_BYTE* labelByte = reinterpret_cast<unsigned char*>(const_cast<char*>(serialNumberStr.c_str()));



  std::vector<CK_ATTRIBUTE> tv {
    { CKA_TOKEN, &trueValue, sizeof(trueValue) },
    { CKA_VALUE, data.data(), (CK_ULONG) data.size() },
    { CKA_CLASS, &keyClass, sizeof(keyClass) },
    { CKA_CERTIFICATE_TYPE, &certType, sizeof(certType) },
    { CKA_PRIVATE, &falseValue, sizeof(falseValue) },
    { CKA_SUBJECT, subjectDer.data(), (CK_ULONG) subjectDer.size() },
    { CKA_SERIAL_NUMBER, serialNumberDer.data() , (CK_ULONG) serialNumberDer.size() },
    { CKA_LABEL, labelByte, (CK_ULONG) serialNumberStr.size()}
  };

  // If keyId is unset, do not add CKA_ID attribute to the vector
  if (keyId.size() != 0)
  {
    CK_ATTRIBUTE caId = { CKA_ID, keyId.data(), (CK_ULONG) keyId.size() };
    tv.push_back(caId);
  }

  CK_RV rv = CKR_OK;
  CK_OBJECT_HANDLE obj;

  rv = F->C_CreateObject(session, tv.data(), tv.size(), &obj);

  if (rv != CKR_OK) {
    switch (rv) {
      case CKR_DATA_LEN_RANGE:
      case CKR_DEVICE_MEMORY:
        return TokenOpResult::TOO_LARGE;
        break;
      case CKR_SESSION_READ_ONLY:
      case CKR_TOKEN_WRITE_PROTECTED:
        return TokenOpResult::READ_ONLY;
        break;
      default:
        return TokenOpResult::GENERIC_ERROR;
        break;
    }
  }

  return TokenOpResult::SUCCESS;
}

std::vector<TokenInfo> EngineP11::getAllTokensInfo() {
  CK_ULONG listCount;
  CK_RV rv;
  CK_SLOT_ID_PTR pSlotList;
  std::vector<TokenInfo> slots;
  rv = F->C_GetSlotList(CK_TRUE, NULL_PTR, &listCount);
  if (rv != CKR_OK || listCount < 1) {
    return slots;
  }
  pSlotList = (CK_SLOT_ID_PTR)malloc(listCount*sizeof(CK_SLOT_ID));
  rv = F->C_GetSlotList(CK_TRUE, pSlotList, &listCount);
  if (rv == CKR_OK) {
    for (int i=0; i < (int)listCount; i++) {
      CK_SLOT_INFO slotInfo;
      CK_TOKEN_INFO tokenInfo;
      TokenInfo tInfo;
      (void) F->C_GetSlotInfo(pSlotList[i], &slotInfo);
      (void) F->C_GetTokenInfo(pSlotList[i], &tokenInfo);
      std::string m = (string)(char*)tokenInfo.manufacturerID;
      tInfo.manufacturer = m.substr(0,32);
      std::string s = (string)(char*)tokenInfo.manufacturerID;
      tInfo.manufacturer = s.substr(0,32);
      s = (string)(char*)tokenInfo.label;
      tInfo.label = s.substr(0,32);
      s = (string)(char*)tokenInfo.model;
      tInfo.model = s.substr(0,16);
      s = (string)(char*)tokenInfo.serialNumber;
      tInfo.serialNumber = s.substr(0,16);
      tInfo.maxSessionCount = (int)tokenInfo.ulMaxSessionCount;
      tInfo.sessionCount = (int)tokenInfo.ulSessionCount;
      tInfo.maxRwSessionCount = (int)tokenInfo.ulMaxRwSessionCount;
      tInfo.rwSessionCount = (int)tokenInfo.ulRwSessionCount;
      tInfo.maxPinlen = (int)tokenInfo.ulMaxPinLen;
      tInfo.minPinlen = (int)tokenInfo.ulMinPinLen;
      tInfo.totalPublicMemory = (int)tokenInfo.ulTotalPublicMemory;
      tInfo.freePublicMemory = (int)tokenInfo.ulFreePublicMemory;
      tInfo.totalPrivateMemory = (int)tokenInfo.ulTotalPrivateMemory;
      tInfo.freePrivateMemory = (int)tokenInfo.ulFreePrivateMemory;
	  tInfo.slotsFlags = slotInfo.flags;
	  tInfo.tokenFlags = tokenInfo.flags;
      slots.push_back(tInfo);
    }
  }
  free(pSlotList);
  return slots;
}

TokenOpResult::Value
EngineP11::putPrivateKey(const RsaKey& data, const std::string& labelStr) {
  EVP_PKEY *evp_key = NULL;
  int keyType;

  evp_key = Converters::rsaKeyToPkey(data);
  keyType = EVP_PKEY_base_id(evp_key);

  // A private key pair of certificate should be a EVP_PKEY_RSA type
  if (keyType !=  EVP_PKEY_RSA) {
    free(evp_key);
    return TokenOpResult::GENERIC_ERROR;
  }

  // Parse the RSA key
  RSA *r = EVP_PKEY_get1_RSA(evp_key);

  PUT(modulus, r->n);
  PUT(publicExponent, r->e);
  PUT(privateExponent, r->d);
  PUT(firstPrime, r->p);
  PUT(secondPrime, r->q);
  PUT(firstExponent, r->dmp1);
  PUT(secondExponent, r->dmq1);
  PUT(coefficient, r->iqmp);

  CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
  CK_BBOOL trueValue = TRUE;
  CK_KEY_TYPE ckaKeyType = CKK_RSA;
  CK_BYTE* labelByte = reinterpret_cast<unsigned char*>(const_cast<char*>(labelStr.c_str()));

  std::vector<CK_ATTRIBUTE> tv {
    // Mandatory attribute
    {CKA_CLASS, &keyClass, sizeof(keyClass) },
    {CKA_TOKEN, &trueValue, sizeof(trueValue)},
    {CKA_PRIVATE, &trueValue, sizeof(trueValue)},
    {CKA_SENSITIVE, &trueValue, sizeof(trueValue)},
    // The label for identification
    { CKA_LABEL, labelByte, (CK_ULONG) labelStr.size()},
    // Attributes for EVP_PKEY_RSA
    { CKA_KEY_TYPE, &ckaKeyType, sizeof(ckaKeyType) },
    { CKA_MODULUS, modulus.data(), (CK_ULONG) modulus.size() },
    { CKA_PUBLIC_EXPONENT, publicExponent.data(), (CK_ULONG) publicExponent.size() },
    { CKA_PRIVATE_EXPONENT, privateExponent.data(), (CK_ULONG) privateExponent.size() },
    { CKA_PRIME_1, firstPrime.data(), (CK_ULONG) firstPrime.size() },
    { CKA_PRIME_2, secondPrime.data(), (CK_ULONG) secondPrime.size() },
    { CKA_EXPONENT_1, firstExponent.data(), (CK_ULONG) firstExponent.size() },
    { CKA_EXPONENT_2, secondExponent.data(), (CK_ULONG) secondExponent.size() },
    { CKA_COEFFICIENT, coefficient.data(), (CK_ULONG) coefficient.size() }
  };

  // If keyId is unset, do not add CKA_ID attribute to the vector
  if (keyId.size() != 0)
  {
    CK_ATTRIBUTE caId = { CKA_ID, keyId.data(), (CK_ULONG) keyId.size() };
    tv.push_back(caId);
  }

  CK_RV rv = CKR_OK;
  CK_OBJECT_HANDLE obj;

  rv = F->C_CreateObject(session, tv.data(), tv.size(), &obj);

  free(evp_key);
  if (rv != CKR_OK) {
    switch (rv) {
      case CKR_DATA_LEN_RANGE:
      case CKR_DEVICE_MEMORY:
        return TokenOpResult::TOO_LARGE;
        break;
      case CKR_SESSION_READ_ONLY:
      case CKR_TOKEN_WRITE_PROTECTED:
        return TokenOpResult::READ_ONLY;
        break;
      default:
        return TokenOpResult::GENERIC_ERROR;
        break;
    }
  }

  return TokenOpResult::SUCCESS;
}

bool EngineP11::removePrivateKey(const std::string& labelStr) {
  CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
  CK_KEY_TYPE ckaKeyType = CKK_RSA;
  CK_BBOOL trueValue = CK_TRUE;
  CK_BYTE* labelByte = reinterpret_cast<unsigned char*>(const_cast<char*>(labelStr.c_str()));
  CK_ATTRIBUTE t[] = {
    { CKA_CLASS, &keyClass, sizeof(keyClass) },
    { CKA_TOKEN, &trueValue, sizeof(trueValue) },
    { CKA_KEY_TYPE, &ckaKeyType, sizeof(ckaKeyType) },
    { CKA_LABEL, labelByte, labelStr.size()}
  };
  CK_OBJECT_HANDLE obj;
  EngineP11& p11 = EngineP11::getInstance();

  std::vector<unsigned char> v;
  CK_RV rv = CKR_OK;
  rv = F->C_FindObjectsInit(p11.getSession(), t, 4);
  if (rv != CKR_OK) {
    return false;
  }

  CK_ULONG objectCount;
  rv = F->C_FindObjects(p11.getSession(), &obj, 1, &objectCount);
  if (rv != CKR_OK) {
    return false;
  }

  F->C_FindObjectsFinal(session);
  return F->C_DestroyObject(p11.getSession(), obj) == CKR_OK ?  true : false;
}

RsaKey* EngineP11::getPrivateKey(const RsaPublicKey& publicKey) {
  auto key = findPrivateKey(publicKey);
  auto modulus = publicKey.modulus().dump();
  auto exponent = publicKey.exponent().dump();

  if (!key) return nullptr;

  RsaKey* ret = nullptr;
  RSA* rsa = RSA_new();
  BIGNUM* empty = BN_new();
  BN_one(empty);
  EVP_PKEY* evp = EVP_PKEY_new();
  if ((rsa->n = BN_bin2bn(modulus.data(), modulus.size(), nullptr)) != nullptr)
  if ((rsa->e = BN_bin2bn(exponent.data(), exponent.size(), nullptr)) != nullptr)
  {
    rsa->d = empty;
    rsa->p = empty;
    rsa->q = empty;
    rsa->dmp1 = empty;
    rsa->dmq1 = empty;
    rsa->iqmp = empty;

    EVP_PKEY_set1_RSA(evp, rsa);
    auto der = Converters::rsaKeyToDer(evp, "");
    ret = RsaKey::fromDer(der);
  }
  if (!ret && rsa) {
    RSA_free(rsa);
  }

  if (evp) {
    EVP_PKEY_free(evp);
  }
  if (empty) {
    BN_free(empty);
  }
  return ret;
}

} // namespace Erpiko
