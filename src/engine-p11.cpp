#include "erpiko/utils.h"
#include <iostream>
#include <string>
#include "engine-p11.h"
#include "pkcs11/cryptoki.h"
#include <openssl/engine.h>
#include <openssl/rsa.h>
#ifdef WIN32
#include <Windows.h>
#else
#include <dlfcn.h>
#endif

ENGINE *erpikoEngine = nullptr;
CK_FUNCTION_LIST_PTR F;

using namespace std;
using namespace Erpiko;

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

CK_OBJECT_HANDLE findKey(CK_OBJECT_CLASS type, int keyId, const string& label) {
  CK_BYTE id[] = { (unsigned char) keyId };
  CK_BYTE* subject = reinterpret_cast<unsigned char*>(const_cast<char*>(label.c_str()));
  CK_OBJECT_CLASS keyClass = type;
  CK_KEY_TYPE pKeyType = CKK_RSA;
  CK_ATTRIBUTE t[] = {
    { CKA_CLASS, &keyClass, sizeof(keyClass) },
    { CKA_KEY_TYPE,  &pKeyType, sizeof(pKeyType) },
    { CKA_ID, id, sizeof(id) },
    { CKA_LABEL, subject, label.size()}
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


int rsaPubEncrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding) {
  (void) rsa;
  (void) padding;

  EngineP11& p11 = EngineP11::getInstance();
  CK_RSA_PKCS_OAEP_PARAMS oaepParams = {CKM_SHA_1, CKG_MGF1_SHA1, 1, nullptr, 0 };
  CK_MECHANISM mechanism = {
    CKM_RSA_PKCS_OAEP, &oaepParams, sizeof(oaepParams)
  };

  CK_OBJECT_HANDLE key = findKey(CKO_PUBLIC_KEY, p11.getKeyId(), p11.getKeyLabel().c_str());
  if (key == 0) {
    return 0;
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

  CK_OBJECT_HANDLE key = findKey(CKO_PRIVATE_KEY, p11.getKeyId(), p11.getKeyLabel().c_str());
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
  CK_OBJECT_HANDLE key = findKey(CKO_PRIVATE_KEY, p11.getKeyId(), p11.getKeyLabel().c_str());
  if (key == 0) {
    return 0;
  }

  CK_OBJECT_HANDLE pubKey = findKey(CKO_PUBLIC_KEY, p11.getKeyId(), p11.getKeyLabel().c_str());
  if (pubKey == 0) {
    return 0;
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
		return false;
    }
	rv = F->C_Initialize(nullptr);
	if (rv != CKR_OK) {
		return false;
	}
	return true;
  }
  cout << "This is not a PKCS#11 library\n";

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

bool EngineP11::waitForSlotEvent(int &slot) {
  std::cout << "Waiting for the slot event...\n";
  CK_SLOT_ID slotId; 
  CK_RV rvslot = F->C_WaitForSlotEvent(0, &slotId, nullptr);
  if (rvslot != CKR_OK) {
    return false;
  }
  CK_TOKEN_INFO pInfo;
  slot = (int)slotId;
  CK_RV rv = F->C_GetTokenInfo(slotId, &pInfo);
  if (rv == CKR_TOKEN_NOT_PRESENT) {
    return false;
  }
  return true;
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

} // namespace Erpiko
