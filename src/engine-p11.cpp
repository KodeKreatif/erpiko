#include "engine-p11.h"
#include "erpiko/utils.h"
#include "pkcs11/cryptoki.h"
#include <iostream>
#include <string>
#include <openssl/engine.h>
#include <openssl/rsa.h>
#include <dlfcn.h>

ENGINE *erpikoEngine = nullptr;
CK_FUNCTION_LIST_PTR F;

using namespace std;
using namespace Erpiko;

int rsaKeygen(RSA *rsa, int bits, BIGNUM *exp, BN_GENCB *cb) {
  (void) cb;

  char* eStr = BN_bn2hex(exp);
  if (!eStr) return 0;
  auto v = Utils::fromHexString(eStr);
  CK_BYTE publicExponent[v.size()];
  for (unsigned int i = 0; i < v.size(); i ++) {
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
  CK_BYTE id[] = { p11.getKeyId() };
  CK_BBOOL trueValue = CK_TRUE;
  CK_ATTRIBUTE publicKeyTemplate[] = {
    {CKA_ID, id, 3},
    {CKA_LABEL, subject, p11.getKeyLabel().size()},
    {CKA_TOKEN, &trueValue, sizeof(trueValue)},
    {CKA_ENCRYPT, &trueValue, sizeof(trueValue)},
    {CKA_VERIFY, &trueValue, sizeof(trueValue)},
    {CKA_WRAP, &trueValue, sizeof(trueValue)},
    {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
    {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)}
  };
  CK_ATTRIBUTE privateKeyTemplate[] = {
    {CKA_ID, id, sizeof(id)},
    {CKA_LABEL, subject, 5},
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
      publicKeyTemplate, 8,
      privateKeyTemplate, 8,
      &publicKey,
      &privateKey);

  unsigned char e[1024] = { 0 };
  unsigned char n[1024] = { 0 };
  CK_ATTRIBUTE privValueT[] = {
    {CKA_PUBLIC_EXPONENT, e, sizeof(e)},
    {CKA_MODULUS, n, sizeof(n)}
  };

  rv = F->C_GetAttributeValue(p11.getSession(), privateKey, privValueT, 2);
  std::vector<unsigned char> vec(e, e + privValueT[0].ulValueLen);

  if (rv == CKR_OK)
  if ((rsa->e = BN_bin2bn(vec.data(), vec.size(), nullptr)) != nullptr)
  if ((rsa->n = BN_bin2bn(n, privValueT[1].ulValueLen, nullptr)) != nullptr)
  {
    return 1;
  }
  return 0;
}

const RSA_METHOD* rsaMethod() {
  static RSA_METHOD* m = nullptr;

  if (m == nullptr) {
    m = const_cast<RSA_METHOD*>(RSA_get_default_method());
    m->flags = 0;
    m->rsa_keygen = rsaKeygen;
  }
  return m;
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
      ENGINE_set_RSA(erpikoEngine, rsaMethod())
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

  if (lib) {
    dlclose(lib);
    lib = nullptr;
  }

  lib = dlopen(path.c_str(), RTLD_LAZY);
  if (!lib) {
    return false;
  }
  auto getF = reinterpret_cast<CK_C_GetFunctionList> (reinterpret_cast<long long> (dlsym(lib, "C_GetFunctionList")));
  if (getF != nullptr) {
    CK_RV rv = getF(&F);
    if (rv == CKR_OK) {
      return F->C_Initialize(nullptr) == CKR_OK;
    }
  }
  return false;
}

void
EngineP11::finalize() {
  if (F != nullptr) {
    F->C_Finalize(nullptr);
    F = nullptr;
    dlclose(lib);
    lib = nullptr;
  }
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
