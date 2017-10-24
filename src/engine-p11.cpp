#include "engine-p11.h"
#include "pkcs11/cryptoki.h"
#include <iostream>
#include <string>
#include <openssl/engine.h>
#include <openssl/rsa.h>
#include <dlfcn.h>

ENGINE *erpikoEngine = nullptr;
CK_FUNCTION_LIST_PTR F;

using namespace std;

int rsaKeygen(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb) {
  (void) rsa;
  (void) bits;
  (void)e;
  (void) cb;
  return 1;
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
  void *lib = dlopen(path.c_str(), RTLD_LAZY);
  if (!lib) {
    return false;
  }
  auto getF = reinterpret_cast<CK_C_GetFunctionList> (reinterpret_cast<long long> (dlsym(lib, "C_GetFunctionList")));
  if (getF != nullptr) {
    CK_RV rv = getF(&F);
    if (rv == CKR_OK) {
      return true;
    }
  }
  return false;
}

} // namespace Erpiko
