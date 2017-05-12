#ifndef _SIM_OPENSSL_H
#define _SIM_OPENSSL_H

#include "openssl/opensslconf.h"
#include "openssl/asn1.h"
#include "openssl/asn1t.h"
#include "openssl/x509.h"

extern "C" {

typedef struct sim_st {
  X509_ALGOR *hashAlgorithm;
  ASN1_OCTET_STRING *authorityRandom;
  ASN1_OCTET_STRING *pepsi;
} SIM;

static const ASN1_TEMPLATE SIM_seq_tt[] = {
  {
    0,
    0,
    offsetof(SIM, hashAlgorithm),
    "hashAlgorithm",
    &X509_ALGOR_it,
  },
  {
    0,
    0,
    offsetof(SIM, authorityRandom),
    "authorityRandom",
    &ASN1_OCTET_STRING_it,
  },
  {
    0,
    0,
    offsetof(SIM, pepsi),
    "pepsi",
    &ASN1_OCTET_STRING_it,
  },
};

const ASN1_ITEM SIM_it = {
  ASN1_ITYPE_SEQUENCE,
  V_ASN1_SEQUENCE,
  SIM_seq_tt,
  sizeof(SIM_seq_tt) / sizeof(ASN1_TEMPLATE),
  NULL,
  sizeof(SIM),
  "SIM",
};

DECLARE_ASN1_FUNCTIONS(SIM)

SIM*
d2i_SIM(SIM **a, const unsigned char **in, long len)
{
  return (SIM*)ASN1_item_d2i((ASN1_VALUE **)a, in, len,
      &SIM_it);
}

int
i2d_SIM(SIM *a, unsigned char **out)
{
  return ASN1_item_i2d((ASN1_VALUE *)a, out, &SIM_it);
}

SIM*
SIM_new(void)
{
  return (SIM *)ASN1_item_new(&SIM_it);
}

void
SIM_free(SIM *a)
{
  ASN1_item_free((ASN1_VALUE *)a, &SIM_it);
}


typedef struct sim_pepsi_st {
  ASN1_UTF8STRING *userPassword;
  ASN1_OCTET_STRING *authorityRandom;
  ASN1_OBJECT *siiType;
  ASN1_UTF8STRING *sii;
} SIM_PEPSI;

static const ASN1_TEMPLATE SIM_PEPSI_seq_tt[] = {
  {
    0,
    0,
    offsetof(SIM_PEPSI, userPassword),
    "userPassword",
    &ASN1_UTF8STRING_it,
  },
  {
    0,
    0,
    offsetof(SIM_PEPSI, authorityRandom),
    "authorityRandom",
    &ASN1_OCTET_STRING_it,
  },
  {
    0,
    0,
    offsetof(SIM_PEPSI, siiType),
    "siiType",
    &ASN1_OBJECT_it,
  },
  {
    0,
    0,
    offsetof(SIM_PEPSI, sii),
    "sii",
    &ASN1_UTF8STRING_it,
  },
};

const ASN1_ITEM SIM_PEPSI_it = {
  ASN1_ITYPE_SEQUENCE,
  V_ASN1_SEQUENCE,
  SIM_PEPSI_seq_tt,
  sizeof(SIM_PEPSI_seq_tt) / sizeof(ASN1_TEMPLATE),
  NULL,
  sizeof(SIM_PEPSI),
  "SIM_PEPSI",
};

DECLARE_ASN1_FUNCTIONS(SIM_PEPSI)

SIM_PEPSI*
d2i_SIM_PEPSI(SIM_PEPSI **a, const unsigned char **in, long len)
{
  return (SIM_PEPSI*)ASN1_item_d2i((ASN1_VALUE **)a, in, len,
      &SIM_PEPSI_it);
}

int
i2d_SIM_PEPSI(SIM_PEPSI *a, unsigned char **out)
{
  return ASN1_item_i2d((ASN1_VALUE *)a, out, &SIM_PEPSI_it);
}

SIM_PEPSI*
SIM_PEPSI_new(void)
{
  return (SIM_PEPSI *)ASN1_item_new(&SIM_PEPSI_it);
}

void
SIM_PEPSI_free(SIM_PEPSI *a)
{
  ASN1_item_free((ASN1_VALUE *)a, &SIM_PEPSI_it);
}



typedef struct sim_epepsi_st {
  ASN1_OBJECT *siiType;
  ASN1_UTF8STRING *sii;
  SIM *sim;
} SIM_EPEPSI;

static const ASN1_TEMPLATE SIM_EPEPSI_seq_tt[] = {
  {
    0,
    0,
    offsetof(SIM_EPEPSI, siiType),
    "siiType",
    &ASN1_OBJECT_it,
  },
  {
    0,
    0,
    offsetof(SIM_EPEPSI, sii),
    "sii",
    &ASN1_UTF8STRING_it,
  },
  {
    0,
    0,
    offsetof(SIM_EPEPSI, sim),
    "sim",
    &SIM_it,
  },
};

const ASN1_ITEM SIM_EPEPSI_it = {
  ASN1_ITYPE_SEQUENCE,
  V_ASN1_SEQUENCE,
  SIM_EPEPSI_seq_tt,
  sizeof(SIM_EPEPSI_seq_tt) / sizeof(ASN1_TEMPLATE),
  NULL,
  sizeof(SIM_EPEPSI),
  "SIM_EPEPSI",
};

DECLARE_ASN1_FUNCTIONS(SIM_EPEPSI)

SIM_EPEPSI*
d2i_SIM_EPEPSI(SIM_EPEPSI **a, const unsigned char **in, long len)
{
  return (SIM_EPEPSI*)ASN1_item_d2i((ASN1_VALUE **)a, in, len,
      &SIM_EPEPSI_it);
}

int
i2d_SIM_EPEPSI(SIM_EPEPSI *a, unsigned char **out)
{
  return ASN1_item_i2d((ASN1_VALUE *)a, out, &SIM_EPEPSI_it);
}

SIM_EPEPSI*
SIM_EPEPSI_new(void)
{
  return (SIM_EPEPSI *)ASN1_item_new(&SIM_EPEPSI_it);
}

void
SIM_EPEPSI_free(SIM_EPEPSI *a)
{
  ASN1_item_free((ASN1_VALUE *)a, &SIM_EPEPSI_it);
}




} // extern "C"


#endif // _SIM_OPENSSL_H
