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
    .flags = 0,
    .tag = 0,
    .offset = offsetof(SIM, hashAlgorithm),
    .field_name = "hashAlgorithm",
    .item = &X509_ALGOR_it,
  },
  {
    .flags = 0,
    .tag = 0,
    .offset = offsetof(SIM, authorityRandom),
    .field_name = "authorityRandom",
    .item = &ASN1_OCTET_STRING_it,
  },
  {
    .flags = 0,
    .tag = 0,
    .offset = offsetof(SIM, pepsi),
    .field_name = "pepsi",
    .item = &ASN1_OCTET_STRING_it,
  },
};

const ASN1_ITEM SIM_it = {
  .itype = ASN1_ITYPE_SEQUENCE,
  .utype = V_ASN1_SEQUENCE,
  .templates = SIM_seq_tt,
  .tcount = sizeof(SIM_seq_tt) / sizeof(ASN1_TEMPLATE),
  .funcs = NULL,
  .size = sizeof(SIM),
  .sname = "SIM",
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
    .flags = 0,
    .tag = 0,
    .offset = offsetof(SIM_PEPSI, userPassword),
    .field_name = "userPassword",
    .item = &ASN1_UTF8STRING_it,
  },
  {
    .flags = 0,
    .tag = 0,
    .offset = offsetof(SIM_PEPSI, authorityRandom),
    .field_name = "authorityRandom",
    .item = &ASN1_OCTET_STRING_it,
  },
  {
    .flags = 0,
    .tag = 0,
    .offset = offsetof(SIM_PEPSI, siiType),
    .field_name = "siiType",
    .item = &ASN1_OBJECT_it,
  },
  {
    .flags = 0,
    .tag = 0,
    .offset = offsetof(SIM_PEPSI, sii),
    .field_name = "sii",
    .item = &ASN1_UTF8STRING_it,
  },
};

const ASN1_ITEM SIM_PEPSI_it = {
  .itype = ASN1_ITYPE_SEQUENCE,
  .utype = V_ASN1_SEQUENCE,
  .templates = SIM_PEPSI_seq_tt,
  .tcount = sizeof(SIM_PEPSI_seq_tt) / sizeof(ASN1_TEMPLATE),
  .funcs = NULL,
  .size = sizeof(SIM_PEPSI),
  .sname = "SIM_PEPSI",
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
    .flags = 0,
    .tag = 0,
    .offset = offsetof(SIM_EPEPSI, siiType),
    .field_name = "siiType",
    .item = &ASN1_OBJECT_it,
  },
  {
    .flags = 0,
    .tag = 0,
    .offset = offsetof(SIM_EPEPSI, sii),
    .field_name = "sii",
    .item = &ASN1_UTF8STRING_it,
  },
  {
    .flags = 0,
    .tag = 0,
    .offset = offsetof(SIM_EPEPSI, sim),
    .field_name = "sim",
    .item = &SIM_it,
  },
};

const ASN1_ITEM SIM_EPEPSI_it = {
  .itype = ASN1_ITYPE_SEQUENCE,
  .utype = V_ASN1_SEQUENCE,
  .templates = SIM_EPEPSI_seq_tt,
  .tcount = sizeof(SIM_EPEPSI_seq_tt) / sizeof(ASN1_TEMPLATE),
  .funcs = NULL,
  .size = sizeof(SIM_EPEPSI),
  .sname = "SIM_EPEPSI",
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
