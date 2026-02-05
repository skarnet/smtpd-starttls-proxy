/* ISC license. */

#ifndef QMAIL_SMTPC_H
#define QMAIL_SMTPC_H

#include <stddef.h>
#include <stdint.h>

#include <skalibs/cdb.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>

#include "qmailr.h"

#define dienomem() qmailr_tempsys("Unable to grow stralloc")


/* dns */

typedef struct mxip_s mxip, *mxip_ref ;
struct mxip_s
{
  size_t pos4 ;
  size_t pos6 ;
  uint16_t n4 ;
  uint16_t n6 ;
} ;
#define MXIP_ZERO { 0 }

extern void dns_stuff (char const *, char const *const *, unsigned int, size_t *, genalloc *, stralloc *, unsigned int, char const *, unsigned int, char const *, unsigned int, uint32_t) ;


/* smtproutes */

typedef struct smtproutes_s smtproutes ;
struct smtproutes_s
{
  cdb map ;
} ;
#define SMTPROUTES_ZERO { .map = CDB_ZERO }

extern int smtproutes_init (smtproutes *) ;
extern int smtproutes_match (smtproutes const *, char const *, stralloc *, size_t *, uint16_t *) ;
extern void smtproutes_free (smtproutes *) ;

#endif
