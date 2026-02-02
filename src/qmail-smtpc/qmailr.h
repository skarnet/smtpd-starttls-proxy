/* ISC license. */

#ifndef QMAILR_H
#define QMAILR_H

#include <stddef.h>
#include <stdint.h>

#include <skalibs/gccattributes.h>
#include <skalibs/tai.h>
#include <skalibs/stralloc.h>


/* qmailr_error */

extern void qmailr_diev (int, char const *const *, unsigned int) gccattr_noreturn ;
extern void qmailr_dievsys (char const *const *, unsigned int) gccattr_noreturn ;
extern void qmailr_die (int, char const *) gccattr_noreturn ;
extern void qmailr_diesys (char const *) gccattr_noreturn ;

#define qmailr_temp(s) qmailr_die(0, (s))
#define qmailr_tempv(v, n) qmailr_diev(0, (v), n)
#define qmailr_tempsys(s) qmailr_diesys(s)
#define qmailr_tempvsys(v, n) qmailr_dievsys(v, n)
#define qmailr_perm(s) qmailr_die(1, (s))
#define qmailr_permv(v, n) qmailr_diev(1, (v), n)


/* qmailr_utils */

extern int qmailr_memcmp4 (void const *, void const *) ;
extern int qmailr_memcmp16 (void const *, void const *) ;


/* qmailr_tcpto */

extern int qmailr_tcpto_match (char const *, int) ;
extern int qmailr_tcpto_update (char const *, int, int) ;


/* qmailr_control */

extern int qmailr_control_read (char const *, stralloc *, size_t *) ;
extern int qmailr_control_readint (char const *file, unsigned int *, stralloc *) ;
extern int qmailr_control_readiplist (char const *, stralloc *, stralloc *) ;


/* qmailr_tls */

typedef struct qmailr_tls_s qmailr_tls, *qmailr_tls_ref ;
struct qmailr_tls_s
{
  size_t tapos ;
  size_t certpos ;
  size_t keypos ;
  uint8_t flagtls : 1 ;
  uint8_t flagtadir : 1 ;
  uint8_t flagclientcert : 1 ;
} ;
#define QMAILR_TLS_ZERO { 0 }

extern int qmailr_tls_init (qmailr_tls *, stralloc *) ;

#endif
