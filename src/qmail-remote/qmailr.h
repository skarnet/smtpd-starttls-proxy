/* ISC license. */

#ifndef QMAILR_H
#define QMAILR_H

#include <stddef.h>
#include <stdint.h>

#include <skalibs/gccattributes.h>
#include <skalibs/buffer.h>
#include <skalibs/tai.h>
#include <skalibs/stralloc.h>


/* qmailr_error */

extern void qmailr_warnv (char, char const *const *, unsigned int) gccattr_noreturn ;
extern void qmailr_diev (char, char const *const *, unsigned int) gccattr_noreturn ;
extern void qmailr_dievsys (char const *const *, unsigned int) gccattr_noreturn ;

#define qmailr_array(...) ((char const *const[]){__VA_ARGS__})
#define qmailr_dien(e, n, ...) qmailr_diev(e, qmailr_array(__VA_ARGS__), (n))
#define qmailr_diensys(n, ...) qmailr_dievsys(qmailr_array(__VA_ARGS__), (n))

#define qmailr_die(c, ...) qmailr_dien(c, sizeof(qmailr_array(__VA_ARGS__))/sizeof(char const *), __VA_ARGS__)
#define qmailr_diesys(...) qmailr_diensys(sizeof(qmailr_array(__VA_ARGS__))/sizeof(char const *), __VA_ARGS__)

#define qmailr_temp(...) qmailr_die('Z', __VA_ARGS__)
#define qmailr_tempsys(...) qmailr_diesys(__VA_ARGS__)
#define qmailr_perm(...) qmailr_die(1, __VA_ARGS__)

#define qmailr_tempu(...) qmailr_die('D', "Unable to ", __VA_ARGS__)
#define qmailr_tempusys(...) qmailr_diesys("Unable to ", __VA_ARGS__)


/* qmailr_utils */

#define qdeadline(d, t) do { if (t) tain_addsec_g(d, t) ; else tain_add_g(d, &tain_infinite_relative) ; } while (0)

extern int qmailr_memcmp4 (void const *, void const *) ;
extern int qmailr_memcmp16 (void const *, void const *) ;
extern int qmailr_box_encode (char const *, size_t, stralloc *) ;


/* qmailr_tcpto */

extern int qmailr_tcpto_match (char const *, int) ;
extern int qmailr_tcpto_update (char const *, int, int) ;


/* qmailr_control */

extern int qmailr_control_read (char const *, stralloc *, size_t *) ;
extern int qmailr_control_readint (char const *file, unsigned int *, stralloc *) ;
extern int qmailr_control_readiplist (char const *, stralloc *, stralloc *) ;


 /* qmailr_smtp */

extern int qmailr_smtp_read_line (buffer *, char *, size_t, unsigned int *, tain const *) ;
extern int qmailr_smtp_read_answer (buffer *, char *, size_t, unsigned int) ;
extern int qmailr_smtp_ehlo (buffer *, buffer *, char const *, unsigned int) ;
extern int qmailr_smtp_start (buffer *, buffer *, char const *, unsigned int) ;
extern void qmailr_smtp_quit (buffer *b, unsigned int) ;


/* qmailr_tls */

typedef struct qmailr_tls_s qmailr_tls, *qmailr_tls_ref ;
struct qmailr_tls_s
{
  size_t tapos ;
  size_t certpos ;
  size_t keypos ;
  uint8_t strictness : 2 ;
  uint8_t flagwanttls : 1 ;
  uint8_t flagtadir : 1 ;
  uint8_t flagclientcert : 1 ;
} ;
#define QMAILR_TLS_ZERO { 0 }

extern int qmailr_tls_init (qmailr_tls *, stralloc *) ;

#endif
