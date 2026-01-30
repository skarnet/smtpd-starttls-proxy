/* ISC license. */

#include <stdint.h>

#include <skalibs/gccattributes.h>
#include <skalibs/tai.h>

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


/* qmailr_tcpto */

extern int qmailr_tcpto_match (char const *, int) ;
extern int qmailr_tcpto_update (char const *, int, int) ;

