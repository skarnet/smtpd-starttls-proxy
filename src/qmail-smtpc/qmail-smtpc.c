/* ISC license. */

#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include <skalibs/cdb.h>
#include <skalibs/stralloc.h>
#include <skalibs/sig.h>
#include <skalibs/tai.h>
#include <skalibs/ip46.h>

#include <smtpd-starttls-proxy/config.h>
#include "qmailr.h"
#include "qmail-smtpc.h"

#define dieusage() qmailr_perm("qmail-remote was invoked improperly")

int main (int argc, char const *const *argv)
{
  stralloc storage = STRALLOC_ZERO ;
  stralloc ipme4 = STRALLOC_ZERO ;
  stralloc ipme6 = STRALLOC_ZERO ;
  qmailr_tls qt = QMAILR_TLS_ZERO ;
  smtproutes routes = SMTPROUTES_ZERO ;
  unsigned int timeoutconnect = 60, timeoutremote = 1200 ;
  char const *host ;
  size_t mepos, helopos, hostpos = 0, senderpos ;
  uint16_t port = 25 ;
  int r ;

  if (argc-- < 4) dieusage() ;
  argv++ ;
  if (chdir(SMTPD_STARTTLS_PROXY_QMAIL_HOME) == -1) qmailr_temp("Unable to chdir to " SMTPD_STARTTLS_PROXY_QMAIL_HOME) ;
  if (sig_altignore(SIGPIPE) == -1) qmailr_tempsys("Unable to ignore SIGPIPE") ;
  host = *argv++ ; argc-- ;
  tain_now_set_stopwatch_g() ;
  dns_init() ;

 /* init control */

  r = qmailr_control_read("control/me", &storage, &mepos) ;
  if (r == -1) qmailr_tempsys("Unable to read control/me") ;
  else if (!r) qmailr_temp("Invalid control/me") ;

  r = qmailr_control_read("control/helohost", &storage, &helopos) ;
  if (r == -1) qmailr_tempsys("Unable to read control/helohost") ;
  else if (!r) helopos = mepos ;

  r = qmailr_control_readint("control/timeoutconnect", &timeoutconnect, &storage) ;
  if (r == -1) qmailr_tempsys("Unable to read control/timeoutconnect") ;
  r = qmailr_control_readint("control/timeoutremote", &timeoutremote, &storage) ;
  if (r == -1) qmailr_tempsys("Unable to read control/timeoutremote") ;

  if (!qmailr_control_readiplist("control/ipme", &ipme4, &ipme6))
    qmailr_tempsys("Unable to read control/ipme") ;
  stralloc_shrink(&ipme4) ;
  stralloc_shrink(&ipme6) ;
  qsort(ipme4.s, ipme4.len >> 2, 4, &qmailr_memcmp4) ;
  qsort(ipme6.s, ipme6.len >> 4, 16, &qmailr_memcmp16) ;

  if (!qmailr_tls_init(&qt, &storage))
    qmailr_tempsys("Unable to read TLS control files") ;

  if (smtproutes_init(&routes))
  {
    if (!smtproutes_match(&routes, host, &storage, &hostpos, &port))
    {
      size_t hostlen = strlen(host) ;
      for (size_t i = 0 ; i < hostlen ; i++) if (host[i] == '.')
        if (smtproutes_match(&routes, argv[1], &storage, &hostpos, &port)) break ;
      if (!hostpos) smtproutes_match(&routes, "", &storage, &hostpos, &port) ;
    }
    smtproutes_free(&routes) ;
  }

  // TODO: box_encode(&senderpos) ;

  {
    genalloc mxpos = GENALLOC_ZERO ;
    int usehost ;
    size_t recippos[argc] ;

    dns_canon(host, argv, argc, recippos, hostpos ? 0 : &mxpos, &storage) ;
    usehost = hostpos || !genalloc_len(size_t, &mxpos) ;

    unsigned int mxn = usehost ? 1 : genalloc_len(size_t, &mxpos) ;
    mxip mxind[mxn] ;
    dns_ip_of_mx(usehost ? &hostpos : genalloc_s(size_t, &mxpos), mxn, mxind, &storage, ipme4.s, ipme4.len >> 2, ipme6.s, ipme6.len >> 4) ;
    genalloc_free(size_t, &mxpos) ;
  }


  _exit(0) ;
}
