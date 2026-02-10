/* ISC license. */

#include <unistd.h>
#include <limits.h>

#include <skalibs/types.h>
#include <skalibs/env.h>
#include <skalibs/stralloc.h>
#include <skalibs/cspawn.h>
#include <skalibs/djbunix.h>
#include <skalibs/exec.h>

#include <s6-networking/config.h>
#include <smtpd-starttls-proxy/config.h>

#include "qmailr.h"
#include "qmail-remote.h"

void run_tls (int fdr, char const *fmtip, unsigned int timeoutconnect, unsigned int timeoutremote, qmailr_tls const *qtls, size_t helopos, size_t const *eaddrpos, unsigned int n, char const *storage)
{
  int fdw = dup(fdr) ;
  unsigned int m = 0 ;
  stralloc modif = STRALLOC_ZERO ;
  char fmtr[UINT_FMT] ;
  char fmtw[UINT_FMT] ;
  char fmtt[UINT_FMT] ;
  char fmtk[UINT_FMT] ;
  char const *argv[20 + n] ;

  if (fdw == -1) qmailr_tempusys("duplicate file descriptor") ;
  if (!env_addmodif(&modif, "TLS_UID", 0) || !env_addmodif(&modif, "TLS_GID", 0)
   || !env_addmodif(&modif, qtls->flagtadir ? "CADIR" : "CAFILE", storage + qtls->tapos)) dienomem() ;
  if (qtls->flagclientcert)
  {
    if (!env_addmodif(&modif, "CERTFILE", storage + qtls->certpos)
     || !env_addmodif(&modif, "KEYFILE", storage + qtls->keypos)) dienomem() ;
  }

  {
    int devnull = open_readb("/dev/null") ;
    if (devnull >= 0)
    {
      if (devnull < 3) qmailr_temp("weird fd configuration") ;
      fd_move(2, devnull) ;
    }
  }

  fmtr[uint_fmt(fmtr, (unsigned int)fdr)] = 0 ;
  fmtw[uint_fmt(fmtw, (unsigned int)fdw)] = 0 ;
  fmtt[uint_fmt(fmtt, timeoutremote)] = 0 ;
  fmtk[uint_fmt(fmtk, timeoutconnect > UINT_MAX/1000 ? UINT_MAX : timeoutconnect * 1000)] = 0 ;

  argv[m++] = S6_NETWORKING_EXTBINPREFIX "s6-tlsc" ;
  argv[m++] = "-Sjzv0" ;
  argv[m++] = "-K" ;
  argv[m++] = fmtk ;
  argv[m++] = "-6" ;
  argv[m++] = fmtr ;
  argv[m++] = "-7" ;
  argv[m++] = fmtw ;
  argv[m++] = "--" ;

  argv[m++] = SMTPD_STARTTLS_PROXY_LIBEXECPREFIX "qmail-remote-io" ;
  argv[m++] = "-t" ;
  argv[m++] = fmtt ;
  argv[m++] = "-6" ;
  argv[m++] = fmtr ;
  argv[m++] = "-7" ;
  argv[m++] = fmtw ;
  argv[m++] = "--" ;
  argv[m++] = fmtip ;
  argv[m++] = storage + helopos ;
  for (unsigned int i = 0 ; i < n ; i++) argv[m++] = storage + eaddrpos[i] ;
  argv[m++] = 0 ;
  mexec_m(argv, modif.s, modif.len) ;
  qmailr_tempusys("exec ", argv[0]) ;
}
