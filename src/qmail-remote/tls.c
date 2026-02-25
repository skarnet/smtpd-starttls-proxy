/* ISC license. */

#include <sys/wait.h>
#include <unistd.h>
#include <limits.h>

#include <skalibs/types.h>
#include <skalibs/env.h>
#include <skalibs/allreadwrite.h>
#include <skalibs/stralloc.h>
#include <skalibs/cspawn.h>
#include <skalibs/djbunix.h>
#include <skalibs/exec.h>

#include <s6-networking/config.h>
#include <smtpd-starttls-proxy/config.h>

#include "qmailr.h"
#include "qmail-remote.h"

/*
  Ideally, we would just exec into "s6-tlsc qmail-remote-io".
  Unfortunately, the interface with qmail-rspawn is super weird:
we don't have access to stderr directly, stdout counts as both a
protocol channel and an error channel so we need to prepend
messages with Z|D|K and null-terminate them, and qmail-rspawn
hates a child that doesn't exit 0 or 111.
  s6-tlsc writes error messages to its stderr and exits nonzero
and non-111 in important TLS failure cases that we want to report.
So instead of execing, we spawn it and stick around to translate
the exit code and the error message back to qmail-rspawn.
*/

void run_tls (int fdr, char const *fmtip, unsigned int timeoutconnect, unsigned int timeoutremote, qmailr_tls const *qtls, size_t helopos, size_t const *eaddrpos, unsigned int n, size_t mxnamepos, char const *storage)
{
  int wstat ;
  pid_t pid ;
  int fdw = dup(fdr) ;
  unsigned int m = 0 ;
  stralloc modif = STRALLOC_ZERO ;
  cspawn_fileaction fa[2] =
  {
    [0] = { .type = CSPAWN_FA_CLOSE },
    [1] = { .type = CSPAWN_FA_MOVE, .x = { .fd2 = { [0] = 2 } } }
  } ;
  int p[2] ;
  char fmtr[UINT_FMT] ;
  char fmtw[UINT_FMT] ;
  char fmtt[UINT_FMT] ;
  char fmtk[UINT_FMT] ;
  char const *argv[23 + n] ;

  if (fdw == -1) qmailr_tempusys("duplicate file descriptor") ;
  if (pipe(p) == -1) qmailr_tempusys("pipe") ;
  fa[0].x.fd = p[0] ;
  fa[1].x.fd2[1] = p[1] ;

  if (!env_addmodif(&modif, "TLS_UID", 0) || !env_addmodif(&modif, "TLS_GID", 0)
   || !env_addmodif(&modif, qtls->flagtadir ? "CADIR" : "CAFILE", storage + qtls->tapos)) dienomem() ;
  if (qtls->flagclientcert)
  {
    if (!env_addmodif(&modif, "CERTFILE", storage + qtls->certpos)
     || !env_addmodif(&modif, "KEYFILE", storage + qtls->keypos)) dienomem() ;
  }

  fmtr[uint_fmt(fmtr, (unsigned int)fdr)] = 0 ;
  fmtw[uint_fmt(fmtw, (unsigned int)fdw)] = 0 ;
  fmtt[uint_fmt(fmtt, timeoutremote)] = 0 ;
  fmtk[uint_fmt(fmtk, timeoutconnect > UINT_MAX/1000 ? UINT_MAX : timeoutconnect * 1000)] = 0 ;

  argv[m++] = S6_NETWORKING_EXTBINPREFIX "s6-tlsc" ;
  argv[m++] = "-Sjzv0" ;  /* S = use close_notify, v0 = as silent as possible */
  argv[m++] = "-K" ;
  argv[m++] = fmtk ;
  argv[m++] = "-6" ;
  argv[m++] = fmtr ;
  argv[m++] = "-7" ;
  argv[m++] = fmtw ;
  argv[m++] = "-k" ;
  argv[m++] = storage + mxnamepos ;
  argv[m++] = "--" ;

  argv[m++] = SMTPD_STARTTLS_PROXY_LIBEXECPREFIX "qmail-remote-io" ;
  argv[m++] = "-t" ;
  argv[m++] = fmtt ;
  argv[m++] = "-6" ;
  argv[m++] = fmtr ;
  argv[m++] = "-7" ;
  argv[m++] = fmtw ;
  argv[m++] = "--helohost" ;
  argv[m++] = storage + helopos ;
  argv[m++] = "--" ;
  argv[m++] = fmtip ;
  for (unsigned int i = 0 ; i < n ; i++) argv[m++] = storage + eaddrpos[i] ;
  argv[m++] = 0 ;
  pid = mspawn_m(argv, modif.s, modif.len, 0, fa, 2) ;
  if (!pid) qmailr_tempusys("spawn ", argv[0]) ;

  stralloc_free(&modif) ;
  fd_close(p[1]) ;
  if (wait_pid(pid, &wstat) == -1) qmailr_tempusys("waitpid") ;
  if (WIFSIGNALED(wstat))
    qmailr_tempusys("either s6-tlsc or qmail-remote-io crashed") ;

  {
    char buf[4096] ;
    size_t r = fd_read(p[0], buf, 4096) ;
    if (r == -1) qmailr_tempusys("read from pipe") ;
    if (r)
    {
      if (r == 4096) r-- ;
      while (r && buf[r-1] == '\n') r-- ;
      buf[r++] = 0 ;
      qmailr_temp(buf) ;
    }
  }
  _exit(0) ;
}
