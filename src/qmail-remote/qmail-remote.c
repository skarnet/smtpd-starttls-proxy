/* ISC license. */

#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

#include <skalibs/types.h>
#include <skalibs/env.h>
#include <skalibs/exec.h>
#include <skalibs/fmtscan.h>
#include <skalibs/buffer.h>
#include <skalibs/cdb.h>
#include <skalibs/stralloc.h>
#include <skalibs/sig.h>
#include <skalibs/tai.h>
#include <skalibs/djbunix.h>
#include <skalibs/socket.h>
#include <skalibs/ip46.h>
#include <skalibs/unix-timed.h>
#ifdef DEBUG
# include <skalibs/prog.h>
#endif

#include <s6-networking/config.h>
#include <smtpd-starttls-proxy/config.h>
#include "qmailr.h"
#include "qmail-remote.h"

#define dieusage() qmailr_perm("qmail-remote was invoked improperly")

static inline void exec_tls (int fdr, char const *fmtip, unsigned int timeoutconnect, unsigned int timeoutremote, qmailr_tls const *qtls, size_t helopos, size_t const *eaddrpos, unsigned int n, char const *storage) gccattr_noreturn ;
static inline void exec_tls (int fdr, char const *fmtip, unsigned int timeoutconnect, unsigned int timeoutremote, qmailr_tls const *qtls, size_t helopos, size_t const *eaddrpos, unsigned int n, char const *storage)
{
  int fdw = dup(fdr) ;
  unsigned int m = 0 ;
  char fmtr[UINT_FMT] ;
  char fmtw[UINT_FMT] ;
  char fmtt[UINT_FMT] ;
  char fmtk[UINT_FMT] ;
  char const *argv[20 + n] ;

  if (fdw == -1) qmailr_tempusys("duplicate file descriptor") ;
  if (!env_mexec("TLS_UID", 0) || !env_mexec("TLS_GID", 0)
   || !env_mexec(qtls->flagtadir ? "CADIR" : "CAFILE", storage + qtls->tapos)) dienomem() ;
  if (qtls->flagclientcert)
  {
    if (!env_mexec("CERTFILE", storage + qtls->certpos)
     || !env_mexec("KEYFILE", storage + qtls->keypos)) dienomem() ;
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
  mexec(argv) ;
  qmailr_tempusys("exec ", argv[0]) ;
}

static inline void exec_notls (int fd, char const *fmtip, unsigned int timeoutremote, size_t helopos, size_t const *eaddrpos, unsigned int n, char const *storage) gccattr_noreturn ;
static inline void exec_notls (int fd, char const *fmtip, unsigned int timeoutremote, size_t helopos, size_t const *eaddrpos, unsigned int n, char const *storage)
{
  unsigned int m = 0 ;
  char fmtfd[UINT_FMT] ;
  char fmtt[UINT_FMT] ;
  char const *argv[11 + n] ;

  fmtfd[uint_fmt(fmtfd, (unsigned int)fd)] = 0 ;
  fmtt[uint_fmt(fmtt, timeoutremote)] = 0 ;
  argv[m++] = SMTPD_STARTTLS_PROXY_LIBEXECPREFIX "qmail-remote-io" ;
  argv[m++] = "-t" ;
  argv[m++] = fmtt ;
  argv[m++] = "-6" ;
  argv[m++] = fmtfd ;
  argv[m++] = "-7" ;
  argv[m++] = fmtfd ;
  argv[m++] = "--" ;
  argv[m++] = fmtip ;
  argv[m++] = storage + helopos ;
  for (unsigned int i = 0 ; i < n ; i++) argv[m++] = storage + eaddrpos[i] ;
  argv[m++] = 0 ;
  exec(argv) ;
  qmailr_tempusys("exec ", argv[0]) ;
}

static int smtp_start (buffer *in, buffer *out, char const *helohost, unsigned int timeout, char const *fmtip)
{
  int hastls = 0 ;
  tain deadline ;
  char line[1024] ;

  int r = qmailr_smtp_read_answer(in, line, 1024, timeout) ;
  if (r == -1) qmailr_tempusys("read from ", fmtip) ;
  if (!r) qmailr_temp("Connected to ", fmtip, " but connection died") ;
  if (r != 220)
  {
    qmailr_smtp_quit(out, timeout) ;
    qmailr_temp("Connected to ", fmtip, " but greeting failed") ;
  }

  buffer_putnoflush(out, "EHLO ", 5) ;
  buffer_putsnoflush(out, helohost) ;
  buffer_putnoflush(out, "\r\n", 2) ;

  tain_addsec_g(&deadline, timeout) ;
  if (!buffer_timed_flush_g(out, &deadline))
    qmailr_tempusys("send ", "EHLO", " to ", fmtip) ;

  tain_addsec_g(&deadline, timeout) ;
  for (;;)
  {
    unsigned int code = 250 ;
    int r = qmailr_smtp_read_line(in, line, 1024, &code, &deadline) ;
    if (r == -1) qmailr_tempusys("read from ", fmtip) ;
    if (!r) qmailr_temp("Connected to ", fmtip, " but connection died") ;
    if (code != 250) qmailr_temp("Connected to ", fmtip, " but it speaks a weird protocol") ;
    if (!strcasecmp(line + 4, "STARTTLS")) hastls = 1 ;
    if (r == 1) break ;
  }
  return hastls ;
}

static void attempt_smtp (int fd, char const *ip, int is6, unsigned int timeoutconnect, unsigned int timeoutremote, qmailr_tls const *qtls, size_t helopos, size_t const *eaddrpos, unsigned int n, char const *storage)
{
  int hastls ;
  char inbuf[2048] ;
  char outbuf[2048] ;
  char fmtip[IP6_FMT] ;
  buffer in = BUFFER_INIT(&buffer_read, fd, inbuf, 2048) ;
  buffer out = BUFFER_INIT(&buffer_write, fd, outbuf, 2048) ;
  if (is6) fmtip[ip6_fmt(fmtip, ip)] = 0 ;
  else fmtip[ip4_fmt(fmtip, ip)] = 0 ;

  hastls = smtp_start(&in, &out, storage + helopos, timeoutremote, fmtip) ;
  if (qtls->flagwanttls)
  {
    if (hastls)
    {
      int r ;
      tain deadline ;
      char line[1024] ;
      buffer_putsnoflush(&out, "STARTTLS\r\n") ;
      tain_addsec_g(&deadline, timeoutremote) ;
      if (!buffer_timed_flush_g(&out, &deadline)) qmailr_tempusys("send ", "STARTTLS", " to ", fmtip) ;
      r = qmailr_smtp_read_answer(&in, line, 1024, timeoutremote) ;
      if (r == -1) qmailr_tempusys("read from ", fmtip) ;
      else if (!r)
      {
        qmailr_smtp_quit(&out, timeoutremote) ;
        qmailr_temp("Connected to ", fmtip, " but connection died") ;
      }
      else if (r == 220) exec_tls(fd, fmtip, timeoutconnect, timeoutremote, qtls, helopos, eaddrpos, n, storage) ;
      if (qtls->strictness) return ;
    }
    else if (qtls->strictness >= 2) return ;
  }
  exec_notls(fd, fmtip, timeoutremote, helopos, eaddrpos, n, storage) ;
}

int main (int argc, char const *const *argv)
{
  stralloc storage = STRALLOC_ZERO ;
  stralloc ipme4 = STRALLOC_ZERO ;
  stralloc ipme6 = STRALLOC_ZERO ;
  qmailr_tls qtls = QMAILR_TLS_ZERO ;
  smtproutes routes = SMTPROUTES_ZERO ;
  unsigned int timeoutconnect = 60, timeoutremote = 1200, timeoutdns = 0 ;
  char const *host ;
  size_t mepos, helopos, hostpos = 0 ;
  uint16_t port = 25 ;
  int r ;

#ifdef DEBUG
  char progstr[18 + PID_FMT] = "qmail-remote: pid " ;
  progstr[18 + pid_fmt(progstr + 18, getpid())] = 0 ;
  PROG = progstr ;
#endif

  if (argc-- < 4) dieusage() ;
  argv++ ;
  if (chdir(SMTPD_STARTTLS_PROXY_QMAIL_HOME) == -1) qmailr_tempusys("chdir to ", SMTPD_STARTTLS_PROXY_QMAIL_HOME) ;
  if (sig_altignore(SIGPIPE) == -1) qmailr_tempusys("ignore SIGPIPE") ;
  host = *argv++ ; argc-- ;
  tain_now_set_stopwatch_g() ;


 /* init control */

  r = qmailr_control_read("control/me", &storage, &mepos) ;
  if (r == -1) qmailr_tempusys("read ", "control/me") ;
  else if (!r) qmailr_temp("Invalid ", "control/me") ;

  r = qmailr_control_read("control/helohost", &storage, &helopos) ;
  if (r == -1) qmailr_tempusys("read ", "control/helohost") ;
  else if (!r) helopos = mepos ;

  r = qmailr_control_readint("control/timeoutconnect", &timeoutconnect, &storage) ;
  if (r == -1) qmailr_tempusys("read ", "control/timeoutconnect") ;
  r = qmailr_control_readint("control/timeoutremote", &timeoutremote, &storage) ;
  if (r == -1) qmailr_tempusys("read ", "control/timeoutremote") ;
  r = qmailr_control_readint("control/timeoutdns", &timeoutdns, &storage) ;
  if (r == -1) qmailr_tempusys("read ", "control/timeoutdns") ;

  if (!qmailr_control_readiplist("control/ipme", &ipme4, &ipme6))
    qmailr_tempusys("read ", "control/ipme") ;
  qsort(ipme4.s, ipme4.len >> 2, 4, &qmailr_memcmp4) ;
  qsort(ipme6.s, ipme6.len >> 4, 16, &qmailr_memcmp16) ;

  if (!qmailr_tls_init(&qtls, &storage))
    qmailr_tempusys("read ", "TLS control files") ;

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

  {
    genalloc mxipind = GENALLOC_ZERO ;
    mxip const *mxs ;
    size_t eaddrpos[argc] ;
    size_t ntot = 0 ;
    unsigned int mxn = dns_stuff(hostpos ? storage.s + hostpos : host, argv, argc, eaddrpos, &mxipind, &storage, timeoutdns, ipme4.s, ipme4.len >> 2, ipme6.s, ipme6.len >> 4, !hostpos) ;
    if (!mxn) qmailr_perm("No suitable MX found for remote host") ;
    stralloc_free(&ipme4) ;
    stralloc_free(&ipme6) ;
    mxs = genalloc_s(mxip, &mxipind) ;

    for (unsigned int i = 0 ; i < mxn ; i++) ntot += mxs[i].n4 + mxs[i].n6 ;
    if (!ntot) qmailr_perm("No suitable IP addresses for the MX") ;

    for (; qtls.flagwanttls && qtls.strictness == 1 ; qtls.flagwanttls = 0)
    {
      for (unsigned int i = 0 ; i < mxn ; i++)
      {
#ifdef SKALIBS_IPV6_ENABLED
        for (unsigned int j = 0 ; j < mxs[i].n6 ; j++)
        {
          char const *ip = storage.s + mxs[i].pos6 + (j << 4) ;
          tain deadline ;
          int fd ;
          if (qmailr_tcpto_match(ip, 1)) continue ;
          fd = socket_tcp6() ;
          if (fd == -1) qmailr_tempusys("create socket") ;
          tain_addsec_g(&deadline, timeoutconnect) ;
          if (!socket_deadlineconnstamp6_g(fd, ip, port, &deadline))
          {
            if (!qmailr_tcpto_update(ip, 1, errno == ETIMEDOUT))
              qmailr_tempusys("update ", "tcpto6") ;
            fd_close(fd) ;
            continue ;
          }
          if (!qmailr_tcpto_update(ip, 1, 0))
            qmailr_tempusys("update ", "tcpto6") ;
          attempt_smtp(fd, ip, 1, timeoutconnect, timeoutremote, &qtls, helopos, eaddrpos, argc, storage.s) ;
          fd_close(fd) ;
        }
#endif
        for (unsigned int j = 0 ; j < mxs[i].n4 ; j++)
        {
          char const *ip = storage.s + mxs[i].pos4 + (j << 2) ;
          tain deadline ;
          int fd ;
          if (qmailr_tcpto_match(ip, 0)) continue ;
          fd = socket_tcp4() ;
          if (fd == -1) qmailr_tempusys("create socket") ;
          tain_addsec_g(&deadline, timeoutconnect) ;
          if (!socket_deadlineconnstamp4_g(fd, ip, port, &deadline))
          {
            if (!qmailr_tcpto_update(ip, 0, errno == ETIMEDOUT))
              qmailr_tempusys("update ", "tcpto") ;
            fd_close(fd) ;
            continue ;
          }
          if (!qmailr_tcpto_update(ip, 0, 0))
            qmailr_tempusys("update ", "tcpto") ;
          attempt_smtp(fd, ip, 0, timeoutconnect, timeoutremote, &qtls, helopos, eaddrpos, argc, storage.s) ;
          fd_close(fd) ;
        }
      }
    }
  }
  qmailr_tempusys("establish an SMTP connection") ;
  _exit(101) ;  /* not reached */
}
