/* ISC license. */

#include <unistd.h>

#include <skalibs/gccattributes.h>
#include <skalibs/types.h>
#include <skalibs/buffer.h>
#include <skalibs/gol.h>
#include <skalibs/tai.h>
#include <skalibs/unix-timed.h>

#include "qmailr.h"

enum gola_e
{
  GOLA_TIMEOUT,
  GOLA_FDR,
  GOLA_FDW,
  GOLA_HELOHOST,
  GOLA_N
} ;

static inline unsigned int qgol_argv (char const *const *argv, gol_bool const *b, unsigned int bn, gol_arg const *a, unsigned int an, uint64_t *br, char const **ar)
{
  int problem = 0 ;
  int r = gol(argv, b, bn, a, an, br, ar, &problem) ;

  if (r < 0)
  {
    if (problem > 0)
    {
      char s[2] = { argv[-r-1][problem], 0 } ;
      qmailr_perm("qmail-remote-io: ", "unrecognized ", "short ", "option: ", s) ;
    }
    else if (!problem)
      qmailr_perm("qmail-remote-io: ", "invalid ", "option: ", argv[-r-1]) ;
    else if (problem == -1)
      qmailr_perm("qmail-remote-io: ", "unrecognized ", "boolean ", "option: ", argv[-r-1]) ;
    else
      qmailr_perm("qmail-remote-io: ", "unrecognized ", "option with argument: ", argv[-r-1]) ;
  }
  else return r ;
}

static inline unsigned int qgol_main (int argc, char const *const *argv, gol_bool const *b, unsigned int bn, gol_arg const *a, unsigned int an, uint64_t *br, char const **ar)
{
  if (argc < 1 || argv[argc]) qmailr_perm("qmail-remote-io: ", "invalid argc/argv") ;
  if (argc == 1) return 1 ;
  return 1 + qgol_argv(argv + 1, b, bn, a, an, br, ar) ;
}

static unsigned int read_answer_options (buffer *in, unsigned int timeout, char *buf, size_t buflen, char const *fmtip, unsigned int flags)
{
  int r = qmailr_smtp_read_answer(in, buf, buflen, timeout) ;
  if (r == -1) qmailr_tempsys("qmail-remote-io: ", "unable to ", "read SMTP answer from ", fmtip, flags & 1 ? " (Possible duplicate!)" : "") ;
  if (!r) qmailr_tempsys("qmail-remote-io: ", fmtip, " closed the connection early", flags & 1 ? " (Possible duplicate!)" : "") ;
  return r ;
}

static unsigned read_answer (buffer *in, unsigned int timeout, char *buf, size_t buflen, char const *fmtip)
{
  return read_answer_options(in, timeout, buf, buflen, fmtip, 0) ;
}

static void put (buffer *out, char const *s)
{
  if (buffer_puts(out, s) < 0)
    qmailr_tempsys("qmail-remote-io: ", "unable to ", "queue SMTP command") ;
}

static void datachar (buffer *out, char c)
{
  if (buffer_put(out, &c, 1) < 1)
    qmailr_tempsys("qmail-remote-io: ", "unable to ", "send character after DATA") ;
}

/*
  small DFA for blast() to quote dots and newlines

	0	1	2	3
st\ev	EOF	.	\n	other

0		qp	rp	p
START	END	INLINE	START	INLINE

1		p	rp	p
INLINE	X	INLINE	START	INLINE

END=2 X=3

0x10	q	quote with .
0x20	r	quote with \r
0x40	p	print char

*/

static inline uint8_t cclass (char c)
{
  return c == '.' ? 1 : c == '\n' ? 2 : 3 ;
}

static void blast (buffer *out, unsigned int timeout)
{
  static uint8_t const table[2][4] =
  {
    { 0x02, 0x51, 0x60, 0x41 },
    { 0x03, 0x41, 0x60, 0x41 }
  } ;
  uint8_t state = 0 ;
  while (state < 2)
  {
    char c ;
    uint8_t val ;
    ssize_t r = buffer_get(buffer_0, &c, 1) ;
    if (r == -1) qmailr_tempsys("qmail-remote-io: ", "unable to ", "read message") ;
    val = r ? table[state][cclass(c)] : table[state][0] ;
    state = val & 3 ;
    if (val & 0x10) datachar(out, '.') ;
    if (val & 0x20) datachar(out, '\r') ;
    if (val & 0x40) datachar(out, c) ;
  }
  if (state > 2) qmailr_perm("qmail-remote-io: ", "SMTP cannot transfer messages with partial final lines") ;
  if (buffer_putflush(out, ".\r\n", 3) < 0) qmailr_tempsys("qmail-remote-io: ", "unable to ", "finalize message data") ;
}

static inline void smtp_body (buffer *in, buffer *out, char const *fmtip, char const *sender, char const *const *recip, unsigned int n, unsigned int timeout) gccattr_noreturn ;
static inline void smtp_body (buffer *in, buffer *out, char const *fmtip, char const *sender, char const *const *recip, unsigned int n, unsigned int timeout)
{
  tain deadline ;
  unsigned int code ;
  int flagbother = 0 ;
  char buf[4096] ;

  put(out, "MAIL FROM:<") ;
  put(out, sender) ;
  put(out, ">\r\n") ;
  qdeadline(&deadline, timeout) ;
  if (!buffer_timed_flush_g(out, &deadline))
    qmailr_tempsys("qmail-remote-io: ", "unable to ", "send command to ", fmtip) ;
  code = read_answer(in, timeout, buf, 4096, fmtip) ;
  if (code >= 500)
  {
    qmailr_smtp_quit(out, timeout) ;
    qmailr_perm("qmail-remote-io: ", "connected to ", fmtip, " but sender was rejected", ".\nRemote host said: ", buf+4) ;
  }
  else if (code >= 400)
  {
    qmailr_smtp_quit(out, timeout) ;
    qmailr_temp("qmail-remote-io: ", "connected to ", fmtip, " but sender was rejected", ".\nRemote host said: ", buf+4) ;
  }

  for (unsigned int i = 0 ; i < n ; i++)
  {
    put(out, "RCPT TO:<") ;
    put(out, recip[i]) ;
    put(out, ">\r\n") ;
    qdeadline(&deadline, timeout) ;
    if (!buffer_timed_flush_g(out, &deadline))
      qmailr_tempsys("qmail-remote-io: ", "unable to ", "send command to ", fmtip) ;
    code = read_answer(in, timeout, buf, 4096, fmtip) ;
    if (code >= 500)
    {
      qmailr_smtp_quit(out, timeout) ;
      qmailr_die('h', fmtip, " does not like recipient", ".\nRemote host said: ", buf+4) ;
    }
    else if (code >= 400)
    {
      qmailr_smtp_quit(out, timeout) ;
      qmailr_die('s', fmtip, " does not like recipient", ".\nRemote host said: ", buf+4) ;
    }
    else
    {
      buffer_put(buffer_1, "r", 2) ;
      flagbother = 1 ;
    }
  }
  if (!flagbother)
  {
    qmailr_smtp_quit(out, timeout) ;
    qmailr_perm("Giving up on ", fmtip) ;
  }

  put(out, "DATA\r\n") ;
  qdeadline(&deadline, timeout) ;
  if (!buffer_timed_flush_g(out, &deadline))
    qmailr_tempsys("qmail-remote-io: ", "unable to ", "send command to ", fmtip) ;
  code = read_answer(in, timeout, buf, 4096, fmtip) ;
  if (code >= 500)
  {
    qmailr_smtp_quit(out, timeout) ;
    qmailr_perm(fmtip, " failed on DATA command") ;
  }
  else if (code >= 400)
  {
    qmailr_smtp_quit(out, timeout) ;
    qmailr_temp(fmtip, " failed on DATA command") ;
  }

  blast(out, timeout) ;
  code = read_answer_options(in, timeout, buf, 4096, fmtip, 1) ;
  if (code >= 500)
  {
    qmailr_smtp_quit(out, timeout) ;
    qmailr_perm(fmtip, " failed after I sent the message") ;
  }
  else if (code >= 400)
  {
    qmailr_smtp_quit(out, timeout) ;
    qmailr_temp(fmtip, " failed after I sent the message") ;
  }

  qmailr_smtp_quit(out, timeout) ;
  qmailr_die('K', fmtip, " accepted message") ;
}

int main (int argc, char const *const *argv)
{
  static gol_arg const rgola[] =
  {
    { .so = 't', .lo = "timeoutremote", .i = GOLA_TIMEOUT },
    { .so = '6', .lo = "fdr", .i = GOLA_FDR },
    { .so = '7', .lo = "fdw", .i = GOLA_FDW },
    { .so = 'h', .lo = "helohost", .i = GOLA_HELOHOST },
  } ;
  char const *wgola[GOLA_N] = { 0 } ;
  unsigned int fdr = 6, fdw = 7 ;
  unsigned int timeoutremote = 1200 ;
  buffer in, out ;
  char inbuf[1024] ;
  char outbuf[BUFFER_OUTSIZE] ;
  unsigned int golc = qgol_main(argc, argv, 0, 0, rgola, 4, 0, wgola) ;
  argc -= golc ; argv += golc ;
  if (argc < 3) qmailr_perm("qmail-remote-io: ", "too few arguments") ;

  if (wgola[GOLA_TIMEOUT] && !uint0_scan(wgola[GOLA_TIMEOUT], &timeoutremote))
    qmailr_perm("qmail-remote-io: ", "invalid timeoutremote") ;
  if (wgola[GOLA_FDR] && !uint0_scan(wgola[GOLA_FDR], &fdr))
    qmailr_perm("qmail-remote-io: ", "invalid fdr") ;
  if (wgola[GOLA_FDW] && !uint0_scan(wgola[GOLA_FDW], &fdw))
    qmailr_perm("qmail-remote-io: ", "invalid fdw") ;

  buffer_init(&in, &buffer_read, fdr, inbuf, 1024) ;
  buffer_init(&out, &buffer_write, fdw, outbuf, BUFFER_OUTSIZE) ;

  tain_now_set_stopwatch_g() ;
  if (wgola[GOLA_HELOHOST])
  {
    if (qmailr_smtp_ehlo(&in, &out, wgola[GOLA_HELOHOST], timeoutremote) == -1)
      qmailr_tempusys("initiate SMTP exchange with ", argv[0]) ;
  }
  smtp_body(&in, &out, argv[0], argv[1], argv + 2, argc - 2, timeoutremote) ;
}
