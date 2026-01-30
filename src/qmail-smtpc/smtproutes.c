/* ISC license. */

#include <skalibs/bsdsnowflake.h>

#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>

#include <skalibs/stat.h>
#include <skalibs/posixplz.h>
#include <skalibs/uint16.h>
#include <skalibs/buffer.h>
#include <skalibs/cdb.h>
#include <skalibs/cdbmake.h>
#include <skalibs/stralloc.h>
#include <skalibs/djbtime.h>
#include <skalibs/djbunix.h>

#include <smtpd-starttls-proxy/config.h>
#include "qmailr.h"


/*
   qmail-remote uses a "constmap" for smtproutes, which is
   basically a cdb in RAM. Every instance of qmail-remote
   parses control/smtproutes to make the constmap.
   We replace it with a real cdb, stored in the filesystem.
   It saves CPU (N-1 instances of qmail-remote use the cdb
   directly) and RAM (the cdb is read-only and shared).
   The cdb is updated whenever control/smtproutes is newer.
   We have to lock around the test to avoid several
   concurrent compilations; the lock feels a bit too big,
   the crit section can probably be made smaller, but the
   current behaviour is safe and avoids retry heuristics.
*/

/*
   Key to the control/smtproutes parser:

	0	1	2	3	4	5
st\ev	EOF	#	\n	:	0-9	other

0				h	n	n
START	END	COMMENT	START	RELAY	HOST	HOST

1
COMMENT	END	COMMENT	START	COMMENT	COMMENT	COMMENT

2		n		h	n	n
HOST	X	HOST	X	RELAY	HOST	HOST

3	ra	n	ra	r	n	n
RELAY	END	RELAY	START	PORT	RELAY	RELAY

4	pa		pa		n
PORT	END	X	START	X	PORT	X

END=5, X=6

0x08    n	push character
0x10	h	compute host length
0x20	r	compute relay length
0x40	p	compute port
0x80	a	add route entry
*/

static inline uint8_t cclass (char c)
{
  switch (c)
  {
    case 0 : return 0 ;
    case '#' : return 1 ;
    case '\n' : return 2 ;
    case ':' : return 3 ;
    case '0' :
    case '1' :
    case '2' :
    case '3' :
    case '4' :
    case '5' :
    case '6' :
    case '7' :
    case '8' :
    case '9' : return 4 ;
    default : break ;
  }
  return 5 ;
}

static inline char getnext (buffer *b)
{
  char c ;
  ssize_t r = buffer_get(b, &c, 1) ;
  if (r == -1) qmailr_tempsys("unable to read from control/smtproutes") ;
  return r ? c : 0 ;
}

static inline void smtproutes_compile (int fdr, int fdw)
{
  static uint8_t const table[5][6] =
  {
    { 0x05, 0x01, 0x00, 0x13, 0x0a, 0x0a },
    { 0x05, 0x01, 0x00, 0x01, 0x01, 0x01 },
    { 0x06, 0x0a, 0x06, 0x13, 0x0a, 0x0a },
    { 0xa5, 0x0b, 0xa0, 0x24, 0x0b, 0x0b },
    { 0xc5, 0x06, 0xc0, 0x06, 0x0c, 0x06 }
  } ;
  cdbmaker cm = CDBMAKER_ZERO ;
  stralloc sa = STRALLOC_ZERO ;
  char buf[2048] ;
  buffer b = BUFFER_INIT(&buffer_read, fdr, buf, 2048) ;
  uint32_t relaypos = 0, relayend = 0 ;
  uint8_t state = 0 ;
  if (!cdbmake_start(&cm, fdw)) qmailr_tempsys("Unable to cdbmake_start") ;

  while (state < 5)
  {
    char c = getnext(&b) ;
    uint8_t val = table[state][cclass(c)] ;
    state = val & 0x07 ;
    if (val & 0x08)
    {
      if (!stralloc_catb(&sa, &c, 1)) qmailr_tempsys("Unable to grow stralloc") ;
    }
    if (val & 0x10)
    {
      relaypos = sa.len + 1 ;
      if (!stralloc_catb(&sa, "\0\0\31", 3)) qmailr_tempsys("Unable to grow stralloc") ;
    }
    if (val & 0x20)
    {
      if (!stralloc_0(&sa)) qmailr_tempsys("Unable to grow stralloc") ;
      relayend = sa.len ;
    }
    if (val & 0x40)
    {
      uint16_t port ;
      if (!stralloc_0(&sa)) qmailr_tempsys("Unable to grow stralloc") ;
      if (!uint160_scan(sa.s + relayend, &port)) qmailr_temp("Invalid port in control/smtproutes") ;
      uint16_pack_big(sa.s + relaypos, port) ;
    }
    if (val & 0x80)
    {
      if (!cdbmake_add(&cm, sa.s, relaypos, sa.s + relaypos, relayend - relaypos))
        qmailr_tempsys("Unable to cdbmake_add") ;
      sa.len = 0 ;
    }
  }
  if (state != 5) qmailr_temp("Syntax error in control/smtproutes") ;
  stralloc_free(&sa) ;
  if (!cdbmake_finish(&cm)) qmailr_tempsys("Unable to cdbmake_finish") ;
}

int smtproutes_init (cdb *c)
{
  static char const *cdbfile = SMTPD_STARTTLS_PROXY_QMAIL_HOME "/run/qmail-remote/smtproutes.cdb" ;
  static char const *lckfile = SMTPD_STARTTLS_PROXY_QMAIL_HOME "/run/qmail-remote/smtproutes.lock" ;
  static char const *txtfile = SMTPD_STARTTLS_PROXY_QMAIL_HOME "/control/smtproutes" ;
  static size_t const cdblen = sizeof(cdbfile) - 1 ;
  int fdl = openc_create(lckfile) ;
  if (fdl == -1) qmailr_tempsys("Unable to open run/qmail-remote/smtproutes.lock") ;
  if (fd_lock(fdl, 1, 0) == -1) qmailr_tempsys("Unable to lock run/qmail-remote/smtproutes.lock") ;

  int fdc = openc_read(cdbfile) ;
  if (fdc >= 0)
  {
    struct stat stc, str ;
    if (fstat(fdc, &stc) == -1) qmailr_tempsys("Unable to fstat run/qmail-remote/smtproutes.cdb") ;
    if (stat(txtfile, &str) == -1)
    {
      if (errno != ENOENT) qmailr_tempsys("Unable to fstat control/smtproutes") ;
      unlink_void(cdbfile) ;
      fd_close(fdc) ;
      goto zero ;
    }
    if (timespec_cmp(&stc.st_mtim, &str.st_mtim) > 0) goto useit ;
    fd_close(fdc) ;
  }

  int fdr = openc_read(txtfile) ;
  if (fdr == -1)
  {
    if (errno != ENOENT) qmailr_tempsys("Unable to open control/smtproutes") ;
    goto zero ;
  }

  {
    char tmp[cdblen + 8] ;
    memcpy(tmp, cdbfile, cdblen) ;
    memcpy(tmp + cdblen, ":XXXXXX", 8) ;
    fdc = mkstemp(tmp) ;
    if (fdc == -1) qmailr_tempsys("Unable to mkstemp") ;
    smtproutes_compile(fdr, fdc) ;
    if (lseek(fdc, 0, SEEK_SET) == -1) qmailr_tempsys("Unable to lseek") ;
    if (fsync(fdc) == -1) qmailr_tempsys("Unable to fsync run/qmail-remote/smtproutes.cdb") ;
    fd_close(fdr) ;
    if (rename(tmp, cdbfile) == -1) unlink_void(tmp) ;
  }

 useit:
  if (!cdb_init_fromfd(c, fdc)) qmailr_tempsys("Unable to mmap run/qmail-remote/smtproutes.cdb") ;
  fd_close(fdc) ;
  fd_close(fdl) ;
  return 1 ;

 zero:
  fd_close(fdl) ;
  errno = 0 ;
  return 0 ;
}
