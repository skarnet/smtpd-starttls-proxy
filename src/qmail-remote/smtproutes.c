/* ISC license. */

#include <skalibs/bsdsnowflake.h>

#include <string.h>
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
#include <skalibs/lolstdio.h>

#include <smtpd-starttls-proxy/config.h>
#include "qmailr.h"
#include "qmail-remote.h"


/*
   qmail-remote uses a "constmap" for smtproutes, which is
   basically a cdb in RAM. Every instance of qmail-remote
   parses control/smtproutes to make the constmap.
   We replace it with a real cdb, stored in the filesystem.
   It saves CPU (N-1 instances of qmail-remote use the cdb
   directly) and RAM (the cdb is read-only and shared).
   The cdb is updated whenever control/smtproutes is newer.
   We have to lock around the test to avoid several
   concurrent compilations; the current lock feels too big,
   the crit section can probably be made smaller, but the
   behaviour is safe and avoids retry heuristics.
*/

/*
   Key to the control/smtproutes parser
   [host]:[relay[:port]]
   An ip in square brackets is acceptable in host and relay, even ipv6


	0	1	2	3	4	5	6	7	8	9
st\ev	EOF	#	\n	:	[	]	0-9	a-f	other	special

0				h			n	n	n
START	END	COMMENT	START	RELAY	QHOST	X	HOST	HOST	HOST	X

1
COMMENT	END	COMMENT	START	COMMENT	COMMENT	COMMENT	COMMENT	COMMENT	COMMENT COMMENT

2				n			n	n
QHOST	X	X	X	QHOST	X	EHOST	QHOST	QHOST	X	X

3		n		h			n	n	n
HOST	X	HOST	X	RELAY	X	X	HOST	HOST	HOST	X

4				h
EHOST	X	X	X	RELAY	X	X	X	X	X	X

5	ra	n	ra	r			n	n	n
RELAY	END	INRELAY	START	PORT	QRELAY	X	INRELAY	INRELAY	INRELAY	X

6				n			n	n
QRELAY	X	X	X	QRELAY	X	ERELAY	QRELAY	QRELAY	X	X

7	ra		ra	r			n	n	n
INRELAY	END	X	START	PORT	X	X	INRELAY INRELAY	INRELAY	X

8	ra		ra	r
ERELAY	END	X	START	PORT	X	X	X	X	X	X

9	pa		pa				n
PORT	END	X	START	X	X	X	PORT	X	X	X

END=a, X=b

0x0100  n	push character
0x0200	h	compute host length
0x0400	r	compute relay length
0x0800	p	compute port
0x1000	a	add route entry
*/

static inline uint8_t cclass (char c)
{
  static uint8_t const table[128] = "0999999999299999999999999999999998918889999898786666666666399898877777788888888888888888884958898888888888888888888888888899999" ;
  return c & 0x80 ? 9 : table[(uint8_t)c] - '0' ;
}

static inline char getnext (buffer *b)
{
  char c ;
  ssize_t r = buffer_get(b, &c, 1) ;
  if (r == -1) qmailr_tempusys("read ", "control/smtproutes") ;
  return r ? c : 0 ;
}

static inline void smtproutes_compile (int fdr, int fdw)
{
  static uint16_t const table[10][10] =
  {
    { 0x000a, 0x0001, 0x0000, 0x0205, 0x0002, 0x000b, 0x0103, 0x0103, 0x0103, 0x000b },
    { 0x000a, 0x0001, 0x0000, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001 },
    { 0x000b, 0x000b, 0x000b, 0x0102, 0x000b, 0x0004, 0x0102, 0x0102, 0x0102, 0x000b },
    { 0x000b, 0x0103, 0x000b, 0x0205, 0x000b, 0x000b, 0x0103, 0x0103, 0x0103, 0x000b },
    { 0x000b, 0x000b, 0x000b, 0x0205, 0x000b, 0x000b, 0x000b, 0x000b, 0x000b, 0x000b },
    { 0x140a, 0x0107, 0x1400, 0x0409, 0x0006, 0x000b, 0x0107, 0x0107, 0x0107, 0x000b },
    { 0x000b, 0x000b, 0x000b, 0x0106, 0x000b, 0x0008, 0x0106, 0x0106, 0x0106, 0x000b },
    { 0x140a, 0x000b, 0x1400, 0x0409, 0x000b, 0x000b, 0x0107, 0x0107, 0x0107, 0x000b },
    { 0x140a, 0x000b, 0x1400, 0x0409, 0x000b, 0x000b, 0x000b, 0x000b, 0x000b, 0x000b },
    { 0x180a, 0x000b, 0x1800, 0x000b, 0x000b, 0x000b, 0x0109, 0x000b, 0x000b, 0x000b }
  } ;
  cdbmaker cm = CDBMAKER_ZERO ;
  stralloc sa = STRALLOC_ZERO ;
  char buf[2048] ;
  buffer b = BUFFER_INIT(&buffer_read, fdr, buf, 2048) ;
  uint32_t relaypos = 0, relayend = 0 ;
  uint8_t state = 0 ;
  if (!cdbmake_start(&cm, fdw)) qmailr_tempusys("cdbmake_start") ;

  while (state < 0x0a)
  {
    char c = getnext(&b) ;
    uint16_t val = table[state][cclass(c)] ;
    LOLDEBUG("state %hhu, char %c, newstate %hu, actions %s%s%s%s%s", state, c, val & 0x000f,
      val & 0x0100 ? "n" : "",
      val & 0x0200 ? "h" : "",
      val & 0x0400 ? "r" : "",
      val & 0x0800 ? "p" : "",
      val & 0x1000 ? "a" : "") ;
    state = val & 0x000f ;
    if (val & 0x0100)
    {
      if (!stralloc_catb(&sa, &c, 1)) dienomem() ;
    }
    if (val & 0x0200)
    {
      relaypos = sa.len + 1 ;
      if (!stralloc_catb(&sa, "\0\0\31", 3)) dienomem() ;
    }
    if (val & 0x0400)
    {
      if (!stralloc_0(&sa)) dienomem() ;
      relayend = sa.len ;
    }
    if (val & 0x0800)
    {
      uint16_t port ;
      if (!stralloc_0(&sa)) dienomem() ;
      if (!uint160_scan(sa.s + relayend, &port)) qmailr_temp("Invalid port in ", "control/smtproutes") ;
      uint16_pack_big(sa.s + relaypos, port) ;
    }
    if (val & 0x1000)
    {
      if (relaypos || relayend > 2 + relaypos)
      {
        uint16_t port ;
        uint16_unpack_big(sa.s + relaypos, &port) ;
        LOLDEBUG("adding entry: %.*s -> %.*s port %hu", (int)relaypos, sa.s, (int)(relayend - relaypos - 2), sa.s + relaypos + 2, port) ;
        if (!cdbmake_add(&cm, sa.s, relaypos, sa.s + relaypos, relayend - relaypos))
          qmailr_tempusys("cdbmake_add") ;
      }
      sa.len = 0 ;
    }
  }
  if (state != 0x0a) qmailr_temp("Syntax error in ", "control/smtproutes") ;
  stralloc_free(&sa) ;
  if (!cdbmake_finish(&cm)) qmailr_tempusys("cdbmake_finish") ;
}

int smtproutes_init (smtproutes *routes)
{
  static char const *cdbfile = SMTPD_STARTTLS_PROXY_QMAIL_HOME "/run/qmail-remote/smtproutes.cdb" ;
  static char const *lckfile = SMTPD_STARTTLS_PROXY_QMAIL_HOME "/run/qmail-remote/smtproutes.lock" ;
  static char const *txtfile = SMTPD_STARTTLS_PROXY_QMAIL_HOME "/control/smtproutes" ;
  static size_t const cdblen = sizeof(SMTPD_STARTTLS_PROXY_QMAIL_HOME "/run/qmail-remote/smtproutes.cdb") - 1 ;
  int fdl = openc_create(lckfile) ;
  if (fdl == -1) qmailr_tempusys("open ", "run/qmail-remote/smtproutes.lock") ;
  if (fd_lock(fdl, 1, 0) == -1) qmailr_tempusys("lock ", "run/qmail-remote/smtproutes.lock") ;

  int fdc = openc_read(cdbfile) ;
  if (fdc >= 0)
  {
    struct stat stc, str ;
    if (fstat(fdc, &stc) == -1) qmailr_tempusys("fstat ", "run/qmail-remote/smtproutes.cdb") ;
    if (stat(txtfile, &str) == -1)
    {
      if (errno != ENOENT) qmailr_tempusys("fstat ", "control/smtproutes") ;
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
    if (errno != ENOENT) qmailr_tempusys("open ", "control/smtproutes") ;
    goto zero ;
  }

  {
    char tmp[cdblen + 8] ;
    memcpy(tmp, cdbfile, cdblen) ;
    memcpy(tmp + cdblen, ":XXXXXX", 8) ;
    fdc = mkstemp(tmp) ;
    if (fdc == -1) qmailr_tempusys("mkstemp ", tmp) ;
    smtproutes_compile(fdr, fdc) ;
    if (lseek(fdc, 0, SEEK_SET) == -1) qmailr_tempusys("lseek") ;
    if (fsync(fdc) == -1) qmailr_tempusys("fsync ", tmp) ;
    fd_close(fdr) ;
    if (rename(tmp, cdbfile) == -1) unlink_void(tmp) ;
  }

 useit:
  if (!cdb_init_fromfd(&routes->map, fdc)) qmailr_tempusys("mmap ", "run/qmail-remote/smtproutes.cdb") ;
  fd_close(fdc) ;
  fd_close(fdl) ;
  return 1 ;

 zero:
  fd_close(fdl) ;
  errno = 0 ;
  return 0 ;
}

int smtproutes_match (smtproutes const *routes, char const *s, stralloc *sa, size_t *pos, uint16_t *port)
{
  cdb_data data ;
  int r = cdb_find(&routes->map, &data, s, strlen(s)) ;
  if (r == -1) qmailr_temp("Invalid run/qmail-remote/smtproutes.cdb") ;
  if (!r) return 0 ;
  if (data.len < 3) return 0 ;
  if (data.s[data.len - 1]) qmailr_temp("Invalid ", "run/qmail-remote/smtproutes.cdb") ;
  *pos = sa->len ;
  uint16_unpack_big(data.s, port) ;
  if (!stralloc_catb(sa, data.s + 2, data.len - 2)) dienomem() ;
  return 1 ;
}

void smtproutes_free (smtproutes *routes)
{
  cdb_free(&routes->map) ;
}
