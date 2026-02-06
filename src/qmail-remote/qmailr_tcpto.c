/* ISC license. */

#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#include <skalibs/uint32.h>
#include <skalibs/uint64.h>
#include <skalibs/allreadwrite.h>
#include <skalibs/cdb.h>
#include <skalibs/tai.h>
#include <skalibs/djbunix.h>

#include <smtpd-starttls-proxy/config.h>
#include "qmailr.h"

#include <skalibs/posixishard.h>


/*
   tcpto implementation, should be compatible with qmail-tcpto.
   Assumes the 4 unused bytes at the end of a record are there to
   accommodate 64-bit time_t. Which we use. But qmail-tcpto does
   not, so you should patch that before 2038.
   Has ipv6 support, storing v6 records in a different file.
   Unlike qmail's tcpto, we assume the records are sorted by IP.
   This makes it easy to look for a record with bsearch. We
   keep records sorted with every modification, and we aggressively
   cut empty ones from the file.
   For the match function, not sure what is faster between mmapping and
   simple reading. Currently we mmap to save private/dirty RAM, but
   that holds the lock longer; it should be ok because we switched to
   a shared lock for this (unsure why djb didn't).
*/

int qmailr_tcpto_match (char const *ip, int is6)
{
  char const *file = is6 ? SMTPD_STARTTLS_PROXY_QMAIL_HOME "/run/qmail-remote/tcpto6" : SMTPD_STARTTLS_PROXY_QMAIL_HOME "/queue/lock/tcpto" ;
  uint32_t iplen = is6 ? 16 : 4 ;
  uint32_t width = iplen + 12 ;
  int r = 0 ;
  char const *p ;
  cdb c ;  /* XXX: not a cdb, we're just using the mmap wrapper */
  int fd = openc_read(file) ;

  if (fd == -1) return -1 ;
  if (fd_lock(fd, 0, 0) == -1) goto err ;
  if (!cdb_init_fromfd(&c, fd)) goto err ;
  if (c.size % width) goto errproto ;
  p = bsearch(ip, c.map, c.size / width, width, is6 ? &qmailr_memcmp16 : &qmailr_memcmp4) ;
  if (p)
  {
    if (p[iplen] >= 2)
    {
      tai when ;
      uint64_t x ;
      uint64_unpack(p + iplen + 4, &x) ;
      tai_u64(&when, x) ;
      tai_sub(&when, tain_secp(&STAMP), &when) ;
      r = tai_sec(&when) < ((60 + (getpid() & 31)) << 6) ;  /* don't ask me, ask djb */
    }
  }
  cdb_free(&c) ;
  fd_close(fd) ;
  return r ;

 errproto:
  errno = EPROTO ;
 err:
  fd_close(fd) ;
  return -1 ;
}

int qmailr_tcpto_update (char const *ip, int is6, int problem)
{
  char const *file = is6 ? SMTPD_STARTTLS_PROXY_QMAIL_HOME "/run/qmail-remote/tcpto6" : SMTPD_STARTTLS_PROXY_QMAIL_HOME "/queue/lock/tcpto" ;
  uint32_t iplen = is6 ? 16 : 4 ;
  uint32_t width = iplen + 12 ;
  uint32_t n ;
  char *p = 0 ;
  struct stat st ;
  int fdr ;
  int fdw = openc_create(file) ;

  if (fdw == -1) return 0 ;
  if (fd_lock(fdw, 1, 0) == -1) goto err ;
  fdr = openc_read(file) ;
  if (fdr == -1) goto err ;
  if (fstat(fdr, &st) == -1) goto err0 ;
  if (st.st_size % width) goto errproto ;
  n = st.st_size / width ;

  {
    char buf[(n+1) * width] ;  /* relax, it won't bite */
    if (n)
    {
      if (allread(fdr, buf, st.st_size) < st.st_size) goto err0 ;
      memset(buf + st.st_size, 0, width) ;
      p = bsearch(ip, buf, n, width, is6 ? &qmailr_memcmp16 : &qmailr_memcmp4) ;
      if (p)
      {
        if (problem)
        {
          tai when ;
          uint64_t x ;
          uint64_unpack(p + iplen + 4, &x) ;
          tai_u64(&when, x) ;
          tai_sub(&when, tain_secp(&STAMP), &when) ;
          if (tai_sec(&when) < 120) p = 0 ;
          else
          {
            if (++p[iplen] > 10) p[iplen] = 10 ;
            x = tai_sec(tain_secp(&STAMP)) - TAI_MAGIC ;
            uint64_pack(p + iplen + 4, x) ;
          }
        }
        else p[iplen] = 0 ;
      }
    }
    else if (problem)
    {
      uint64_t x = tai_sec(tain_secp(&STAMP)) - TAI_MAGIC ;
      p = buf + n++ * width ;
      memcpy(p, ip, iplen) ;
      p[iplen] = 1 ;
      memset(p + iplen + 1, 0, 3) ;
      uint64_pack(p + iplen + 4, x) ;
    }
    fd_close(fdr) ;

    if (p)
    {
      for (uint32_t i = 0 ; i < n ; i++)
        if (!buf[i * width + iplen])
          memcpy(buf + i * width, buf + --n * width, width) ;
      if (n)
      {
        qsort(buf, n, width, is6 ? &qmailr_memcmp16 : &qmailr_memcmp4) ;
        if (allwrite(fdw, buf, n * width) < n * width) goto err ;
      }
      if (ftruncate(fdw, n * width) == -1) goto err ;
    }
  }

  fd_close(fdw) ;
  return 1 ;

 errproto:
  errno = EPROTO ;
 err0:
  fd_close(fdr) ;
 err:
  fd_close(fdw) ;
  return 0 ;
}
