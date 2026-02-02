/* ISC license. */

#include <stddef.h>
#include <errno.h>

#include <skalibs/types.h>
#include <skalibs/allreadwrite.h>
#include <skalibs/buffer.h>
#include <skalibs/fmtscan.h>
#include <skalibs/stralloc.h>
#include <skalibs/djbunix.h>

#include "qmailr.h"

#include <skalibs/posixishard.h>

int qmailr_control_read (char const *file, stralloc *sa, size_t *pos)
{
  int fd = openc_readb(file) ;
  if (fd == -1) return errno == ENOENT ? (errno = 0, 0) : -1 ;

  char buf[4096] ;
  size_t r = allread(fd, buf, 4096) ;
  fd_close(fd) ;
  if (r == 4096) return (errno = ENAMETOOLONG, -1) ;
  if (!r) return 0 ;
  if (buf[r-1] == '\n') r-- ;
  if (!r) return 0 ;
  if (!stralloc_readyplus(sa, r+1)) return -1 ;
  *pos = sa->len ;
  stralloc_catb(sa, buf, r) ; stralloc_0(sa) ;
  return 1 ;
}

int qmailr_control_readint (char const *file, unsigned int *x, stralloc *sa)
{
  size_t pos ;
  int r = qmailr_control_readfile(file, sa, &pos) ;
  if (r <= 0) return r ;
  sa->len = pos ;
  if (!uint0_scan(sa->s + sa->len, x)) return (errno = EPROTO, 0) ;
  return 1 ;
}

int qmailr_control_readiplist (char const *file, stralloc *ip4, stralloc *ip6)
{
  int fd = openc_readb(file) ;
  if (fd == -1) return errno == ENOENT ? (errno = 0, 0) : -1 ;

  size_t pos4 = ip4->len, pos6 = ip6->len ;
  char buf[4096] ;
  buffer b = BUFFER_INIT(&buffer_read, fd, buf, 4096) ;

  for (;;)
  {
    char line[128] ;
    char ip[16] ;
    size_t len = 0 ;
    int r = getlnmax(&b, line, 127, &len, '\n') ;
    if (r == -1) goto err ;
    if (!r) break ;
    if (!len) continue ;
    if (line[len-1] != '\n') line[len++] = '\n' ;
    if (ip6_scan(line, ip) == len-1)
    {
      if (!stralloc_catb(ip6, ip, 16)) goto err ;
    }
    else if (ip4_scan(line, ip) == len-1)
    {
      if (!stralloc_catb(ip4, ip, 4)) goto err ;
    }
    else goto errinval ;
  }
  return 1 ;

 errinval:
  errno = EINVAL ;
 err:
  ip4->len = pos4 ; ip6->len = pos6 ;
  return 0 ;
}
