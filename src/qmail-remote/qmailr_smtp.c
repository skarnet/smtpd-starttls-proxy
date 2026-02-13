/* ISC license. */

#include <strings.h>
#include <errno.h>

#include <skalibs/types.h>
#include <skalibs/buffer.h>
#include <skalibs/tai.h>
#include <skalibs/unix-timed.h>

#include "qmailr.h"

#include <skalibs/posixishard.h>

int qmailr_smtp_read_line (buffer *in, char *line, size_t max, unsigned int *code, tain const *deadline)
{
  unsigned int c ;
  size_t w = 0 ;
  ssize_t r = timed_getlnmax_g(in, line, max, &w, '\n', deadline) ;
  if (r <= 0) return r ;
  if (w < 4) return (errno = EPROTO, -1) ;
  line[--w] = 0 ;
  if (line[w-1] == '\r') line[--w] = 0 ;
  while (w >= 3 && line[w-1] == ' ') line[--w] = 0 ;
  if (uint_scan(line, &c) != 3) return (errno = EPROTO, -1) ;
  *code = c ;
  return 1 + (line[3] == '-') ;
}

int qmailr_smtp_read_answer (buffer *in, char *line, size_t max, unsigned int timeout)
{
  unsigned int code = 1000 ;
  tain deadline ;
  qdeadline(&deadline, timeout) ;
  for (;;)
  {
    unsigned int c ;
    int r = qmailr_smtp_read_line(in, line, max, &c, &deadline) ;
    if (r <= 0) return r ;
    if (code == 1000) code = c ;
    else if (code != c) return (errno = EPROTO, -1) ;
    if (r == 1) break ;
  }
  return code ;
}

void qmailr_smtp_quit (buffer *out, unsigned int timeout)
{
  tain deadline ;
  buffer_puts(out, "QUIT\r\n") ;
  qdeadline(&deadline, timeout) ;
  buffer_timed_flush_g(out, &deadline) ;
}
