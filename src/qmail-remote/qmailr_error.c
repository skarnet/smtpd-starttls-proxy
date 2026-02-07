/* ISC license. */

#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <skalibs/buffer.h>

#include <smtpd-starttls-proxy/config.h>

void qmailr_warnv (char code, char const *const *v, unsigned int n)
{
  buffer_put(buffer_1, &code, 1) ;
  while (n--) buffer_puts(buffer_1, *v++) ;
  buffer_putflush(buffer_1, "\n", 2) ;
}

void qmailr_diev (char code, char const *const *v, unsigned int n)
{
  qmailr_warnv(code, v, n) ;
  _exit(0) ;
}

void qmailr_dievsys (char const *const *v, unsigned int n)
{
  char const *se = strerror(errno) ;
  buffer_put(buffer_1, "Z", 1) ;
  while (n--) buffer_puts(buffer_1, *v++) ;
  buffer_put(buffer_1, ": ", 2) ;
  buffer_puts(buffer_1, se) ;
  buffer_putflush(buffer_1, "\n", 2) ;
  _exit(0) ;
}
