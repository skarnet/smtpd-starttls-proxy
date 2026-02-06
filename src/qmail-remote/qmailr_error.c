/* ISC license. */

#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <skalibs/buffer.h>

#include <smtpd-starttls-proxy/config.h>

void qmailr_diev (int permanent, char const *const *v, unsigned int n)
{
  buffer_put(buffer_1small, permanent ? "D" : "Z", 1) ;
  while (n--) buffer_puts(buffer_1small, *v++) ;
  buffer_putflush(buffer_1small, "\n", 2) ;
  _exit(0) ;
}

void qmailr_dievsys (char const *const *v, unsigned int n)
{
  char const *se = strerror(errno) ;
  buffer_put(buffer_1small, "Z", 1) ;
  while (n--) buffer_puts(buffer_1small, *v++) ;
  buffer_put(buffer_1small, ": ", 2) ;
  buffer_puts(buffer_1small, se) ;
  buffer_putflush(buffer_1small, "\n", 2) ;
  _exit(0) ;
}

void qmailr_die (int permanent, char const *msg)
{
  qmailr_diev(permanent, &msg, 1) ;
}

void qmailr_diesys (char const *msg)
{
  qmailr_dievsys(&msg, 1) ;
}
