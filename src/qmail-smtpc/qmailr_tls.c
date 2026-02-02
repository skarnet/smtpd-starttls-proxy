/* ISC license. */

#include <stddef.h>

#include <smtpd-starttls-proxy/config.h>
#include "qmailr.h"

int qmailr_tls_init (qmailr_tls *qt, stralloc *sa)
{
  static char const *tafile = SMTPD_STARTTLS_PROXY_QMAIL_HOME "/control/trustanchors" ;
  static char const *certfile = SMTPD_STARTTLS_PROXY_QMAIL_HOME "/control/clientcert" ;
  static char const *keyfile = SMTPD_STARTTLS_PROXY_QMAIL_HOME "/control/clientkey" ;

  qmailr_tls tmp = QMAILR_TLS_ZERO ;
  size_t sabase = sa->len ;
  int r = qmailr_control_read(tafile, sa, &tmp.tapos) ;
  if (r == -1) return 0 ;
  if (r)
  {
    tmp.flagtls = 1 ;
    if (sa->s[sa->len - 2] == '/')
    {
      sa->s[--sa->len - 1] = 0 ;
      tmp.flagtadir = 1 ;
    }
    r = qmailr_control_read(certfile, sa, &tmp.certpos) ;
    if (r == -1) goto err ;
    if (r)
    {
      r = qmailr_control_read(keyfile, sa, &tmp.keypos) ;
      if (r == -1) goto err ;
      if (r) tmp.flagclientcert = 1 ;
    }
  }

  *qt = tmp ;
  return 1 ;

 err:
  sa->len = sabase ;
  return 0 ;
}
