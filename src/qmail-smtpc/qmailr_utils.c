/* ISC license. */

#include <string.h>

#include "qmailr.h"

int qmailr_memcmp4 (void const *a, void const *b)
{
  return memcmp(a, b, 4) ;
}

int qmailr_memcmp16 (void const *a, void const *b)
{
  return memcmp(a, b, 16) ;
}
