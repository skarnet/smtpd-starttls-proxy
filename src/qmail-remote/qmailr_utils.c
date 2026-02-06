/* ISC license. */

#include <string.h>

#include <skalibs/bitarray.h>
#include <skalibs/stralloc.h>

#include "qmailr.h"

int qmailr_memcmp4 (void const *a, void const *b)
{
  return memcmp(a, b, 4) ;
}

int qmailr_memcmp16 (void const *a, void const *b)
{
  return memcmp(a, b, 16) ;
}

static inline int needsquoting (char const *s, size_t len)
{
  static unsigned char const badchar[32] =
  {
    0xff, 0xff, 0xff, 0xff,
    0x05, 0x13, 0x00, 0x5c,
    0x01, 0x00, 0x00, 0x38,
    0x00, 0x00, 0x00, 0x80,
    0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff,
  } ;
  if (!len) return 1 ;
  if (s[0] == '.' || s[len - 1] == '.') return 1 ;
  for (size_t i = 0 ; i < len ; i++)
  {
    if (bitarray_peek(badchar, (unsigned char)s[i])) return 1 ;
    if (i + 2 < len && s[i] == '.' && s[i+1] == '.') return 1 ;
  }
  return 0 ;
}

int qmailr_box_encode (char const *s, size_t len, stralloc *storage)
{
  if (needsquoting(s, len))
  {
    size_t j = storage->len ;
    if (!stralloc_readyplus(storage, 2 + (len << 1))) return 0 ;
    storage->s[j++] = '"' ;
    for (size_t i = 0 ; i < len ; i++)
    {
      if (strchr("\"\\\r\n", s[i])) storage->s[j++] = '\\' ;
      storage->s[j++] = s[i] ;
    }
    storage->s[j++] = '"' ;
    storage->len = j ;
  }
  else if (!stralloc_catb(storage, s, len)) return 0 ;
  return 1 ;
}
