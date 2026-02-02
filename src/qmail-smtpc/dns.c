/* ISC license. */

#include <string.h>
#include <stdlib.h>

#include <skalibs/tai.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <skalibs/ip46.h>
#include <skalibs/random.h>

#include <s6-dns/s6dns.h>

#include "qmailr.h"
#include "qmail-smtpc.h"

static int mx_cmp (void const *a, void const *b)
{
  s6dns_message_rr_mx_t const *aa = a ;
  s6dns_message_rr_mx_t const *bb = b ;
  return aa->preference < bb-> preference ? -1 : aa->preference > bb->preference ;
}

void dns_init (void)
{
  if (!s6dns_init_options(0)) qmailr_tempsys("Unable to init DNS") ;
}

void dns_canon (char const *host, char const *const *recip, unsigned int n, size_t *recippos, genalloc *mxpos, stralloc *storage)
{
  genalloc mx = GENALLOC_ZERO ;  /* s6dns_message_rr_mx_t */
  size_t atpos[n] ;
  s6dns_dpag_t cnames[n] ;
  s6dns_resolve_t info[n + !!mxpos] ;

  for (unsigned int i = 0 ; i < n ; i++)
  {
    char const *at = strrchr(recip[i], '@') ;
    if (!at) qmailr_perm("Invalid recipient") ;
    atpos[i] = at - recip[i] ;
    if (!s6dns_domain_fromstring_noqualify_encode(&info[i].q, at+1, strlen(at+1)))
      qmailr_tempsys("Unable to DNS-encode recipient domain") ;
    cnames[i].ds = genalloc_zero ;
    cnames[i].rtype = S6DNS_T_CNAME ;
    info[i].qtype = S6DNS_T_CNAME ;
    info[i].options = S6DNS_O_RECURSIVE ;
    info[i].deadline = tain_infinite ;
    info[i].parsefunc = &s6dns_message_parse_answer_domain ;
    info[i].data = cnames + i ;
  }
  if (!s6dns_domain_fromstring_noqualify_encode(&info[n].q, host, strlen(host)))
    qmailr_tempsys("Unable to DNS-encode recipient domain") ;

  if (mxpos)
  {
    info[n].qtype = S6DNS_T_MX ;
    info[n].options = S6DNS_O_RECURSIVE ;
    info[n].deadline = tain_infinite ;
    info[n].parsefunc = &s6dns_message_parse_answer_mx ;
    info[n].data = &mx ;
  }

  if (!s6dns_resolven_parse_g(info, n + !!mxpos, 0))
    qmailr_tempsys("Unable to perform DNS resolutions") ;

  for (unsigned int i = 0 ; i < n ; i++)
  {
    recippos[i] = storage->len ;
    // TODO: box_encode(recip[i], atpos[i], storage) ;
    if (!stralloc_catb(storage, "@", 1)) dienomem() ;
    if (!info[i].status && genalloc_len(s6dns_domain_t, &cnames[i].ds))
    {
      if (!s6dns_domain_decode(genalloc_s(s6dns_domain_t, &cnames[i].ds)))
        qmailr_tempsys("Unable to parse CNAME") ;
      if (!stralloc_readyplus(storage, 256)) dienomem() ;
      recippos[i] = storage->len ;
      storage->len += s6dns_domain_tostring(storage->s + storage->len, 255, genalloc_s(s6dns_domain_t, &cnames[i].ds)) ;
      if (storage->s[storage->len-1] == '.') --storage->len ;
      storage->s[storage->len++] = 0 ;
    }
    else if (!stralloc_cats(storage, recip[i] + atpos[i] + 1)) dienomem() ;
    if (!stralloc_0(storage)) dienomem() ;
  }

  if (mxpos && !info[n].status && genalloc_len(s6dns_message_rr_mx_t, &mx))
  {
    s6dns_message_rr_mx_t *mxs = genalloc_s(s6dns_message_rr_mx_t, &mx) ;
    size_t mxlen = genalloc_len(s6dns_message_rr_mx_t, &mx) ;
    qsort(mxs, mxlen, sizeof(s6dns_message_rr_mx_t), &mx_cmp) ;
    if (!genalloc_readyplus(size_t, mxpos, mxlen)) dienomem() ;
    for (size_t i = 0 ; i < mxlen ; i++)
    {
      if (!s6dns_domain_decode(&mxs[i].exchange)) qmailr_tempsys("Unable to parse MX record") ;
      if (!stralloc_readyplus(storage, 256)) dienomem() ;
      genalloc_catb(size_t, mxpos, storage->len, 1) ;
      storage->len += s6dns_domain_tostring(storage->s + storage->len, 255, &mxs[i].exchange) ;
      storage->s[storage->len++] = 0 ;
    }
    genalloc_free(s6dns_message_rr_mx_t, &mx) ;
  }
}

void dns_ip_of_mx (size_t const *pos, unsigned int n, mxip *tab, stralloc *storage, char const *ipme4, unsigned int n4, char const *ipme6, unsigned int n6)
{
#ifdef SKALIBS_IPV6_ENABLED
  unsigned int const N = n << 1 ;
  stralloc ip6[n] ;
#else
  unsigned int const N = n ;
#endif
  stralloc ip4[n] ;
  s6dns_resolve_t info[N] ;
  for (unsigned int i = 0 ; i < n ; i++)
  {
    if (!s6dns_domain_fromstring_noqualify_encode(&info[i].q, storage->s + pos[i], strlen(storage->s + pos[i])))
      qmailr_tempsys("Unable to DNS-encode MX") ;
    ip4[i] = stralloc_zero ;
    info[i].qtype = S6DNS_T_A ;
    info[i].options = S6DNS_O_RECURSIVE ;
    info[i].deadline = tain_infinite ;
    info[i].parsefunc = &s6dns_message_parse_answer_a ;
    info[i].data = ip4 + i ;

#ifdef SKALIBS_IPV6_ENABLED
    ip6[i] = stralloc_zero ;
    info[n+i].q = info[i].q ;
    info[n+i].qtype = S6DNS_T_A ;
    info[n+i].options = S6DNS_O_RECURSIVE ;
    info[n+i].deadline = tain_infinite ;
    info[n+i].parsefunc = &s6dns_message_parse_answer_aaaa ;
    info[n+i].data = ip6 + i ;
#endif
  }

  if (!s6dns_resolven_parse_g(info, N, 0))
    qmailr_tempsys("Unable to perform DNS resolutions") ;

  for (unsigned int i = 0 ; i < n ; i++)
  {
    if (!info[i].status)
    {
      for (unsigned int j = 0 ; j < ip4[i].len ; j += 4)
      {
        if (bsearch(ip4[i].s + j, ipme4, n4, 4, &qmailr_memcmp4))
        {
          memmove(ip4[i].s + j, ip4[i].s + ip4[i].len - 4, 4) ;
          ip4[i].len -= 4 ;
        }
      }
      random_unsort(ip4[i].s, ip4[i].len >> 2, 4) ;
      tab[i].pos4 = storage->len ;
      tab[i].n4 = ip4[i].len >> 2 ;
      if (!stralloc_catb(storage, ip4[i].s, ip4[i].len)) dienomem() ;
      stralloc_free(ip4 + i) ;
    }

#ifdef SKALIBS_IPV6_ENABLED
    if (!info[n+i].status)
    {
      for (unsigned int j = 0 ; j < ip6[i].len ; j += 16)
      {
        if (bsearch(ip6[i].s + j, ipme6, n6, 16, &qmailr_memcmp16))
        {
          memmove(ip6[i].s + j, ip6[i].s + ip6[i].len - 16, 16) ;
          ip6[i].len -= 16 ;
        }
      }
      random_unsort(ip6[i].s, ip6[i].len >> 4, 16) ;
      tab[i].pos6 = storage->len ;
      tab[i].n6 = ip6[i].len >> 4 ;
      if (!stralloc_catb(storage, ip6[i].s, ip6[i].len)) dienomem() ;
      stralloc_free(ip6 + i) ;
    }
#endif

  }
}
