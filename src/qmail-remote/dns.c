/* ISC license. */

#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <stdlib.h>
#include <errno.h>

#include <skalibs/tai.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <skalibs/iopause.h>
#include <skalibs/ip46.h>
#include <skalibs/random.h>
#include <skalibs/prog.h>
#include <skalibs/lolstdio.h>

#include <s6-dns/s6dns.h>
#include <s6-dns/skadns.h>

#include "qmailr.h"
#include "qmail-remote.h"

typedef struct cnameinfo_s cnameinfo, *cnameinfo_ref ;
struct cnameinfo_s
{
  stralloc sa ;
  size_t atpos ;
  uint16_t id ;
  uint16_t count ;
} ;

typedef struct mxipinfo_s mxipinfo, mxipinfo_ref ;
struct mxipinfo_s
{
  stralloc ip4 ;
  stralloc ip6 ;
  uint16_t id4 ;
  uint16_t id6 ;
} ;
#define MXIPINFO_ZERO { .ip4 = STRALLOC_ZERO, .ip6 = STRALLOC_ZERO, .id4 = UINT16_MAX, .id6 = UINT16_MAX }

static int mx_cmp (void const *a, void const *b)
{
  s6dns_message_rr_mx_t const *aa = a ;
  s6dns_message_rr_mx_t const *bb = b ;
  return aa->preference < bb-> preference ? -1 : aa->preference > bb->preference ;
}

static unsigned int use_host_as_mx (skadns_t *a, char const *host, genalloc *mxip, tain const *deadline)
{
  unsigned int newreqs = 0 ;
  mxipinfo info = MXIPINFO_ZERO ;
  s6dns_domain_t q ;
  if (!s6dns_domain_fromstring_noqualify_encode(&q, host, strlen(host)))
    qmailr_tempusys("DNS-encode host domain") ;
  if (!skadns_send_g(a, &info.id4, &q, S6DNS_T_A, deadline, deadline))
    qmailr_tempusys("send ", "A", " DNS query") ;
  LOLDEBUG("sending A for %s, id %hu", host, info.id4) ;
  newreqs++ ;
#ifdef SKALIBS_IPV6_ENABLED
  if (!skadns_send_g(a, &info.id6, &q, S6DNS_T_AAAA, deadline, deadline))
    qmailr_tempusys("send ", "AAAA", " DNS query") ;
  LOLDEBUG("sending AAAA for %s, id %hu", host, info.id6) ;
  newreqs++ ;
#endif
  if (!genalloc_catb(mxipinfo, mxip, &info, 1)) dienomem() ;
  return newreqs ;
}

 /*
   The point of this monster here is to do all the DNS resolutions in parallel,
   to avoid compounding network latency. One of the many things that could never
   be done by patching the original qmail-remote.
   1 sender + n-1 recipients are given in eaddr.
   - loop around CNAME until we get the canonical name, for the n eaddrs
   - either lookup the MX for the host then find all the A and AAAAs of all the MXes,
     or get the A and AAAAs of the host directly (if smtproutes)
   - do not keep the As and AAAAs listed in ipme
   - sort the set of IPs by MX preference
   When done, addrmangle (i.e. quote if needed) all the boxnames in eaddr.
   Shove everything in storage and return the indices:
   in eaddrpos for sender+recipients, in mxipind for the IPs to connect to.

   Also, fuck DNS for requiring so many small allocations and data copies.

   Also, fuck DNS.
 */

unsigned int dns_stuff (char const *host, char const *const *eaddr, unsigned int n, size_t *eaddrpos, genalloc *mxipind, stralloc *storage, unsigned int timeoutdns, char const *ipme4, unsigned int n4, char const *ipme6, unsigned int n6, uint32_t flags)
{
  skadns_t a = SKADNS_ZERO ;
  genalloc mxipi = GENALLOC_ZERO ;  /* mxipinfo */
  unsigned int pending = 0 ;
  unsigned int mxn = 0 ;
  uint16_t mxid = UINT16_MAX ;
  tain deadline ;
  cnameinfo cnames[n] ;

  tain_addsec_g(&deadline, timeoutdns) ;
  if (!skadns_startf_g(&a, &deadline))
    qmailr_tempusys("start asynchronous DNS helper") ;

  for (unsigned int i = 0 ; i < n ; i++)
  {
    char const *at = strrchr(eaddr[i], '@') ;
    cnames[i].sa = stralloc_zero ;
    if (at)
    {
      s6dns_domain_t q ;
      size_t len = strlen(at+1) ;
      cnames[i].atpos = at - eaddr[i] ;
      if (!stralloc_catb(&cnames[i].sa, at+1, len)) dienomem() ;
      if (!s6dns_domain_fromstring_noqualify_encode(&q, at+1, len))
        qmailr_tempusys("DNS-encode recipient domain") ;
      if (!skadns_send_g(&a, &cnames[i].id, &q, S6DNS_T_CNAME, &deadline, &deadline))
        qmailr_tempusys("send ", "CNAME", " DNS query") ;
      LOLDEBUG("sending CNAME for %s, id %hu", at+1, cnames[i].id) ;
      cnames[i].count = 1 ;
      pending++ ;
    }
    else
    {
      cnames[i].id = UINT16_MAX ;
      cnames[i].count = 0 ;
      cnames[i].atpos = strlen(eaddr[i]) ;
    }
  }

  if (flags & 1)
  {
    s6dns_domain_t q ;
    if (!s6dns_domain_fromstring_noqualify_encode(&q, host, strlen(host)))
      qmailr_tempusys("DNS-encode host domain") ;
    if (!skadns_send_g(&a, &mxid, &q, S6DNS_T_MX, &deadline, &deadline))
      qmailr_tempusys("send ", "MX", " DNS query") ;
    LOLDEBUG("sending MX for %s, id %hu", host, mxid) ;
    pending++ ;
  }
  else
  {
    mxn = 1 ;
    pending += use_host_as_mx(&a, host, &mxipi, &deadline) ;
  }

  while (pending)
  {
    uint16_t *ids ;
    iopause_fd x = { .fd = skadns_fd(&a), .events = IOPAUSE_READ } ;
    int r = iopause_g(&x, 1, &deadline) ;
    if (r == -1) qmailr_tempusys("iopause") ;
    if (!r) qmailr_tempsys("Timed out waiting for DNS") ;
    LOLDEBUG("looping, pending = %u", pending) ;
    r = skadns_update(&a) ;
    if (r == -1) qmailr_tempusys("read DNS answers") ;
    ids = genalloc_s(uint16_t, &a.list) ;
    for (size_t j = 0 ; j < genalloc_len(uint16_t, &a.list) ; j++)
    {
      char const *packet = skadns_packet(&a, ids[j]) ;
      uint16_t packetlen = skadns_packetlen(&a, ids[j]) ;
      if (!packet) qmailr_tempsys("DNS packet reading error") ;

      if (ids[j] == mxid)  /* return from MX query */
      {
        s6dns_message_header_t h ;
        genalloc mxes = GENALLOC_ZERO ;  /* s6dns_message_rr_mx_t */

        LOLDEBUG("received id %hu (MX)", mxid) ;
        r = s6dns_message_parse(&h, packet, packetlen, &s6dns_message_parse_answer_mx, &mxes) ;
        if (r == -1) qmailr_tempsys("DNS packet parsing error") ;
        if (!r)
        {
          if (errno == EBUSY || errno == EIO) qmailr_temp("Temporary DNS error while resolving ", "MX") ;
          else qmailr_perm("DNS ", "CNAME", " resolution error") ;
        }
        skadns_release(&a, ids[j]) ;
        pending-- ;
        mxid = UINT16_MAX ;
        if (r >= 2)  /* we have MXes, ask for their IPs */
        {
          s6dns_message_rr_mx_t *mxs = genalloc_s(s6dns_message_rr_mx_t, &mxes) ;
          mxn = genalloc_len(s6dns_message_rr_mx_t, &mxes) ;
          if (!genalloc_readyplus(mxipinfo, &mxipi, mxn)) dienomem() ;
          qsort(mxs, mxn, sizeof(s6dns_message_rr_mx_t), &mx_cmp) ;
          for (unsigned int i = 0 ; i < mxn ; i++)
          {
#ifdef DEBUG
            char exch[256] ;
            s6dns_domain_tostring(exch, 256, &mxs[i].exchange) ;
#endif
            mxipinfo *p = genalloc_s(mxipinfo, &mxipi) + i ;
            p->ip4 = p->ip6 = stralloc_zero ;
            s6dns_domain_encode(&mxs[i].exchange) ;
            if (!skadns_send_g(&a, &p->id4, &mxs[i].exchange, S6DNS_T_A, &deadline, &deadline))
              qmailr_tempusys("send ", "A", " DNS query") ;
            LOLDEBUG("sending A for %s, id %hu", exch, p->id4) ;
            pending++ ;
#ifdef SKALIBS_IPV6_ENABLED
            if (!skadns_send_g(&a, &p->id6, &mxs[i].exchange, S6DNS_T_AAAA, &deadline, &deadline))
              qmailr_tempusys("send ", "AAAA", " DNS query") ;
            LOLDEBUG("sending AAAA for %s, id %hu", exch, p->id6) ;
            pending++ ;
#endif
          }
          genalloc_free(s6dns_message_rr_mx_t, &mxes) ;
        }
        else
        {
          mxn = 1 ;
          pending += use_host_as_mx(&a, host, &mxipi, &deadline) ;
        }
        continue ;
      }

      for (unsigned int i = 0 ; i < n ; i++) if (ids[j] == cnames[i].id)  /* return from CNAME query */
      {
        s6dns_message_header_t h ;
        s6dns_dpag_t dlist = { .ds = GENALLOC_ZERO, .rtype = S6DNS_T_CNAME } ;
        LOLDEBUG("received id %hu (CNAME)", ids[j]) ;
        r = s6dns_message_parse(&h, packet, packetlen, &s6dns_message_parse_answer_domain, &dlist) ;
        if (r == -1) qmailr_tempsys("DNS packet parsing error") ;
        if (!r)
        {
          if (errno == EBUSY || errno == EIO) qmailr_temp("Temporary DNS error while resolving ", "CNAME") ;
          else qmailr_perm("DNS ", "CNAME", " resolution error") ;
        }
        skadns_release(&a, ids[j]) ;
        pending-- ;
        if (r >= 2)  /* it's a CNAME, loop on it */
        {
          s6dns_domain_t *domain = genalloc_s(s6dns_domain_t, &dlist.ds) ;
          if (cnames[i].count++ >= 100) qmailr_perm("DNS CNAME loop") ;
          if (!skadns_send_g(&a, &cnames[i].id, domain, S6DNS_T_CNAME, &deadline, &deadline))
            qmailr_tempusys("send ", "CNAME", " DNS query") ;
#ifdef DEBUG
          {
            char s[256] ;
            s6dns_domain_t dom = *domain ;
            s6dns_domain_decode(&dom) ;
            s6dns_domain_tostring(s, 256, &dom) ;
            LOLDEBUG("sending CNAME for %s, id %hu", s, cnames[i].id) ;
          }
#endif
          pending++ ;
          if (!stralloc_ready(&cnames[i].sa, 256)) dienomem() ;
          s6dns_domain_decode(domain) ;
          cnames[i].sa.len = s6dns_domain_tostring(cnames[i].sa.s, 256, domain) ;
          genalloc_free(s6dns_domain_t, &dlist.ds) ;
        }
        else
        {
          cnames[i].id = UINT16_MAX ;  /* we have the canonical host in cnames[i].sa */
          LOLDEBUG("%.*s is not a CNAME", (int)cnames[i].sa.len, cnames[i].sa.s) ;
        }
        continue ;
      }

      for (unsigned int i = 0 ; i < mxn ; i++)
      {
        mxipinfo *p = genalloc_s(mxipinfo, &mxipi) + i ;
        if (ids[j] == p->id4)
        {
          s6dns_message_header_t h ;
          LOLDEBUG("received id %hu (A)", ids[j]) ;
          r = s6dns_message_parse(&h, packet, packetlen, &s6dns_message_parse_answer_a, &p->ip4) ;
          if (r == -1) qmailr_tempsys("DNS packet parsing error") ;
          if (!r)
          {
            if (errno == EBUSY || errno == EIO) qmailr_temp("Temporary DNS error while resolving ", "A") ;
            else qmailr_perm("DNS ", "A", " resolution error") ;
          }
          skadns_release(&a, ids[j]) ;
          pending-- ;
          p->id4 = UINT16_MAX ;
          for (unsigned int k = 0 ; k < p->ip4.len ; k += 4)
          {
            if (bsearch(p->ip4.s + k, ipme4, n4, 4, &qmailr_memcmp4))
            {
              memmove(p->ip4.s + k, p->ip4.s + p->ip4.len - 4, 4) ;
              p->ip4.len -= 4 ;
              k -= 4 ;
            }
          }
        }
#ifdef SKALIBS_IPV6_ENABLED
        else if (ids[j] == p->id6)
        {
          s6dns_message_header_t h ;
          LOLDEBUG("received id %hu (A)", ids[j]) ;
          r = s6dns_message_parse(&h, packet, packetlen, &s6dns_message_parse_answer_aaaa, &p->ip6) ;
          if (r == -1) qmailr_tempsys("DNS packet parsing error") ;
          if (!r)
          {
            if (errno == EBUSY || errno == EIO) qmailr_temp("Temporary DNS error while resolving ", "AAAA") ;
            else qmailr_perm("DNS ", "AAAA", " resolution error") ;
          }
          skadns_release(&a, ids[j]) ;
          pending-- ;
          p->id6 = UINT16_MAX ;
          for (unsigned int k = 0 ; k < p->ip6.len ; k += 16)
          {
            if (bsearch(p->ip6.s + k, ipme6, n6, 16, &qmailr_memcmp16))
            {
              memmove(p->ip6.s + k, p->ip6.s + p->ip6.len - 16, 16) ;
              p->ip6.len -= 16 ;
              k -= 16 ;
            }
          }
        }
#endif
      }
    }
  }
  skadns_end(&a) ;  /* we done, buddy */

  for (unsigned int i = 0 ; i < n ; i++)
  {
    eaddrpos[i] = storage->len ;
    if (!qmailr_box_encode(eaddr[i], cnames[i].atpos, storage)) dienomem() ;
    if (cnames[i].count)
    {
      if (!stralloc_catb(storage, "@", 1)) dienomem() ;
      if (!stralloc_catb(storage, cnames[i].sa.s, cnames[i].sa.len)) dienomem() ;
      stralloc_free(&cnames[i].sa) ;
    }
    if (!stralloc_0(storage)) dienomem() ;
  }

  if (!genalloc_readyplus(mxip, mxipind, mxn)) dienomem() ;
  for (unsigned int i = 0 ; i < mxn ; i++)
  {
    mxip data ;
    mxipinfo *p = genalloc_s(mxipinfo, &mxipi) + i ;
    data.n4 = p->ip4.len >> 2 ;
    data.pos4 = storage->len ;
    if (!stralloc_catb(storage, p->ip4.s, p->ip4.len)) dienomem() ;
    stralloc_free(&p->ip4) ;
#ifdef SKALIBS_IPV6_ENABLED
    data.n6 = p->ip6.len >> 4 ;
    data.pos6 = storage->len ;
    if (!stralloc_catb(storage, p->ip6.s, p->ip6.len)) dienomem() ;
    stralloc_free(&p->ip6) ;
    genalloc_catb(mxip, mxipind, &data, 1) ;
#endif
  }
  genalloc_free(mxipinfo, &mxipi) ;
  return mxn ;
}
