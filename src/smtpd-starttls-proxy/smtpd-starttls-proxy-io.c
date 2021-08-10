/* ISC license. */

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/uio.h>

#include <skalibs/gccattributes.h>
#include <skalibs/types.h>
#include <skalibs/sgetopt.h>
#include <skalibs/buffer.h>
#include <skalibs/error.h>
#include <skalibs/strerr2.h>
#include <skalibs/tai.h>
#include <skalibs/djbunix.h>
#include <skalibs/iopause.h>
#include <skalibs/skamisc.h>
#include <skalibs/exec.h>
#include <skalibs/unix-timed.h>

#include <s6/config.h>

#define USAGE "smtpd-starttls-proxy-io [ -- ] prog..."
#define dieusage() strerr_dieusage(100, USAGE)

#define INSIZE 1024
#define OUTSIZE 1920

#define reset_timeout() tain_addsec_g(&deadline, 300)

static int fdctl ;
static int sslfds[2] ;
static int wantexec = 0 ;

typedef struct io_s io_t, *io_t_ref ;
struct io_s {
  buffer in ;
  buffer out ;
  size_t w ;
  char line[INSIZE] ;
  char inbuf[INSIZE] ;
  char outbuf[OUTSIZE] ;
} ;

static io_t io[2] =
{
  { .in = BUFFER_INIT(&buffer_read, 0, io[0].inbuf, INSIZE), .out = BUFFER_INIT(&buffer_write, 1, io[0].outbuf, OUTSIZE), .w = 0 },
  { .w = 0 }
} ;

typedef int cbfunc (char const *) ;
typedef cbfunc *cbfunc_ref ;

#define MAXCBQ 16

static cbfunc_ref cbq[MAXCBQ] ;
static size_t cbq_head = 0, cbq_tail = 0 ;

static void cbfunc_enqueue (cbfunc_ref f)
{
  size_t newhead = (cbq_head + 1) % MAXCBQ ;
  if (newhead == cbq_tail)
    strerr_dief1x(101, "cbq full, increase MAXCBQ") ;
  cbq[cbq_head] = f ;
  cbq_head = newhead ;
}

static inline void answer_enqueue (char const *s)
{
  if (buffer_puts(&io[0].out, s) < 0) _exit(1) ;  /* unresponsive client */
}

static int answer_forward (char const *s)
{
  answer_enqueue(s) ;
  return 1 ;
}

static int answer_ehlo (char const *s)
{
  static int needed = 1 ;
  if (needed && s[0] == '2' && !strncasecmp(s+4, "starttls", 8))
  {
    needed = 0 ;
    strerr_warni1x("server seems to support STARTTLS natively") ;
  }
  if (needed && s[3] == ' ') answer_enqueue("250-STARTTLS\r\n") ;
  answer_enqueue(s) ;
  return s[3] == ' ' ;
}

static int trigger_starttls (char const *s)
{
  if (s[0] != '2')
  {
    answer_enqueue("454 Server failed to reset\r\n") ;
    wantexec = 0 ;
  }
  else answer_enqueue("220 Ready to start TLS\r\n") ;
  return 1 ;
}

static void process_server_line (char const *s)
{
  if (s[0] < '0' || s[0] > '5'
   || s[1] < '0' || s[1] > '9'
   || s[2] < '0' || s[2] > '9'
   || (s[3] != ' ' && s[3] != '-'))
    strerr_dief1x(100, "server is not speaking SMTP") ;
  if (cbq_head == cbq_tail)
    strerr_dief1x(101, "can't happen: popping an empty cbq!") ;
  if ((*cbq[cbq_tail])(s)) cbq_tail = (cbq_tail + 1) % MAXCBQ ;
}

typedef int cmdfunc (char const *) ;
typedef cmdfunc *cmdfunc_ref ;

typedef struct cmdmap_s cmdmap, *cmdmap_ref ;
struct cmdmap_s
{
  char const *name ;
  cmdfunc_ref f ;
} ;

static int command_enqueue (char const *s, cbfunc_ref f)
{
  if (buffer_puts(&io[1].out, s) < 0) _exit(1) ;  /* unresponsive server */
  cbfunc_enqueue(f) ;
  return 0 ;
}

static int do_noop (char const *s)
{
  (void)s ;
  answer_enqueue("250 OK\r\n") ;
  return 0 ;
}

static int do_forward (char const *s)
{
  return command_enqueue(s, &answer_forward) ;
}

static int do_badorder (char const *s)
{
  (void)s ;
  answer_enqueue("503 MAIL first. Are you like this with girls too?\r\n") ;
  return 0 ;
}

static int do_ehlo (char const *s)
{
  return command_enqueue(s, &answer_ehlo) ;
}

static int do_notls (char const *s)
{
  size_t n = buffer_len(&io[0].in) ;
  if (buffer_puts(&io[1].out, s) < 0) _exit(1) ;
  fd_close(fdctl) ;
  fd_close(sslfds[1]) ;
  fd_close(sslfds[0]) ;
  if (n)
  {
    struct iovec v[2] ;
    buffer_rpeek(&io[0].in, v) ;
    if (buffer_putv(&io[1].out, v, 2) < 0) _exit(1) ;
    buffer_rseek(&io[0].in, n) ;
  }
  n = buffer_len(&io[1].in) ;
  if (n)
  {
    struct iovec v[2] ;
    buffer_rpeek(&io[1].in, v) ;
    if (buffer_putv(&io[0].out, v, 2) < 0) _exit(1) ;
    buffer_rseek(&io[1].in, n) ;
  }
  wantexec = 1 ;
  return 1 ;
}

static int do_starttls (char const *s)
{
  if (buffer_len(&io[0].in))
    answer_enqueue("503 After STARTTLS you need to stfu\r\n") ;
  else
  {
    command_enqueue("RSET\r\n", &trigger_starttls) ;
    wantexec = 2 ;
  }
  return 0 ;
}

static cmdmap const commands[] =
{
  { .name = "ehlo", .f = &do_ehlo },
  { .name = "starttls", .f = &do_starttls },
  { .name = "helo", .f = &do_notls },
  { .name = "mail", .f = &do_notls },
  { .name = "rcpt", .f = &do_badorder },
  { .name = "data", .f = &do_badorder },
  { .name = "rset", .f = &do_forward },
  { .name = "vrfy", .f = &do_forward },
  { .name = "expn", .f = &do_forward },
  { .name = "help", .f = &do_forward },
  { .name = "noop", .f = &do_noop },
  { .name = "quit", .f = &do_forward },
  { .name = 0, .f = 0 }
} ;

static int process_client_line (char const *s)
{
  cmdmap const *cmd = commands ;
  for (; cmd->name ; cmd++)
  {
    size_t len = strlen(cmd->name) ;
    if (!strncasecmp(s, cmd->name, strlen(cmd->name))
     && (s[len] == ' ' || s[len] == '\r' || s[len] == '\n'))
      break ;
  }
  if (cmd->name) return (*cmd->f)(s) ;
  answer_enqueue("500 SMTP motherfucker, do you speak it?\r\n") ;
  return 0 ;
}


 /* Engine */

static void child (int, int) gccattr_noreturn ;
static void child (int fdr, int fdw)
{
  iopause_fd x[4] = { { .fd = 0 }, { .fd = 1 }, { .fd = fdr }, { .fd = fdw } } ;
  tain deadline ;
  PROG = "smtpd-starttls-proxy-io" ;

  if (ndelay_on(0) < 0 || ndelay_on(1) < 0 || ndelay_on(fdr) < 0 || ndelay_on(fdw) < 0)
    strerr_diefu1sys(111, "make fds non-blocking") ;
  buffer_init(&io[1].in, &buffer_read, fdr, io[1].inbuf, INSIZE) ;
  buffer_init(&io[1].out, &buffer_write, fdw, io[1].outbuf, OUTSIZE) ;
  tain_now_set_stopwatch_g() ;
  reset_timeout() ;

  cbfunc_enqueue(&answer_forward) ;

  for (;;)
  {
    int r ;
    if (!buffer_len(&io[0].out) && (x[2].fd == -1 || (cbq_head == cbq_tail && wantexec))) break ;
    x[0].events = !wantexec ? IOPAUSE_READ : 0 ;
    x[1].events = buffer_len(&io[0].out) ? IOPAUSE_WRITE : 0 ;
    x[2].events = wantexec != 1 ? IOPAUSE_READ : 0 ;
    x[3].events = buffer_len(&io[1].out) ? IOPAUSE_WRITE : 0 ;
    r = iopause_g(x, 4, &deadline) ;
    if (r == -1) strerr_diefu1sys(111, "iopause") ;
    if (!r) strerr_dief1x(99, "timed out") ;
    for (size_t i = 0 ; i < 4 ; i++) if (x[i].revents & IOPAUSE_EXCEPT) x[i].revents |= IOPAUSE_READ | IOPAUSE_WRITE ;

    if (x[1].events & x[1].revents & IOPAUSE_WRITE)
    {
      if (!buffer_flush(&io[0].out))
      {
        if (error_isagain(errno)) strerr_diefu1sys(111, "write to client") ;
      }
      else reset_timeout() ;
    }

    if (x[3].events & x[3].revents & IOPAUSE_WRITE)
    {
      if (!buffer_flush(&io[1].out))
      {
        if (!error_isagain(errno)) strerr_diefu1sys(111, "write to server") ;
      }
      else reset_timeout() ;
    }

    if (x[2].revents & IOPAUSE_READ)
    {
      for (;;)
      {
        int r = getlnmax(&io[1].in, io[1].line, INSIZE - 1, &io[1].w, '\n') ;
        if (r < 0)
        {
          if (error_isagain(errno)) break ;
          else strerr_diefu1sys(111, "read line from server") ;
        }
        if (!r)
        {
          x[3].fd = -1 ;
          x[2].fd = -1 ;
          wantexec = 0 ;
          break ;
        }
        io[1].line[io[1].w] = 0 ;
        reset_timeout() ;
        process_server_line(io[1].line) ;
        io[1].w = 0 ;
      }
    }

    if (x[0].revents & IOPAUSE_READ)
    {
      for (;;)
      {
        int r = getlnmax(&io[0].in, io[0].line, INSIZE - 1, &io[0].w, '\n') ;
        if (r < 0)
        {
          if (error_isagain(errno)) break ;
          else if (errno == ERANGE) _exit(1) ;  /* DoS attempt, just gtfo */
          else strerr_diefu1sys(111, "read line from client") ;
        }
        if (!r) _exit(0) ;
        io[0].line[io[0].w] = 0 ;
        reset_timeout() ;
        if (process_client_line(io[0].line)) break ;
        io[0].w = 0 ;
      }
    }
  }

  if (!wantexec) _exit(0) ;
  if (buffer_len(&io[1].out) && !buffer_timed_flush_g(&io[1].out, &deadline))
    strerr_diefu1sys(111, "write to server") ;
  if (wantexec >= 2)
  {
    int got = 0 ;
    if (write(fdctl, "Y", 1) != 1)
      strerr_diefu1sys(111, "send ucspi-tls start command") ;
    fd_shutdown(fdctl, 1) ;
    for (;;)
    {
      ssize_t r = fd_read(fdctl, io[1].outbuf, OUTSIZE) ;
      if (r < 0) strerr_diefu1sys(111, "read handshake data") ;
      if (!r) break ;
      got = 1 ;
    }
    if (!got) _exit(1) ;  /* handshake failed */
    fd_close(fdctl) ;
    if (fd_move2(0, sslfds[0], 1, sslfds[1]) == -1)
      strerr_diefu1sys(111, "move fds") ;
  }
  {
    char fmtr[UINT_FMT] ;
    char fmtw[UINT_FMT] ;
    char const *newargv[7] = { S6_EXTBINPREFIX "s6-ioconnect", "-r", fmtr, "-w", fmtw, 0, 0 } ;
    fmtr[uint_fmt(fmtr, fdr)] = 0 ;
    fmtw[uint_fmt(fmtw, fdw)] = 0 ;
    if (wantexec == 1) newargv[5] = "-01" ;
    xexec(newargv) ;
  }
}

int main (int argc, char const *const *argv)
{
  int p[2][2] ;
  PROG = "smtpd-starttls-proxy-io (parent)" ;
  {
    subgetopt l = SUBGETOPT_ZERO ;
    for (;;)
    {
      int opt = subgetopt_r(argc, argv, "", &l) ;
      if (opt == -1) break ;
      switch (opt)
      {
        default : dieusage() ;
      }
    }
    argc -= l.ind ; argv += l.ind ;
  }
  if (!argc) dieusage() ;

  {
    unsigned int u ;
    char const *x = getenv("SSLCTLFD") ;
    if (!x) strerr_dienotset(100, "SSLCTLFD") ;
    if (!uint0_scan(x, &u)) strerr_dieinvalid(100, "SSLCTLFD") ;
    fdctl = u ;
    x = getenv("SSLREADFD") ;
    if (!x) strerr_dienotset(100, "SSLREADFD") ;
    if (!uint0_scan(x, &u)) strerr_dieinvalid(100, "SSLREADFD") ;
    sslfds[0] = u ;
    x = getenv("SSLWRITEFD") ;
    if (!x) strerr_dienotset(100, "SSLWRITEFD") ;
    if (!uint0_scan(x, &u)) strerr_dieinvalid(100, "SSLWRITEFD") ;
    sslfds[1] = u ;
  }

  if (pipe(p[0]) == -1 || pipe(p[1]) == -1)
    strerr_diefu1sys(111, "pipe") ;
  switch (fork())
  {
    case -1 : strerr_diefu1sys(111, "fork") ;
    case 0 :
      close(p[0][1]) ;
      close(p[1][0]) ;
      child(p[0][0], p[1][1]) ;
    default : break ;
  }

  close(p[1][1]) ;
  close(p[0][0]) ;
  close(fdctl) ;
  close(sslfds[1]) ;
  close(sslfds[0]) ;
  if (fd_move2(0, p[1][0], 1, p[0][1]) == -1)
    strerr_diefu1sys(111, "move fds") ;
  xexec(argv) ;
}
