/* ISC license. */

#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>

#include <skalibs/posixplz.h>
#include <skalibs/types.h>
#include <skalibs/bytestr.h>
#include <skalibs/sgetopt.h>
#include <skalibs/allreadwrite.h>
#include <skalibs/buffer.h>
#include <skalibs/alloc.h>
#include <skalibs/bufalloc.h>
#include <skalibs/error.h>
#include <skalibs/strerr2.h>
#include <skalibs/sig.h>
#include <skalibs/selfpipe.h>
#include <skalibs/tai.h>
#include <skalibs/djbunix.h>
#include <skalibs/iopause.h>
#include <skalibs/skamisc.h>
#include <skalibs/exec.h>
#include <skalibs/unix-timed.h>

#include <s6/config.h>

#define USAGE "smtpd-starttls-proxy-io [ -- ] prog..."
#define dieusage() strerr_dieusage(100, USAGE)
#define dienomem() strerr_diefu1sys(111, "alloc")

#define reset_timeout() tain_addsec_g(&deadline, 300000)

static int fd_control ;
static int sslfds[2] ;
static int wantexec = 0 ;

typedef struct io_s io_t, *io_t_ref ;
struct io_s {
  buffer in ;
  bufalloc out ;
  stralloc indata ;
  char buf[BUFFER_INSIZE] ;
} ;

static io_t io[2] =
{
  { .in = BUFFER_INIT(&buffer_read, 0, io[0].buf, BUFFER_INSIZE), .out = BUFALLOC_INIT(&fd_write, 1), .indata = STRALLOC_ZERO, .buf = "" },
  { .in = BUFFER_ZERO, .out = BUFALLOC_ZERO, .indata = STRALLOC_ZERO, .buf = "" }
} ;


 /* Server answer processing */

typedef int cbfunc (char const *) ;
typedef cbfunc *cbfunc_ref ;

typedef struct cbnode_s cbnode, *cbnode_ref ;
struct cbnode_s
{
  cbnode *prev ;
  cbnode *next ;
  cbfunc_ref f ;
} ;

static cbnode cbsentinel = { .prev = &cbsentinel, .next = &cbsentinel, .f = 0 } ;

static void cbfunc_enqueue (cbfunc_ref f)
{
  cbnode *node = alloc(sizeof(cbnode)) ;
  if (!node) dienomem() ;
  node->f = f ;
  node->next = &cbsentinel ;
  node->prev = cbsentinel.prev ;
  cbsentinel.prev->next = node ;
  cbsentinel.prev = node ;
}

static inline void cbfunc_pop (void)
{
  cbnode *node = cbsentinel.next ;
  if (node == &cbsentinel) strerr_dief1x(101, "can't happen: popping an empty queue!") ;
  node->next->prev = node->prev ;
  cbsentinel.next = node->next ;
  alloc_free(node) ;
}

static inline void answer_enqueue (char const *s)
{
  if (!bufalloc_puts(&io[0].out, s)) dienomem() ;
}

static int answer_forward (char const *s)
{
  answer_enqueue(s) ;
  return 1 ;
}

static int answer_ehlo (char const *s)
{
  static int needed = 1 ;
  if (needed && s[0] == '2' && case_starts(s+4, "starttls"))
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
  if ((*cbsentinel.next->f)(s)) cbfunc_pop() ;
}

 /* Client command processing */

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
  if (!bufalloc_puts(&io[1].out, s)) dienomem() ;
  cbfunc_enqueue(f) ;
  return 0 ;
}

static int do_noop (char const *s)
{
  (void)s ;
  answer_enqueue("250 OK\r\n") ;
  return 0 ;
}

static int command_forward (char const *s)
{
  return command_enqueue(s, &answer_forward) ;
}

static int do_rcpt (char const *s)
{
  (void)s ;
  answer_enqueue("503 MAIL first (#5.5.1)\r\n") ;
  return 0 ;
}

static int do_ehlo (char const *s)
{
  return command_enqueue(s, &answer_ehlo) ;
}

static int do_notls (char const *s)
{
  if (!bufalloc_puts(&io[1].out, s)) dienomem() ;
  fd_close(fd_control) ;
  fd_close(sslfds[1]) ;
  fd_close(sslfds[0]) ;
  wantexec = 1 ;
  return 1 ;
}

static int do_starttls (char const *s)
{
  if (buffer_len(&io[0].in))
    answer_enqueue("503 STARTTLS must be the last command in a group\r\n") ;
  else
  {
    command_enqueue("RSET\r\n", &trigger_starttls) ;
    wantexec = 2 ;
  }
  return 0 ;
}

static cmdmap const commands[] =
{
  { .name = "noop", .f = &do_noop },
  { .name = "help", .f = &command_forward },
  { .name = "vrfy", .f = &command_forward },
  { .name = "expn", .f = &command_forward },
  { .name = "quit", .f = &command_forward },
  { .name = "rcpt", .f = &do_rcpt },
  { .name = "ehlo", .f = &do_ehlo },
  { .name = "helo", .f = &do_notls },
  { .name = "mail", .f = &do_notls },
  { .name = "starttls", .f = &do_starttls },
  { .name = 0, .f = 0 }
} ;

static int process_client_line (char const *s)
{
  cmdmap const *cmd = commands ;
  for (cmdmap const *cmd = commands ; cmd->name ; cmd++)
    if (case_starts(s, cmd->name)) break ;
  if (cmd->name)
  {
    size_t len = strlen(cmd->name) ;
    if (s[len] == ' ' || s[len] == '\r' || s[len] == '\n')
      return (*cmd->f)(s) ;
  }
  answer_enqueue("502 unimplemented (#5.5.1)\r\n") ;
  return 0 ;
}


 /* Engine */

static void handle_signals (void)
{
  for (;;) switch (selfpipe_read())
  {
    case -1 : strerr_diefu1sys(111, "selfpipe_read()") ;
    case 0 : return ;
    case SIGCHLD : wait_reap() ; break ;
    default : break ;
  }
}

int main (int argc, char const *const *argv)
{
  iopause_fd x[5] =
  {
    { .events = IOPAUSE_READ },
    { .fd = 0 },
    { .fd = 1 },
    { .events = IOPAUSE_READ }
  } ;
  tain_t deadline ;
  PROG = "smtpd-starttls-proxy-io" ;
  {
    subgetopt_t l = SUBGETOPT_ZERO ;
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
    fd_control = u ;
    x = getenv("SSLREADFD") ;
    if (!x) strerr_dienotset(100, "SSLREADFD") ;
    if (!uint0_scan(x, &u)) strerr_dieinvalid(100, "SSLREADFD") ;
    sslfds[0] = u ;
    x = getenv("SSLWRITEFD") ;
    if (!x) strerr_dienotset(100, "SSLWRITEFD") ;
    if (!uint0_scan(x, &u)) strerr_dieinvalid(100, "SSLWRITEFD") ;
    sslfds[1] = u ;
  }

  if (ndelay_on(0) < 0 || ndelay_on(1) < 0)
    strerr_diefu1sys(111, "make stdin/stdout non-blocking") ;
  x[0].fd = selfpipe_init() ;
  if (x[0].fd < 0) strerr_diefu1sys(111, "selfpipe_init") ;
  if (sig_ignore(SIGPIPE) < 0) strerr_diefu1sys(111, "ignore SIGPIPE") ;
  {
    sigset_t set ;
    sigemptyset(&set) ;
    sigaddset(&set, SIGCHLD) ;
    if (selfpipe_trapset(&set) < 0) strerr_diefu1sys(111, "trap signals") ;
  }
  {
    int fd[2] = { 0, 1 } ;
    if (!child_spawn2(argv[0], argv, (char const *const *)environ, fd))
      strerr_diefu2sys(111, "spawn ", argv[0]) ;
    if (ndelay_on(fd[0]) == -1 || ndelay_on(fd[1]) == -1)
      strerr_diefu1sys(111, "make server fds non-blocking") ;
    buffer_init(&io[1].in, &buffer_read, fd[0], io[1].buf, BUFFER_INSIZE) ;
    bufalloc_init(&io[1].out, &fd_write, fd[1]) ;
    x[3].fd = fd[0] ; x[4].fd = fd[1] ;
  }

  tain_now_set_stopwatch_g() ;
  reset_timeout() ;

  cbfunc_enqueue(&answer_forward) ;

  for (;;)
  {
    int r ;
    if (!bufalloc_len(&io[0].out) && (x[3].fd == -1 || (cbsentinel.next == &cbsentinel && wantexec))) break ;
    x[1].events = wantexec ? 0 : IOPAUSE_READ ;
    x[2].events = bufalloc_len(&io[0].out) ? IOPAUSE_WRITE : 0 ;
    x[4].events = bufalloc_len(&io[1].out) ? IOPAUSE_WRITE : 0 ;
    r = iopause_g(x, 5, &deadline) ;
    if (r == -1) strerr_diefu1sys(111, "iopause") ;
    if (!r) strerr_dief1x(99, "timed out") ;
    for (size_t i = 0 ; i < 5 ; i++) if (x[0].revents & IOPAUSE_EXCEPT) x[0].revents |= IOPAUSE_READ | IOPAUSE_WRITE ;

    if (x[0].revents & IOPAUSE_READ) handle_signals() ;

    if (x[2].events & x[2].revents & IOPAUSE_WRITE)
    {
      reset_timeout() ;
      if (!bufalloc_flush(&io[0].out) && !error_isagain(errno))
        strerr_diefu1sys(111, "write to client") ;
    }

    if (x[4].events & x[4].revents & IOPAUSE_WRITE)
    {
      reset_timeout() ;
      if (!bufalloc_flush(&io[1].out) && !error_isagain(errno))
        strerr_diefu1sys(111, "write to server") ;
    }

    if (x[3].revents & IOPAUSE_READ)
    {
      reset_timeout() ;
      for (;;)
      {
        int r = skagetln(&io[1].in, &io[1].indata, '\n') ;
        if (r < 0)
        {
          if (error_isagain(errno)) break ;
          else strerr_diefu1sys(111, "read line from server") ;
        }
        if (!r)
        {
          x[4].fd = -1 ;
          x[3].fd = -1 ;
          wantexec = 0 ;
          break ;
        }
        if (!stralloc_0(&io[1].indata)) dienomem() ;
        process_server_line(io[1].indata.s) ;
        io[1].indata.len = 0 ;
      }
    }

    if (x[1].revents & IOPAUSE_READ)
    {
      reset_timeout() ;
      for (;;)
      {
        int r = skagetln(&io[0].in, &io[0].indata, '\n') ;
        if (r < 0)
        {
          if (error_isagain(errno)) break ;
          else strerr_diefu1sys(111, "read line from client") ;
        }
        if (!r) return 0 ;
        if (!stralloc_0(&io[0].indata)) dienomem() ;
        if (process_client_line(io[0].indata.s)) break ;
        io[0].indata.len = 0 ;
      }
    }
  }

  if (!wantexec) return 0 ;
  if (wantexec >= 2)
  {
    int got = 0 ;
    if (fd_write(fd_control, "Y", 1) < 0)
      strerr_diefu1sys(111, "send ucspi-tls start command") ;
    fd_shutdown(fd_control, 1) ;
    for (;;)
    {
      ssize_t r = fd_read(fd_control, io[1].buf, BUFFER_INSIZE) ;
      if (r < 0) strerr_diefu1sys(111, "read handshake data") ;
      if (!r) break ;
      got = 1 ;
    }
    if (!got) return 1 ;  /* handshake failed */
    fd_close(fd_control) ;
    if (fd_move2(0, sslfds[0], 1, sslfds[1]) == -1)
      strerr_diefu1sys(111, "move fds") ;
  }
  else if (io[0].indata.len)
  {
    if (!bufalloc_puts(&io[1].out, io[0].indata.s)) dienomem() ;
    io[0].indata.len = 0 ;
    if (!bufalloc_timed_flush_g(&io[1].out, &deadline)) strerr_dief1x(99, "timed out") ;
  }
  {
    char fmtr[UINT_FMT] ;
    char fmtw[UINT_FMT] ;
    char const *newargv[7] = { S6_EXTBINPREFIX "s6-ioconnect", "-r", fmtr, "-w", fmtw, 0, 0 } ;
    fmtr[uint_fmt(fmtr, x[3].fd)] = 0 ;
    fmtw[uint_fmt(fmtw, x[4].fd)] = 0 ;
    if (wantexec == 1) newargv[5] = "-01" ;
    xexec(newargv) ;
  }
}
