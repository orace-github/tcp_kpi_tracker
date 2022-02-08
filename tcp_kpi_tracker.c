#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include "tcp_kpi_tracker.h"
#include "tcp_kpi_tracker.skel.h"
#include <string.h>
// bpf code skeleton
struct tcp_kpi_tracker_bpf *skel;
#define BASE 256
#define HASH_SIZE 1024

#define FILTER_PORT(p) skel->bss->filter.port = p
#define FILTER_ADDR_v4(a) skel->bss->filter.addr_v4 = a;
#define FILTER_ADDR_v6(a) memcpy(skel->bss->filter.addr_v6, a, 16);

static struct kpi_events hash_table[HASH_SIZE];

static struct env
{
  bool verbose;
  long min_duration_ms;
  bool bictcp_init;
  bool bictcp_cwnd_event;
  bool bictcp_recalc_ssthresh;
  bool bictcp_state;
  bool bictcp_acked;
  bool bictcp_cong_avoid;
  bool bictcp_cong_algorithms;
  short port;
  short af;
  FILE* log_file;
  union
  {
    bool ipv4;
    bool ipv6;
  };
  union
  {
    struct in_addr x4;
    struct in6_addr x6;
  } addr;
} env;

const char *argp_program_version = "tcp_kpi_tracker 0.0";
const char *argp_program_bug_address = "<assogba.emery@gmail.com>";
const char argp_program_doc[] =
    "BPF tcp_kpi_tracker demo application.\n"
    "\n"
    "It traces TCP events and log them as qlog events \n"
    "USAGE: ./tcp_kpi_tracker [-d <min-duration-ms>] [-v]\n";

static const struct argp_option opts[] = {
    {"verbose", 'v', NULL, 0, "Verbose debug output"},
    {"duration", 'd', "DURATION-MS", 0, "Minimum process duration (ms) to report"},
    {"bictcp_init", 'i', NULL, 0, "Enable tracing for cubic's init function"},
    {"bictcp_cwnd_event", 'c', NULL, 0, "Enable tracing for cubic's cwnd_event function"},
    {"bictcp_recal_ssthresh", 'r', NULL, 0, "Enable tracing for cubic's recal_ssthresh function"},
    {"bictcp_state", 's', NULL, 0, "Enable tracing for cubic's state function"},
    {"bictcp_acked", 'a', NULL, 0, "Enable tracing for cubic's acked function"},
    {"bictcp_cong_avoid", 'o', NULL, 0, "Enable tracing for cubic's cong_avoid function"},
    {"bictcp_cong_algorithms", 'n', NULL, 0, "Tracing all cubic's functions"},
    {"ip", 'p', "AF", 0, "IP protocol, --ip=4 for ipv4 and --ip=6 for ipv6"},
    {"ip4addr", 'x', "IP4-ADDR", 0, "IPv4 address"},
    {"ip6addr", 'y', "IP6-ADDR", 0, "IPv6 address"},
    {"port", 'z', "PORT", 0, "Port"},
    {"log_file", 'f', "LOG-FILE", 0, "Log file path"},
    {},
};

/* treat strings as base-256 integers */
/* with digits in the range 1 to 255 */
static unsigned long hash(const char *s, int size, unsigned long m)
{
  unsigned long h;
  unsigned const char *us;
  us = (unsigned const char *)s;
  h = 0;
  while (*us != '\0')
  {
    h = (h * BASE + *us) % m;
    us++;
  }
  return h;
}

static void display_hash_table(void)
{
  int i;
  for (i = 0; i < HASH_SIZE; i++)
  {
    if (hash_table[i].not_free)
      printf("%ld:%d:%s:%s\n", hash_table[i].hash, hash_table[i].retrans,
             hash_table[i].src, hash_table[i].dst);
  }
}

/** Tips: Make sure to call this function after open skel bpf structure,
 *  otherwise a SIGSEGV signal is triggered.
 * That's because FILTER_XXX macro doesn't make memmory verification
 **/ 
static void parse_filter_args()
{
  if (env.af == 4){
    FILTER_ADDR_v4(env.addr.x4.s_addr);
  }
  if (env.af == 6){
    FILTER_ADDR_v6(&env.addr.x6.__in6_u.__u6_addr8);
  }
  FILTER_PORT(env.port);
  skel->bss->filter.init = (env.bictcp_init == true ? 1 : 0);
  skel->bss->filter.acked = (env.bictcp_acked == true ? 1 : 0);
  skel->bss->filter.state = (env.bictcp_state == true ? 1 : 0);
  skel->bss->filter.ssthresh = (env.bictcp_recalc_ssthresh == true ? 1 : 0);
  // skel->bss->filter.undo_cwnd = TODO
  skel->bss->filter.cwnd_event = (env.bictcp_cwnd_event == true ? 1 : 0);
  skel->bss->filter.cong_avoid = (env.bictcp_cong_avoid == true ? 1 : 0);
  skel->bss->filter.allsyms = (env.bictcp_cong_algorithms == true ? 1 : 0);
}

static void common_handle_event(const struct event *e, unsigned long *hashVal)
{
  char src[INET6_ADDRSTRLEN];
  char dst[INET6_ADDRSTRLEN];
  char eventstr[74];
  int ret;
  union
  {
    struct in_addr x4;
    struct in6_addr x6;
  } s, d;

  if (e->af == AF_INET)
  {
    s.x4.s_addr = e->saddr_v4;
    d.x4.s_addr = e->daddr_v4;
  }
  else
  {
    memcpy(&s.x6.s6_addr, e->saddr_v6, sizeof(s.x6.s6_addr));
    memcpy(&d.x6.s6_addr, e->daddr_v6, sizeof(d.x6.s6_addr));
  }
  ret = sprintf(eventstr, "%d  %s %s %d %d %d %d %d",
                e->af == AF_INET ? 4 : 6, inet_ntop(e->af, &d, dst, sizeof(dst)),
                inet_ntop(e->af, &s, src, sizeof(src)), e->dport,
                e->sport, e->state, e->portpair >> 16, e->portpair & 0xffff);
  eventstr[ret] = '\0';
  *hashVal = hash(eventstr, strlen(eventstr), HASH_SIZE);
  printf("%s\n", eventstr);
  if (hash_table[*hashVal].not_free && (strcmp(src, hash_table[*hashVal].src) ||
                                        strcmp(dst, hash_table[*hashVal].dst)))
    fprintf(stderr, "Collision %ld\n", *hashVal);
  if (!hash_table[*hashVal].hash)
  {
    hash_table[*hashVal].hash = *hashVal;
    strcpy(hash_table[*hashVal].src, src);
    strcpy(hash_table[*hashVal].dst, dst);
    hash_table[*hashVal].not_free = 1;
  }
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
  switch (key)
  {
  case 'v':
    env.verbose = true;
    break;
  case 'd':
    errno = 0;
    env.min_duration_ms = strtol(arg, NULL, 10);
    if (errno || env.min_duration_ms <= 0)
    {
      fprintf(stderr, "Invalid duration: %s\n", arg);
      argp_usage(state);
    }
    break;
  case 'i':
    env.bictcp_init = true;
    break;
  case 'c':
    env.bictcp_cwnd_event = true;
    break;
  case 'r':
    env.bictcp_recalc_ssthresh = true;
    break;
  case 's':
    env.bictcp_state = true;
    break;
  case 'a':
    env.bictcp_acked = true;
    break;
  case 'o':
    env.bictcp_cong_avoid = true;
    break;
  case 'n':
    env.bictcp_cong_algorithms = true;
    break;
  case 'p':
    env.af = strtol(arg, NULL, 10);
    if (env.af == 4)
      env.ipv4 = true;
    else if (env.af == 6)
      env.ipv6 = true;
    else
    {
      fprintf(stderr, "Invalid Internet Protocol: %s\n", arg);
      argp_usage(state);
    }
    break;
  case 'x':
    inet_pton(AF_INET, arg, &env.addr.x4);
    break;
  case 'y':
    inet_pton(AF_INET6, arg, &env.addr.x6);
    break;
  case 'z':
    env.port = strtol(arg, NULL, 10);
    errno = 0;
    if (errno || env.port <= 0)
    {
      fprintf(stderr, "Invalid port:%s\n", arg);
      argp_usage(state);
    }
    break;
  case 'f':
    env.log_file = fopen(arg,"w");
    break;
  case ARGP_KEY_ARG:
    argp_usage(state);
    break;
  default:
    return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
  if (level == LIBBPF_DEBUG && !env.verbose)
    return 0;
  return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void)
{
  struct rlimit rlim_new = {
      .rlim_cur = RLIM_INFINITY,
      .rlim_max = RLIM_INFINITY,
  };
  if (setrlimit(RLIMIT_MEMLOCK, &rlim_new))
  {
    fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
    exit(1);
  }
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
  exiting = true;
  display_hash_table();
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
  const struct event *e = (struct event *)data;
  struct tm *tm;
  char ts[32];
  time_t t;
  time(&t);
  tm = localtime(&t);
  unsigned long hashVal;
  strftime(ts, sizeof(ts), "%H:%M:%S", tm);
  switch (e->type)
  {
    case RETRANSMIT_SKB:
      fprintf(stderr, "RETRANSMIT_SKB\n");
      common_handle_event(e, &hashVal);
      hash_table[hashVal].retrans++;
      break;    
    case BICTCP_CONG_AVOID:
    fprintf(stderr, "BICTCP_CONG_AVOID\n");
    common_handle_event(e, &hashVal);
    fprintf(stdout,"%s:%d %s:%d %s:%d\n",
    "tcp_cwnd",e->bictcp.tcp_cwnd,"last_cwnd",e->bictcp.last_cwnd,"last_max_cwnd",e->bictcp.last_max_cwnd);
    if(env.log_file){
      fprintf(env.log_file,"%d %d %d\n",e->bictcp.tcp_cwnd,e->bictcp.last_cwnd,e->bictcp.last_max_cwnd);
    }
    break;
    case BICTCP_ACKED:
    fprintf(stderr, "BICTCP_ACKED\n");
    common_handle_event(e, &hashVal);
    fprintf(stdout,"%s:%d %s:%d %s:%d\n",
    "tcp_cwnd",e->bictcp.tcp_cwnd,"last_cwnd",e->bictcp.last_cwnd,"last_max_cwnd",e->bictcp.last_max_cwnd);
    if(env.log_file){
      fprintf(env.log_file,"%d %d %d\n",e->bictcp.tcp_cwnd,e->bictcp.last_cwnd,e->bictcp.last_max_cwnd);
    }
    break;
    case BICTCP_CWND_EVENT:
    fprintf(stderr, "BICTCP_CWND_EVENT\n");
    common_handle_event(e, &hashVal);
    fprintf(stdout,"%s:%d %s:%d %s:%d\n",
    "tcp_cwnd",e->bictcp.tcp_cwnd,"last_cwnd",e->bictcp.last_cwnd,"last_max_cwnd",e->bictcp.last_max_cwnd);
    if(env.log_file){
      fprintf(env.log_file,"%d %d %d\n",e->bictcp.tcp_cwnd,e->bictcp.last_cwnd,e->bictcp.last_max_cwnd);
    }
    break;
    case BICTCP_INIT:
    fprintf(stderr, "BICTCP_INIT\n");
    common_handle_event(e, &hashVal);
    fprintf(stdout,"%s:%d %s:%d %s:%d\n",
    "tcp_cwnd",e->bictcp.tcp_cwnd,"last_cwnd",e->bictcp.last_cwnd,"last_max_cwnd",e->bictcp.last_max_cwnd);
    if(env.log_file){
      fprintf(env.log_file,"%d %d %d\n",e->bictcp.tcp_cwnd,e->bictcp.last_cwnd,e->bictcp.last_max_cwnd);
    }
    break;
    case BICTCP_SSTHRESH:
    fprintf(stderr, "BICTCP_SSTHRESH\n");
    common_handle_event(e, &hashVal);
    fprintf(stdout,"%s:%d %s:%d %s:%d\n",
    "tcp_cwnd",e->bictcp.tcp_cwnd,"last_cwnd",e->bictcp.last_cwnd,"last_max_cwnd",e->bictcp.last_max_cwnd);
    if(env.log_file){
      fprintf(env.log_file,"%d %d %d\n",e->bictcp.tcp_cwnd,e->bictcp.last_cwnd,e->bictcp.last_max_cwnd);
    }
    break;
    case BICTCP_STATE:
    fprintf(stderr, "BICTCP_STATE\n");
    common_handle_event(e, &hashVal);
    fprintf(stdout,"%s:%d %s:%d %s:%d\n",
    "tcp_cwnd",e->bictcp.tcp_cwnd,"last_cwnd",e->bictcp.last_cwnd,"last_max_cwnd",e->bictcp.last_max_cwnd);
    if(env.log_file){
      fprintf(env.log_file,"%d %d %d\n",e->bictcp.tcp_cwnd,e->bictcp.last_cwnd,e->bictcp.last_max_cwnd);
    }
    break;
    case BICTCP_UNDO_CWND:
    fprintf(stderr, "BICTCP_UNDO_CWND\n");
    common_handle_event(e, &hashVal);
    fprintf(stdout,"%s:%d %s:%d %s:%d\n",
    "tcp_cwnd",e->bictcp.tcp_cwnd,"last_cwnd",e->bictcp.last_cwnd,"last_max_cwnd",e->bictcp.last_max_cwnd);
    if(env.log_file){
      fprintf(env.log_file,"%d %d %d\n",e->bictcp.tcp_cwnd,e->bictcp.last_cwnd,e->bictcp.last_max_cwnd);
    }
    break;
    case TRANSMIT_SKB:
      fprintf(stderr, "TRANSMIT_SKB\n");
      common_handle_event(e, &hashVal);
      break;
    /*case RECV_RESET:
      fprintf(stderr, "RECV_RESET\n");
      common_handle_event(e, &hashVal);
      break;
    case SEND_RESET:
      fprintf(stderr, "SEND_RESET\n");
      common_handle_event(e, &hashVal);
      break;
    case DESTROY_SOCK:
      fprintf(stderr, "DESTROY_SOCK\n");
      common_handle_event(e, &hashVal);
      break;
    case RETRANSMIT_SYNACK:
      fprintf(stderr, "RETRANSMIT_SYNACK\n");
      common_handle_event(e, &hashVal);
      break;
    case TCP_PROBE:
      fprintf(stderr, "TCP_PROBE\n");
      common_handle_event(e, &hashVal);
      break;
    case SOCK_SET_STATE:
      fprintf(stderr, "SOCK_SET_STATE\n");
      common_handle_event(e, &hashVal);
      break;*/
  default:
    break;
    //fprintf(stderr, "UNKNOWN EVENT (%d)\n", e->type);
  }
  return 0;
}

int main(int argc, char **argv)
{
  struct ring_buffer *rb = NULL;
  int err;
  /* Parse command line arguments */
  err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
  if (err)
    return err;
  /* Set up libbpf errors and debug info callback */
  libbpf_set_print(libbpf_print_fn);
  /* Bump RLIMIT_MEMLOCK to create BPF maps */
  bump_memlock_rlimit();
  /* Cleaner handling of Ctrl-C */
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);
  /* Load and verify BPF application */
  skel = tcp_kpi_tracker_bpf__open();
  if (!skel)
  {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;
  }
  /* Parameterize BPF code with minimum duration parameter */
  skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;
  /* Parsing filter arguments */
  parse_filter_args();
  /* Load & verify BPF programs */
  err = tcp_kpi_tracker_bpf__load(skel);
  if (err)
  {
    fprintf(stderr, "Failed to load and verify BPF skeleton\n");
    goto cleanup;
  }

  /* Attach tracepoints */
  err = tcp_kpi_tracker_bpf__attach(skel);
  if (err)
  {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }
  /* Set up ring buffer polling */
  rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
  if (!rb)
  {
    err = -1;
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
  }
  memset(hash_table, 0, sizeof(struct kpi_events) * HASH_SIZE);
  /* Process events */
  printf("%-2s %-16s %-16s %-4s %-10s %-10s %-3s %-3s\n",
         "AF", "DADDR", "SADDR", "PROTOCOL", "DPORT", "SPORT", "OLDSTATE", "NEWSTATE");
  while (!exiting)
  {
    err = ring_buffer__poll(rb, 100 /* timeout, ms */);
    /* Ctrl-C will cause -EINTR */
    if (err == -EINTR)
    {
      err = 0;
      break;
    }
    if (err < 0)
    {
      printf("Error polling perf buffer: %d\n", err);
      break;
    }
  }
cleanup:
  /* Clean up */
  ring_buffer__free(rb);
  tcp_kpi_tracker_bpf__destroy(skel);
  if(env.log_file)
    fclose(env.log_file);
  return err < 0 ? -err : 0;
}
