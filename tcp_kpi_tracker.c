#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include "tcp_kpi_tracker.h"
#include "tcp_kpi_tracker.skel.h"

#define BASE 256

#define HASH_SIZE  1024


static struct kpi_events hash_table[HASH_SIZE];

static struct env {
  bool verbose;
  long min_duration_ms;
} env;

const char *argp_program_version = "tcp_kpi_tracker 0.0";
const char *argp_program_bug_address = "<assogba.emery@gmail.com>";
const char argp_program_doc[] =
"BPF tcp_kpi_tracker demo application.\n"
"\n"
"It traces TCP events and log them as qlog events \n"
"USAGE: ./tcp_kpi_tracker [-d <min-duration-ms>] [-v]\n";

static const struct argp_option opts[] = {
  { "verbose", 'v', NULL, 0, "Verbose debug output" },
  { "duration", 'd', "DURATION-MS", 0, "Minimum process duration (ms) to report" },
  {},
};

/* treat strings as base-256 integers */
/* with digits in the range 1 to 255 */
static unsigned long hash(const char *s, int size, unsigned long m){
  unsigned long h;
  unsigned const char *us;
  us = (unsigned const char *) s;
  h = 0;
  while(*us != '\0') {
    h = (h * BASE + *us) % m;
    us++;
  }
  return h;
}


static void display_hash_table(void){
  int i;
  for(i = 0; i < HASH_SIZE; i ++){
     if(hash_table[i].not_free)
       printf("%ld:%d:%s:%s\n", hash_table[i].hash, hash_table[i].retrans,
         hash_table[i].src, hash_table[i].dst);
  }
}

static void common_handle_event(const struct event *e, unsigned long *hashVal){
  char src[INET6_ADDRSTRLEN];
  char dst[INET6_ADDRSTRLEN];
  char eventstr[74];
  int ret;
  union {
    struct in_addr  x4;
    struct in6_addr x6;
  } s, d;
  if (e->af == AF_INET) {
    s.x4.s_addr = e->saddr_v4;
    d.x4.s_addr = e->daddr_v4;
  } else {
    memcpy(&s.x6.s6_addr, e->saddr_v6, sizeof(s.x6.s6_addr));
    memcpy(&d.x6.s6_addr, e->daddr_v6, sizeof(d.x6.s6_addr));
  } 
  ret = sprintf(eventstr,"%d  %s %s %d %d %d", 
    e->af == AF_INET ? 4 : 6, inet_ntop(e->af, &d, dst, sizeof(dst)), 
       inet_ntop(e->af, &s, src, sizeof(src)), e->dport,  
       e->sport, e->state);
  eventstr[ret] = '\0';
  *hashVal = hash(eventstr, strlen(eventstr), HASH_SIZE);
  printf("%s\n", eventstr);
  if(hash_table[*hashVal].not_free && (strcmp(src, hash_table[*hashVal].src) || 
    strcmp(dst, hash_table[*hashVal].dst)))
    fprintf(stderr, "Collision %ld\n", *hashVal);
  if(!hash_table[*hashVal].hash){
    hash_table[*hashVal].hash = *hashVal;
    strcpy(hash_table[*hashVal].src, src);
    strcpy(hash_table[*hashVal].dst, dst);
    hash_table[*hashVal].not_free = 1;
  }
}

static error_t parse_arg(int key, char *arg, struct argp_state *state){
  switch (key) {
    case 'v':
      env.verbose = true;
      break;
    case 'd':
      errno = 0;
      env.min_duration_ms = strtol(arg, NULL, 10);
      if (errno || env.min_duration_ms <= 0) {
        fprintf(stderr, "Invalid duration: %s\n", arg);
        argp_usage(state);
      }
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

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args){
  if (level == LIBBPF_DEBUG && !env.verbose)
    return 0;
  return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void){
  struct rlimit rlim_new = {
    .rlim_cur	= RLIM_INFINITY,
    .rlim_max	= RLIM_INFINITY,
  };
  if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
    fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
    exit(1);
  }
}

static volatile bool exiting = false;

static void sig_handler(int sig){
  exiting = true;
  display_hash_table();
}

static int handle_event(void *ctx, void *data, size_t data_sz){
  const struct event *e = (struct event *)data;
  struct tm *tm;
  char ts[32];
  time_t t;
  time(&t);
  tm = localtime(&t);
  unsigned long hashVal;
  strftime(ts, sizeof(ts), "%H:%M:%S", tm);   
  switch(e->type){
    case RETRANSMIT_SKB:
      fprintf(stderr, "RETRANSMIT_SKB\n");
      common_handle_event(e, &hashVal);
      hash_table[hashVal].retrans++;
      break;
    /*case BICTCP_CONG_AVOID:
      fprintf(stderr, "BICTCP_CONG_AVOID\n");
      common_handle_event(e, &hashVal);
      break;
    case TRANSMIT_SKB:
      fprintf(stderr, "TRANSMIT_SKB\n");
      common_handle_event(e, &hashVal);
      break;
    case RECV_RESET:
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

int main(int argc, char **argv){
  struct ring_buffer *rb = NULL;
  struct tcp_kpi_tracker_bpf *skel;
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
  if (!skel) {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;
  }
  /* Parameterize BPF code with minimum duration parameter */
  skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;
  /* Load & verify BPF programs */
  err = tcp_kpi_tracker_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load and verify BPF skeleton\n");
    goto cleanup;
  }

  /* Attach tracepoints */
  err = tcp_kpi_tracker_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }
  /* Set up ring buffer polling */
  rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
  if (!rb) {
    err = -1;
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
  }
  memset(hash_table, 0, sizeof(struct kpi_events)*HASH_SIZE);
  /* Process events */
  printf("%-2s %-16s %-16s %-4s %-10s %-10s %-3s %-3s\n",
	       "AF", "DADDR", "SADDR", "PROTOCOL" ,"DPORT", "SPORT", "OLDSTATE", "NEWSTATE");
  while (!exiting) {
    err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
    if (err == -EINTR) {
      err = 0;
      break;
    }
    if (err < 0) {
        printf("Error polling perf buffer: %d\n", err);
        break;
    }
  }
cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	tcp_kpi_tracker_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
