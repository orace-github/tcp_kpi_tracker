#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "tcp_kpi_tracker.h"

char LICENSE[] SEC("license") = "GPL";

#define AF_INET    2
#define AF_INET6   10

static __always_inline struct tcp_sock *tcp_sk(const struct sock *sk)
{
	return (struct tcp_sock *)sk;
}

static __always_inline __u32 bictcp_clock_us(const struct sock *sk)
{
	return tcp_sk(sk)->tcp_mstamp;
}

static __always_inline struct inet_connection_sock *inet_csk(const struct sock *sk)
{
	return (struct inet_connection_sock *)sk;
}

static __always_inline void *inet_csk_ca(const struct sock *sk)
{
	return (void *)inet_csk(sk)->icsk_ca_priv;
}

static __always_inline void bictcp_to_event(struct bictcp* ca, struct event* e){
  BPF_CORE_READ_INTO(&e->bictcp.ack_cnt, ca , ack_cnt);
	BPF_CORE_READ_INTO(&e->bictcp.cnt, ca , cnt);
	BPF_CORE_READ_INTO(&e->bictcp.last_cwnd, ca , last_cwnd);
	BPF_CORE_READ_INTO(&e->bictcp.last_time, ca , last_time);
	BPF_CORE_READ_INTO(&e->bictcp.bic_origin_point, ca , bic_origin_point);
	BPF_CORE_READ_INTO(&e->bictcp.bic_K, ca , bic_K);
	BPF_CORE_READ_INTO(&e->bictcp.delay_min, ca , delay_min);
	BPF_CORE_READ_INTO(&e->bictcp.epoch_start, ca , epoch_start);
	BPF_CORE_READ_INTO(&e->bictcp.tcp_cwnd, ca , tcp_cwnd);
	BPF_CORE_READ_INTO(&e->bictcp.sample_cnt, ca , sample_cnt);
	BPF_CORE_READ_INTO(&e->bictcp.round_start, ca , round_start);
	BPF_CORE_READ_INTO(&e->bictcp.end_seq, ca , end_seq);
	BPF_CORE_READ_INTO(&e->bictcp.last_ack, ca , last_ack);
	BPF_CORE_READ_INTO(&e->bictcp.curr_rtt, ca , curr_rtt);
	BPF_CORE_READ_INTO(&e->bictcp.last_max_cwnd, ca , last_max_cwnd);
}


static int fast_compare(const __u8 *ptr0, const __u8 *ptr1, __u16 len){
  int fast = len/sizeof(size_t) + 1;
  int offset = (fast-1)*sizeof(size_t);
  int current_block = 0;

  if(len <= sizeof(size_t)){fast = 0;}


  size_t *lptr0 = (size_t*)ptr0;
  size_t *lptr1 = (size_t*)ptr1;

  while(current_block < fast){
    if((lptr0[current_block] ^ lptr1[current_block])){
      int pos;
      for(pos = current_block*sizeof(size_t); pos < len ; ++pos){
        if((ptr0[pos] ^ ptr1[pos]) || (ptr0[pos] == 0) || (ptr1[pos] == 0)){
          return  (int)((unsigned char)ptr0[pos] - (unsigned char)ptr1[pos]);
          }
        }
      }
    ++current_block;
    }
  while(len > offset){
    if((ptr0[offset] ^ ptr1[offset])){ 
      return (int)((unsigned char)ptr0[offset] - (unsigned char)ptr1[offset]); 
      }
    ++offset;
    }	
  return 0;
  }

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// struct to filter tcp session in kernel
struct session filter;

static __always_inline __s32 __v4_filter_pass(const struct sock* sk){
    __u32 saddr_v4, daddr_v4;
    __u16 sport, dport;
    BPF_CORE_READ_INTO(&saddr_v4, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&daddr_v4, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
    BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);

    if(((filter.addr_v4 == daddr_v4) && (filter.port == dport)) ||
     ((filter.addr_v4 == saddr_v4) && (filter.port == sport)))
      return 1;
    
    return 0;
}

static __always_inline __s32 __v6_filter_pass(const struct sock* sk){
    __u8 saddr_v6[16]; __u8 daddr_v6[16];
    __u16 sport, dport;
    BPF_CORE_READ_INTO(&saddr_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    BPF_CORE_READ_INTO(&daddr_v6, sk,__sk_common.skc_v6_daddr.in6_u.u6_addr32);
    BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
    BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);

      if(((fast_compare(filter.addr_v6,daddr_v6,16)) && (filter.port == dport)) || 
      ((fast_compare(filter.addr_v6,saddr_v6,16)) && (filter.port == sport)))
        return 1;
      
    return 0;
}

static __always_inline __s32 __v4_v6__filter_pass(const struct sock* sk){
  __u16 af;
  BPF_CORE_READ_INTO(&af, sk, __sk_common.skc_family);
  if(af == AF_INET)
    return __v4_filter_pass(sk);
  if(af == AF_INET6)
    return __v6_filter_pass(sk);
  return 0;
}

const volatile unsigned long long min_duration_ns = 0;

SEC("tp_btf/tcp_retransmit_skb")
//SEC("kprobe/tcp_retransmit_skb")
int BPF_PROG(tcp_retransmit_skb, const struct sock *sk, 
  const struct sk_buff *sk_buff){
  // filter tcp session
  if(!__v4_v6__filter_pass(sk))
    return -1;
  struct bictcp* ca = inet_csk_ca(sk);
  struct event *e;
  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e)
    return 0;
  BPF_CORE_READ_INTO(&e->af, sk, __sk_common.skc_family);
  if(e->af == AF_INET){
    BPF_CORE_READ_INTO(&e->saddr_v4, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&e->daddr_v4, sk, __sk_common.skc_daddr);
  }else if(e->af == AF_INET6){
    BPF_CORE_READ_INTO(&e->saddr_v6, sk,
			   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    BPF_CORE_READ_INTO(&e->daddr_v6, sk,
			   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
  }
  BPF_CORE_READ_INTO(&e->dport, sk, __sk_common.skc_dport);
  BPF_CORE_READ_INTO(&e->sport, sk, __sk_common.skc_num);
  BPF_CORE_READ_INTO(&e->state, sk, __sk_common.skc_state);
  BPF_CORE_READ_INTO(&e->portpair, sk, __sk_common.skc_portpair);
  e->type = RETRANSMIT_SKB;
  bictcp_to_event(ca,e);
  /* send data to user-space for post-processing */
  bpf_ringbuf_submit(e, 0);
  return 0;		    
}
/**/
SEC("kretprobe/cubictcp_init")
int BPF_KPROBE(cubictcp_init, struct sock* sk){
  // filter tcp session
  if(!__v4_v6__filter_pass(sk))
    return -1;
  // tracing bictcp_init ???
  if(!filter.init || !filter.allsyms)
    return -1;
  struct bictcp* ca = inet_csk_ca(sk);
  struct event* e;
  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if(!e)
    return -1;
  e->type = BICTCP_INIT;
  bictcp_to_event(ca,e);
  bpf_ringbuf_submit(e,0);
  return 0;
}


SEC("kretprobe/cubictcp_cwnd_event")
int BPF_KPROBE(cubictcp_cwnd_event, struct sock* sk, enum tcp_ca_event event){
  // filter tcp session
  if(!__v4_v6__filter_pass(sk))
    return -1;
  // tracing bictcp_cwnd_event ???
  if(!filter.cwnd_event || !filter.allsyms)
    return -1;
  struct bictcp* ca = inet_csk_ca(sk);
  struct event* e;
  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if(!e)
    return -1;
  e->type = BICTCP_CWND_EVENT;
  bictcp_to_event(ca,e);
  bpf_ringbuf_submit(e,0);
  return 0;
}

SEC("kretprobe/cubictcp_recalc_ssthresh")
int BPF_KPROBE(cubictcp_recalc_ssthresh, struct sock* sk){
  // filter tcp session
  if(!__v4_v6__filter_pass(sk))
    return -1;
  // tracing bictcp_recalc_ssthresh ???
  if(!filter.ssthresh || !filter.allsyms)
    return -1;
  struct bictcp* ca = inet_csk_ca(sk);
  struct event* e;
  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if(!e)
    return -1;
  e->type = BICTCP_SSTHRESH;
  bictcp_to_event(ca,e);
  bpf_ringbuf_submit(e,0);
  return 0;
}

SEC("kretprobe/cubictcp_state")
int BPF_KPROBE(cubictcp_state, struct sock* sk, __u8 new_state){
  // filter tcp session
  if(!__v4_v6__filter_pass(sk))
    return -1;
  // tracing bictcp_state ???
  if(!filter.state || !filter.allsyms)
    return -1;
  struct bictcp* ca = inet_csk_ca(sk);
  struct event* e;
  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if(!e)
    return -1;
  e->type = BICTCP_STATE;
  bictcp_to_event(ca,e);
  bpf_ringbuf_submit(e,0);
  return 0;
}

SEC("kretprobe/cubictcp_acked")
int BPF_KPROBE(cubictcp_acked, struct sock* sk, const struct ack_sample* sample){
  // filter tcp session
  if(!__v4_v6__filter_pass(sk))
    return -1;
  // tracing bictcp_acked ???
  if(!filter.acked || !filter.allsyms)
    return -1;
  struct event *e;
  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if(!e)
    return -1;
  struct bictcp* ca = inet_csk_ca(sk);
  e->type = BICTCP_ACKED;
  bictcp_to_event(ca,e);
  bpf_ringbuf_submit(e,0);
  return 0;
}

SEC("kretprobe/cubictcp_cong_avoid")
int BPF_KPROBE(cubictcp_cong_avoid, struct sock *sk){
  // filter tcp session
  if(!__v4_v6__filter_pass(sk))
    return -1;
  // tracing bictcp_cong_avoid ???
  if(!filter.cong_avoid || !filter.allsyms)
    return -1;
  struct event *e;
  struct tcp_sock *tp = (struct tcp_sock *)(sk);
  struct bictcp* ca = inet_csk_ca(sk);
  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e)
    return 0;
  BPF_CORE_READ_INTO(&e->af, sk, __sk_common.skc_family);
  if(e->af == AF_INET){
    BPF_CORE_READ_INTO(&e->saddr_v4, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&e->daddr_v4, sk, __sk_common.skc_daddr);
  }else if(e->af == AF_INET6){
    BPF_CORE_READ_INTO(&e->saddr_v6, sk,
			   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    BPF_CORE_READ_INTO(&e->daddr_v6, sk,
			   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
  }
  BPF_CORE_READ_INTO(&e->dport, sk, __sk_common.skc_dport);
  BPF_CORE_READ_INTO(&e->snd_wnd, tp, snd_wnd);
  BPF_CORE_READ_INTO(&e->snd_ssthresh, tp, snd_ssthresh);
  BPF_CORE_READ_INTO(&e->rcv_ssthresh, tp, rcv_ssthresh);
  e->type = BICTCP_CONG_AVOID;
  bictcp_to_event(ca,e);
  /* send data to user-space for post-processing */
  bpf_ringbuf_submit(e, 0);
  return 0;		    
}

SEC("kprobe/__tcp_transmit_skb")
int BPF_KPROBE(__tcp_transmit_skb, struct sock *sk){
  // filter tcp session
  if(!__v4_v6__filter_pass(sk))
    return -1;
  struct bictcp* ca = inet_csk_ca(sk);
  struct event *e;
  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e)
    return 0;
  BPF_CORE_READ_INTO(&e->af, sk, __sk_common.skc_family);
  if(e->af == AF_INET){
    BPF_CORE_READ_INTO(&e->saddr_v4, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&e->daddr_v4, sk, __sk_common.skc_daddr);
  }else if(e->af == AF_INET6){
    BPF_CORE_READ_INTO(&e->saddr_v6, sk,
			   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    BPF_CORE_READ_INTO(&e->daddr_v6, sk,
			   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
  }
  e->type = TRANSMIT_SKB;
  bictcp_to_event(ca,e);
  /* send data to user-space for post-processing */
  bpf_ringbuf_submit(e, 0);
  return 0;		    
}

SEC("tp_btf/tcp_receive_reset")
int BPF_PROG(tcp_receive_reset, const struct sock *sk, 
  const struct sk_buff *sk_buff){
    // filter tcp session
  if(!__v4_v6__filter_pass(sk))
    return -1;
  struct bictcp* ca = inet_csk_ca(sk);
  struct event *e;
  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e)
    return 0;
  BPF_CORE_READ_INTO(&e->af, sk, __sk_common.skc_family);
  if(e->af == AF_INET){
    BPF_CORE_READ_INTO(&e->saddr_v4, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&e->daddr_v4, sk, __sk_common.skc_daddr);
  }else if(e->af == AF_INET6){
    BPF_CORE_READ_INTO(&e->saddr_v6, sk,
			   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    BPF_CORE_READ_INTO(&e->daddr_v6, sk,
			   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
  }
  e->type = RECV_RESET;
  bictcp_to_event(ca,e);
  /* send data to user-space for post-processing */
  bpf_ringbuf_submit(e, 0);
  return 0;		    
}


SEC("tp_btf/tcp_send_reset")
int BPF_PROG(tcp_send_reset, const struct sock *sk, 
  const struct sk_buff *sk_buff){
    // filter tcp session
  if(!__v4_v6__filter_pass(sk))
    return -1;
  struct bictcp* ca = inet_csk_ca(sk);
  struct event *e;
  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e)
    return 0;
  BPF_CORE_READ_INTO(&e->af, sk, __sk_common.skc_family);
  if(e->af == AF_INET){
    BPF_CORE_READ_INTO(&e->saddr_v4, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&e->daddr_v4, sk, __sk_common.skc_daddr);
  }else if(e->af == AF_INET6){
    BPF_CORE_READ_INTO(&e->saddr_v6, sk,
			   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    BPF_CORE_READ_INTO(&e->daddr_v6, sk,
			   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
  }
  e->type = SEND_RESET;
  bictcp_to_event(ca,e);
  /* send data to user-space for post-processing */
  bpf_ringbuf_submit(e, 0);
  return 0;		    
}

SEC("tp_btf/tcp_destroy_sock")
int BPF_PROG(tcp_destroy_sock, const struct sock *sk){
  // filter tcp session
  if(!__v4_v6__filter_pass(sk))
    return -1;
  struct bictcp* ca = inet_csk_ca(sk);
  struct event *e;
  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e)
    return 0;
  BPF_CORE_READ_INTO(&e->af, sk, __sk_common.skc_family);
  if(e->af == AF_INET){
    BPF_CORE_READ_INTO(&e->saddr_v4, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&e->daddr_v4, sk, __sk_common.skc_daddr);
  }else if(e->af == AF_INET6){
    BPF_CORE_READ_INTO(&e->saddr_v6, sk,
			   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    BPF_CORE_READ_INTO(&e->daddr_v6, sk,
			   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
  }
  e->type = DESTROY_SOCK;
  bictcp_to_event(ca,e);
  /* send data to user-space for post-processing */
  bpf_ringbuf_submit(e, 0);
  return 0;		    
}

SEC("tp_btf/tcp_retransmit_synack")
int BPF_PROG(tcp_retransmit_synack, const struct sock *sk,  
  const struct request_sock *reqsock){
    // filter tcp session
  if(!__v4_v6__filter_pass(sk))
    return -1;
  struct bictcp* ca = inet_csk_ca(sk);
  struct event *e;
  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e)
    return 0;
  BPF_CORE_READ_INTO(&e->af, sk, __sk_common.skc_family);
  if(e->af == AF_INET){
    BPF_CORE_READ_INTO(&e->saddr_v4, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&e->daddr_v4, sk, __sk_common.skc_daddr);
  }else if(e->af == AF_INET6){
    BPF_CORE_READ_INTO(&e->saddr_v6, sk,
			   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    BPF_CORE_READ_INTO(&e->daddr_v6, sk,
			   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
  }
  e->type = RETRANSMIT_SYNACK;
  bictcp_to_event(ca,e);
  /* send data to user-space for post-processing */
  bpf_ringbuf_submit(e, 0);
  return 0;		    
}

SEC("tracepoint/tcp/tcp_probe")
int tracing_tcp_probe(struct trace_event_raw_tcp_probe *ctx){
  struct event *e;
  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e)
    return 0;
  BPF_CORE_READ_INTO(&e->saddr , ctx, saddr);
  BPF_CORE_READ_INTO(&e->daddr , ctx, daddr);
  e->type = TCP_PROBE;
  e->sport = ctx->sport;
  e->dport = ctx->dport;
  e->snd_una = ctx->snd_una;
  e->data_len = ctx->data_len;
  e->snd_nxt  = ctx->snd_nxt;
  e->snd_cwnd = ctx->snd_cwnd;
  e->ssthresh = ctx->ssthresh;
  e->snd_wnd  = ctx->snd_wnd;
  e->srtt     = ctx->srtt;
  e->rcv_wnd  = ctx->rcv_wnd;
  /* send data to user-space for post-processing */
  e->type = TCP_PROBE;
  bpf_ringbuf_submit(e, 0);
  return 0;		    
}

SEC("tp/sock/inet_sock_set_state")
int tracing_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx){
  struct event *e;
  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e)
    return 0;
  e->af = ctx->family;
  e->sport = ctx->sport;
  e->dport = ctx->dport;
  e->oldstate = ctx->oldstate;
  e->newstate = ctx->newstate;
  e->protocol = ctx->protocol;
  BPF_CORE_READ_INTO(&e->saddr_v4 , ctx, saddr);
  BPF_CORE_READ_INTO(&e->daddr_v4 , ctx, daddr);
  e->type = SOCK_SET_STATE;
  /* send data to user-space for post-processing */
  bpf_ringbuf_submit(e, 0);
  return 0;		    
}
