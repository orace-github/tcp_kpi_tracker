#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "tcp_kpi_tracker.h"

char LICENSE[] SEC("license") = "GPL";

#define AF_INET    2
#define AF_INET6   10


struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile unsigned long long min_duration_ns = 0;


//SEC("tp_btf/tcp_retransmit_skb")
SEC("kprobe/tcp_retransmit_skb")
int BPF_PROG(tcp_retransmit_skb, const struct sock *sk, 
  const struct sk_buff *sk_buff){
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
  e->type = RETRANSMIT_SKB;
  /* send data to user-space for post-processing */
  bpf_ringbuf_submit(e, 0);
  return 0;		    
}

SEC("kretprobe/bictcp_cong_avoid")
int BPF_KPROBE(bictcp_cong_avoid, struct sock *sk){
  struct event *e;
  struct tcp_sock *tp = (struct tcp_sock *)(sk);
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
  
  /* send data to user-space for post-processing */
  bpf_ringbuf_submit(e, 0);
  return 0;		    
}

SEC("kprobe/__tcp_transmit_skb")
int BPF_KPROBE(__tcp_transmit_skb, struct sock *sk){
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
  /* send data to user-space for post-processing */
  bpf_ringbuf_submit(e, 0);
  return 0;		    
}

SEC("tp_btf/tcp_receive_reset")
int BPF_PROG(tcp_receive_reset, const struct sock *sk, 
  const struct sk_buff *sk_buff){
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
  /* send data to user-space for post-processing */
  bpf_ringbuf_submit(e, 0);
  return 0;		    
}


SEC("tp_btf/tcp_send_reset")
int BPF_PROG(tcp_send_reset, const struct sock *sk, 
  const struct sk_buff *sk_buff){
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
  /* send data to user-space for post-processing */
  bpf_ringbuf_submit(e, 0);
  return 0;		    
}

SEC("tp_btf/tcp_destroy_sock")
int BPF_PROG(tcp_destroy_sock, const struct sock *sk){
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
  /* send data to user-space for post-processing */
  bpf_ringbuf_submit(e, 0);
  return 0;		    
}

SEC("tp_btf/tcp_retransmit_synack")
int BPF_PROG(tcp_retransmit_synack, const struct sock *sk, 
  const struct request_sock *reqsock){
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
