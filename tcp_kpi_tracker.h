#ifndef __TCP_KPI_TRACKER_H
#define __TCP_KPI_TRACKER_H

#define INET6_ADDRSTRLEN 46
enum {
  TCP_PROBE,
  SOCK_SET_STATE,
  RETRANSMIT_SKB,
  RETRANSMIT_SYNACK,
  TRANSMIT_SKB,
  DESTROY_SOCK,
  SEND_RESET,
  RECV_RESET,
  BICTCP_CONG_AVOID,
  BICTCP_ACKED,
};

struct event {
  unsigned long long duration_ns;
  __u8 saddr[28];
  __u8 daddr[28];
  __u16 sport;
  __u16 dport;
  __u32 mark;
  __u16 data_len;
  __u32 snd_nxt;
  __u32 snd_una;
  __u32 snd_cwnd;
  __u32 ssthresh;
  __u32 snd_ssthresh;
  __u32 rcv_ssthresh;
  __u32 snd_wnd;
  __u32 srtt;
  __u32 rcv_wnd;
  __u64 sock_cookie;
  __u32 portpair;
  int oldstate;
  int newstate;
  int state;
  __u16 af;
  __u16 protocol;
  union {
    __u32 saddr_v4;
    __u8 saddr_v6[16];
  };
  union {
    __u32 daddr_v4;
    __u8 daddr_v6[16];
  };
  int type;
  struct __bictcp {
	__u32 cnt;
	__u32 last_max_cwnd;
	__u32 last_cwnd;
	__u32 last_time;
	__u32 bic_origin_point;
  __u32 bic_K;
	__u32 delay_min;
	__u32 epoch_start;
	__u32 ack_cnt;
	__u32 tcp_cwnd;
	__u16 unused;
	__u8 sample_cnt;
	__u8 found;
	__u32 round_start;
	__u32 end_seq;
	__u32 last_ack;
	__u32 curr_rtt;
  } bictcp;
};

struct kpi_events{
  int not_free;
  unsigned long hash;
  int retrans;
  char src[INET6_ADDRSTRLEN];
  char dst[INET6_ADDRSTRLEN];
};

#endif /* __TCP_KPI_TRACKER_H */
