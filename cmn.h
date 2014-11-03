/*
The MIT License (MIT)

Copyright (c) 2014 Gopakumar Choorakkot Edakkunni

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in allcopies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#ifndef __CMN_H__
#define __CMN_H__

#include <sys/types.h> 
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <time.h>

#define VLOG(...)               {                           \
    fprintf(stderr, __VA_ARGS__);                           \
    fflush(stderr);                                         \
}

#define SLOG(socket, msg, ...)  {                           \
    VLOG("[%d]:" msg, socket->sport, ##__VA_ARGS__);        \
}

#define TH_FIN                  0x01
#define TH_SYN                  0x02
#define TH_RST                  0x04
#define TH_PUSH                 0x08
#define TH_ACK                  0x10
#define TH_URG                  0x20

#define TH_WINDOW_MAX           (~0)
#define TH_SYN_RESEND           2 // 2 seconds
#define TH_SYN_MAX_RETRY        1000
#define TH_FIN_MAX_RETRY        1000

typedef enum {
    TCP_STATE_CLOSED = 0,        
    TCP_STATE_LISTEN,         
    TCP_STATE_SYN_RCVD,       
    TCP_STATE_SYN_SENT,       
    TCP_STATE_ESTABLISHED,    
    TCP_STATE_FIN_WAIT1,      
    TCP_STATE_FIN_WAIT2,      
    TCP_STATE_CLOSE_WAIT,     
    TCP_STATE_TIME_WAIT,
    TCP_STATE_CLOSING,        
    TCP_STATE_LAST_ACK,
} tcp_states;

/*
 * Window scale max allowed value is 14, rfc1323 section 2.3
 */
#define TH_OPT_WSCALE           3
#define TH_OPT_WSCALE_LEN       3
#define TH_OPT_WSCALE_MAX       14

#define CLIENT_RUN_TIME         10 // Client exits after 10 seconds
#define MSG_RETRY_COUNT         10
#define MAX_PKT_SIZE            1500
#define SEND_PKT_SIZE           1300
#define SERVICE_PORT_DFLT       21234
#define SERVICE_PORT            service_port
#define PORT_INCR_MAX           500
#define ONE_SECOND              1000000000
#define GRE_HDR_SIZE            4
#define ETH_ALEN                6
#define GRE_HDR                 0x00000800
#define GRE_CLIENT_IP           "10.10.10.2"
#define GRE_SERVER_IP           "10.10.10.1"
#define DEFAULT_PPS             2000
#define MAX_STATS               5
#define MAX_WINDOW              2000
#define IP_ENCAP_SIZE           (sizeof(struct ether_header) + \
                                 sizeof(struct ip))
#define TCP_ENCAP_SIZE          (sizeof(struct ether_header) + \
                                 sizeof(struct ip) + sizeof(struct tcphdr))
#define UDP_ENCAP_SIZE          (sizeof(struct ether_header) + \
                                 sizeof(struct ip) + sizeof(struct udphdr))
#define GRE_ENCAP_SIZE          (sizeof(struct ether_header) + \
                                 sizeof(struct ip) + GRE_HDR_SIZE + \
                                 sizeof(struct ip) + sizeof(struct udphdr))

typedef struct {
    int32_t                 cur_window;
} __attribute__((__packed__)) bw_pkt;

typedef struct {
    uint16_t                cnt;
    int32_t                 index;
    uint32_t                recieved_packets[MAX_STATS];
    uint64_t                recieved_bytes[MAX_STATS];
} __attribute__((__packed__)) bw_stats;

typedef struct {
    uint8_t                 kind;
    uint8_t                 len;
    uint8_t                 shift;
    uint8_t                 pad[0];
} __attribute__((__packed__)) tcp_wscale;

typedef struct {
    uint32_t                saddr;
    uint32_t                daddr;
    uint32_t                my_seq;
    uint32_t                rem_seq;     
    int                     tcp_state;
    int                     syn_retries;
    int                     fin_retries;
    uint64_t                last_synsent;
    uint64_t                last_finsent;
    uint8_t                 inited;        
    uint16_t                dport;
    uint16_t                sport;
    pthread_mutex_t         mutex;
} tcp_socket;
    
extern uint16_t service_port;

uint16_t
ip_cksum(const void *addr, int len, uint16_t start);
uint16_t 
tcp_cksum(uint32_t saddr, uint32_t daddr, int len, struct tcphdr *tcp);
int
sock_tcp_control_send(tcp_socket *socket, int which, int ack);
int
sock_tcp_syn_encap(uint8_t *buf,
                   tcp_socket *sock,
                   uint8_t ack);
int
sock_tcp_fin_encap(uint8_t *buf,
                   tcp_socket *sock,
                   uint8_t ack);
int
sock_tcp_ack_encap(uint8_t *buf,
                   tcp_socket *sock);
int
sock_tcp_rst_encap(uint8_t *buf,
                   tcp_socket *sock);
int
sock_tcp_data_encap(uint8_t *buf, uint16_t len,
                    uint32_t saddr, uint32_t daddr,
                    uint16_t sport, uint16_t dport);
int
sock_tcp_process_control(struct ip *iph, struct tcphdr *th, int recvlen);
uint64_t
get_time_ns(void);
tcp_socket *
tcp_find_socket(uint32_t saddr, uint32_t daddr,
                uint16_t sport, uint16_t dport);
tcp_socket *
sock_tcp_connect(uint32_t saddr, uint32_t daddr,
                 uint16_t sport, uint16_t dport);
tcp_socket *
sock_tcp_listen(uint32_t saddr, uint32_t daddr,
                uint16_t sport, uint16_t dport);
int tcp_is_established (tcp_socket *socket);
int tcp_is_closed (tcp_socket *socket);
tcp_socket *
tcp_create_est_socket(uint32_t saddr, uint32_t daddr,
                      uint16_t sport, uint16_t dport,
                      int server);

#endif

