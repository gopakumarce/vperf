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

#include <stdio.h> 
#include <string.h>
#include <signal.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h> 
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdlib.h> 
#include <time.h> 
#include <netinet/udp.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <getopt.h>
#include "cmn.h"

static uint8_t              senddata[MAX_PKT_SIZE];
static uint8_t              recvdata[MAX_PKT_SIZE];
static struct sockaddr_in   destaddr; 
static int                  fd;
static uint64_t             start_time;
static volatile uint64_t    bytes_rcvd;
static volatile uint32_t    packets_rcvd;
static volatile int32_t     stats_wr_win = -1;
static int32_t              stats_rd_win;
static volatile uint64_t    window_bytes[MAX_WINDOW];
static uint32_t             window_packets[MAX_WINDOW];
static uint8_t              srcmac[ETH_ALEN];
static uint8_t              dstmac[ETH_ALEN];
static uint8_t              raw_gre = 1;
static uint8_t              raw_tcp;
static uint8_t              raw_udp;
static uint8_t              plain_udp;
static struct in_addr       srcip;
static struct in_addr       dstip;
static struct in_addr       srcgre;
static struct in_addr       dstgre;
static struct in_addr       bindip;
static struct sockaddr_ll   rawsocket;
static int                  ifindex;
static char                 *interface;
static int                  runtime = CLIENT_RUN_TIME;
static int                  cmdtmp;
static int                  am_client;
static int                  am_server;
static int                  pps = DEFAULT_PPS;
static int                  ppms;
static int                  interval = 1;
static int                  winint = 1000;
static volatile int         stop_tx;
static int                  port_incr_max;
static int                  tcp_noconnect;
static struct option        long_options[] = {
    {"mode", required_argument, &cmdtmp, 0},
    {"smac", required_argument, &cmdtmp, 0},
    {"dmac", required_argument, &cmdtmp, 0},
    {"sip", required_argument, &cmdtmp, 0},
    {"dip", required_argument, &cmdtmp, 0},
    {"intf", required_argument, &cmdtmp, 0},
    {"proto", required_argument, &cmdtmp, 0},
    {"time", required_argument, &cmdtmp, 0},
    {"bind", required_argument, &cmdtmp, 0},
    {"pps", required_argument, &cmdtmp, 0},
    {"int", required_argument, &cmdtmp, 0},
    {"win", required_argument, &cmdtmp, 0},
    {"port", required_argument, &cmdtmp, 0},
    {"sport", required_argument, &cmdtmp, 0},
    {"sincr", required_argument, &cmdtmp, 0},
    {"nosyn", required_argument, &cmdtmp, 0},
    {NULL, 0, NULL, 0},
};

uint16_t                    service_port = SERVICE_PORT_DFLT;
uint16_t                    service_port_src = SERVICE_PORT_DFLT;

static void *
tcp_close_and_wait (void *arg)
{
    int                         port;
    tcp_socket                  *socket;

    for (port = SERVICE_PORT; port <= SERVICE_PORT + port_incr_max;
         port++) {
        socket = tcp_find_socket(srcip.s_addr, dstip.s_addr, port, port);
        if (!tcp_is_closed(socket)) {
            sock_tcp_close(srcip.s_addr, dstip.s_addr, port, port);
        }
    }
    while (1) {
        for (port = SERVICE_PORT; port <= SERVICE_PORT + port_incr_max;
             port++) {
            socket = tcp_find_socket(srcip.s_addr, dstip.s_addr, port, port);
            if (!tcp_is_closed(socket)) {
                break;
            }
        }
        if (port > (SERVICE_PORT + port_incr_max)) {
            VLOG("All sockets [%d] closed, exiting\n", port);
            break;
        } else {
            VLOG("Waiting for sockets [%d] to close\n", port);
            sleep(2);
        }
    }

    exit(0);
}

/*
 * On client:
 * The first control-c stops the client side traffic
 * the second control-c restarts client side traffic
 * the third control-c kills the client.
 * On server:
 * the very first control-c kills the server
 *
 * Client or server: more control-cs than described above results in exit
 */
static void
process_signal (int32_t sig_num)
{
    static int                  sigcnt = 0;
    tcp_socket                  *socket;
    int                         i;
    pthread_t                   tid;

    if (am_client) {
        if (!sigcnt) {
            stop_tx = 1;
            VLOG("Control-c %d, stop traffic\n", sigcnt);
        } else if (sigcnt == 1) {
            stop_tx = 0;
            VLOG("Control-c %d, start traffic\n", sigcnt);
        } else if (sigcnt == 2) {
            stop_tx = 1;
            VLOG("Control-c %d, stop traffic\n", sigcnt);
        }
    }
    sigcnt++;

    if (am_server) {
        if (sigcnt == 1) {
            VLOG("\n-------------FINAL COUNTS------------\n");
            for (i = 0; i <= stats_wr_win; i++) {
                VLOG("[%04d]: %lu Bytes, %u Packets\n",
                     i, window_bytes[i], window_packets[i]);
            }
            if (raw_tcp) {
                VLOG("Control-c %d, wait for tcp close\n", sigcnt);
                pthread_create(&tid, NULL, tcp_close_and_wait, NULL);
            } else {
                VLOG("Control-c %d, exit\n", sigcnt);
                exit(0);
            } 
        }
        if (sigcnt >= 2) {
            VLOG("Control-c %d, exit\n", sigcnt);
            exit(0);    
        }
    } 

    if (am_client) {
        if (sigcnt == 3) {
            if (raw_tcp) {    
                VLOG("Control-c %d, wait for tcp close\n", sigcnt);
                pthread_create(&tid, NULL, tcp_close_and_wait, NULL);
            } else {
                VLOG("Control-c %d, exit\n", sigcnt);
                exit(0);
            }
        }
        if (sigcnt >= 4) {
            VLOG("Control-c %d, exit\n", sigcnt);
            exit(0);
        }
    }
}

static void
sock_layer2_encapsulate (uint8_t *buf, uint8_t *srcmac, uint8_t *dstmac)
{
    struct ether_header     *eth = (struct ether_header *)buf;

    memcpy(eth->ether_shost, srcmac, ETH_ALEN);
    memcpy(eth->ether_dhost, dstmac, ETH_ALEN);
    eth->ether_type = htons(ETH_P_IP);
}

static void
sock_ipv4_encapsulate (uint8_t *buf, uint8_t proto, uint16_t len,
                       uint32_t saddr, uint32_t daddr)
{
    struct ip               *iph = (struct ip *)buf;

    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_id = htons(0);
    iph->ip_off = 0;
    iph->ip_ttl = 64;
    iph->ip_p = proto;
    iph->ip_len = htons(len + sizeof(struct ip));
    iph->ip_src.s_addr = saddr;
    iph->ip_dst.s_addr = daddr;
    iph->ip_sum = 0;
    iph->ip_sum = ip_cksum(iph, iph->ip_hl*4, 0);
}

static void
sock_udp_hdr_encap (uint8_t *buf, uint16_t len)
{
    struct udphdr           *uhdr = (struct udphdr *)buf;
    static uint16_t         sport = 0;
    static uint16_t         dport = 0;

    if (!sport) {
        sport = SERVICE_PORT;
    }
    if (!dport) {
        dport = SERVICE_PORT;
    }

    uhdr->source = htons(sport);
    uhdr->dest = htons(dport);
    uhdr->len = htons(len + sizeof(struct udphdr));
    uhdr->check = 0;
    if (port_incr_max) {
        sport++;
        dport++;
        if (sport > (SERVICE_PORT + port_incr_max)) {
            sport = SERVICE_PORT;
        }
        if (dport > (SERVICE_PORT + port_incr_max)) {
            dport = SERVICE_PORT;
        }
    }
}

static int
not_udp_pkt (uint8_t *machdr)
{
    struct ip               *iph;
    struct udphdr           *udp;

    iph = (struct ip*)(machdr + sizeof(struct ether_header));
    if (iph->ip_p != IPPROTO_UDP) {
        return (1);
    }
    udp = (struct udphdr *)((uint8_t *)iph + sizeof(struct ip));
    if ((ntohs(udp->dest) < SERVICE_PORT) ||
        (ntohs(udp->dest) > (SERVICE_PORT + port_incr_max))) {
        return (1);
    } 

    return (0);
}

static void
sock_gre_hdr_encap (uint8_t *buf)
{
    uint32_t                *gre = (uint32_t *)buf;

    *gre = htonl(GRE_HDR);
}

static uint8_t *
sock_gre_encap (uint8_t *buf, int len)
{
    sock_layer2_encapsulate(buf, srcmac, dstmac);

    buf += sizeof(struct ether_header);

    sock_ipv4_encapsulate(buf, IPPROTO_GRE,
                          GRE_HDR_SIZE+
                          sizeof(struct ip)+sizeof(struct udphdr)+
                          len,
                          srcip.s_addr, dstip.s_addr);

    buf += sizeof(struct ip);

    sock_gre_hdr_encap(buf);
    
    buf += GRE_HDR_SIZE;

    sock_ipv4_encapsulate(buf, IPPROTO_UDP,
                          sizeof(struct udphdr)+len,
                          srcgre.s_addr, dstgre.s_addr);

    buf += sizeof(struct ip);

    sock_udp_hdr_encap(buf, len);

    buf += sizeof(struct udphdr);

    return (buf);
}

static uint8_t *
sock_tcp_encap (uint8_t *buf, int len, uint16_t sport, uint16_t port)
{
    uint8_t                 *th;
    int                     thlen;

    sock_layer2_encapsulate(buf, srcmac, dstmac);

    buf += sizeof(struct ether_header);

    /*
     * Get the TCP encaps over with so we know the tcp header len
     */
    buf += sizeof(struct ip); // Leave room for IP
    th = buf;
    buf += sock_tcp_data_encap(buf, len, srcip.s_addr, dstip.s_addr,
                               sport, port);
   
    /*
     * Now rewind back to encaps IP
     */
    thlen = (int)(buf - th);
    buf = th - sizeof(struct ip);
    sock_ipv4_encapsulate(buf, IPPROTO_TCP,
                          thlen + len,
                          srcip.s_addr, dstip.s_addr);
    buf += sizeof(struct ip) + thlen;

    return (buf);
}

static uint8_t *
sock_udp_encap (uint8_t *buf, int len)
{
    sock_layer2_encapsulate(buf, srcmac, dstmac);

    buf += sizeof(struct ether_header);

    sock_ipv4_encapsulate(buf, IPPROTO_UDP,
                          sizeof(struct udphdr) + len,
                          srcip.s_addr, dstip.s_addr);

    buf += sizeof(struct ip);

    sock_udp_hdr_encap(buf, len);

    buf += sizeof(struct udphdr);

    return (buf);
}

int
sock_tcp_control_send (tcp_socket *socket, int which, int ack)
{
    uint8_t                 *buf = senddata;
    uint8_t                 *th;
    int                     thlen;

    sock_layer2_encapsulate(buf, srcmac, dstmac);

    buf += sizeof(struct ether_header);

    /*
     * Encaps TCP and get it over with, so we know the tcp hdrlen.
     */
    buf += sizeof(struct ip);
    th = buf;

    switch (which) {
    case TH_SYN:        
        buf += sock_tcp_syn_encap(buf, socket, ack);
        break;
    case TH_FIN:            
        buf += sock_tcp_fin_encap(buf, socket, ack);
        break;
    case TH_ACK:            
        buf += sock_tcp_ack_encap(buf, socket);
        break;
    case TH_RST:            
        buf += sock_tcp_rst_encap(buf, socket);
        break;
    default:
        VLOG("Unknown control type %d\n", which);
        exit(1);        
        break;
    }
    
    thlen = (int)(buf - th);
    buf = th - sizeof(struct ip);
    sock_ipv4_encapsulate(buf, IPPROTO_TCP,
                          thlen,
                          socket->saddr, socket->daddr);
    buf += sizeof(struct ip) + thlen;

    if (sendto(fd, senddata, (int)(buf-senddata), 0,
               (struct sockaddr *)&rawsocket, sizeof(rawsocket)) < 0) {
        VLOG("control send failed");
        return (1);
    }

    return (0);
}

static int32_t
sock_raw_init (void)
{
    int                 rv;

    ifindex = if_nametoindex(interface);

    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        VLOG("cannot create socket\n");
        return (1);
    }    

    memset(&rawsocket, 0, sizeof(struct sockaddr_ll));
    rawsocket.sll_family = AF_PACKET;
    rawsocket.sll_ifindex = ifindex;
    rawsocket.sll_protocol = htons(ETH_P_ALL);

    rv = bind(fd, (struct sockaddr *)&rawsocket, sizeof(struct sockaddr_ll));
    if (rv < 0) {
        VLOG("cannot bind raw socket\n");
        return (1);
    }

    return (0);
}

static int32_t
sock_udp_init (void)
{
    int                     index;
    uint16_t                port;
    struct sockaddr_in      myaddr;

    for (port = 0; port <= port_incr_max; port++) {
        /* create a UDP socket */
        if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            VLOG("cannot create socket\n");
            return (1);
        }

        /* bind the socket to any valid IP address and a specific port */
        memset((char *)&myaddr, 0, sizeof(myaddr));
        myaddr.sin_family = AF_INET;
        if (!bindip.s_addr) {        
            myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
        } else {
            myaddr.sin_addr.s_addr = bindip.s_addr;
        }
        myaddr.sin_port = htons(SERVICE_PORT+port);

        if (bind(fd, (struct sockaddr *)&myaddr,
                 sizeof(myaddr)) < 0) {
            VLOG("bind failed");
            return (2);
        }
    }

    return (0);
}

static int
not_gre_pkt (uint8_t *machdr)
{
    struct ip               *iph;
    struct ip               *ipin;

    iph = (struct ip *)(machdr + sizeof(struct ether_header));
    if (iph->ip_p != IPPROTO_GRE) {
        return (1);
    }        
    ipin = (struct ip *)(((uint8_t *)iph) + sizeof(struct ip) + GRE_HDR_SIZE);
    if (ipin->ip_p != IPPROTO_UDP) {
        return (1);
    }

    return (0);
}

static int
socket_send (uint8_t *data, uint16_t dlen, uint8_t *txdata, uint16_t txlen,
             uint8_t incr)
{
    uint8_t                             *buf;
    int                                 rv = 0;
    static uint16_t                     port = 0;

    if (!port) {
        port = SERVICE_PORT;
    }

    if (!raw_gre && !raw_tcp && !raw_udp) {
        memcpy(txdata, data, dlen);
        rv = sendto(fd, txdata, txlen, 0,
                    (struct sockaddr *)&destaddr,
                    sizeof(destaddr));
        if (rv < 0) {
            VLOG("udp sock send failed");
            return (1);
        }
    } else if (raw_udp) {
        buf = sock_udp_encap(txdata, txlen);
        memcpy(buf, data, dlen);
        if (sendto(fd, txdata, (int)(buf-txdata)+txlen, 0,
                   (struct sockaddr *)&rawsocket, sizeof(rawsocket)) < 0) {
            VLOG("udp sock send failed");
            return (1);
        }
    } else if (raw_gre) {
        buf = sock_gre_encap(txdata, txlen);
        memcpy(buf, data, dlen);
        if (sendto(fd, txdata, (int)(buf-txdata)+txlen, 0,
                   (struct sockaddr *)&rawsocket, sizeof(rawsocket)) < 0) {
            VLOG("gre sock send failed");
            return (1);
        }
    } else if (raw_tcp) {
        if (!incr) {
            buf = sock_tcp_encap(txdata, txlen, SERVICE_PORT_SRC, SERVICE_PORT);
        } else {
            buf = sock_tcp_encap(txdata, txlen, port, port);
        }
        memcpy(buf, data, dlen);
        if (sendto(fd, txdata, (int)(buf-txdata)+txlen, 0,
                   (struct sockaddr *)&rawsocket, sizeof(rawsocket)) < 0) {
            VLOG("tcp sock send failed");
            return (1);
        }
        if (incr && port_incr_max) {
            port++;
            if (port > (SERVICE_PORT + port_incr_max)) {
                port = SERVICE_PORT;
            }
        }
    }

    return (0);
}

static uint8_t *
socket_recv (int *recvlen)
{
    struct sockaddr_in      senderaddr;
    socklen_t               remlen = sizeof(senderaddr);
    struct tcphdr           *th;
    struct ip               *iph;        
    int                     tcpoptlen;
    int                     iplen;
    static uint16_t         port = 0;

    if (!raw_gre && !raw_tcp && !raw_udp) {
        *recvlen = recvfrom(fd, recvdata, MAX_PKT_SIZE, 0,
                            (struct sockaddr *)&senderaddr, &remlen);
        if (*recvlen <= 0) {
            VLOG("recieve error\n");
            return (NULL);
        }
        return (recvdata);
    } else if (raw_udp) {
        *recvlen = read(fd, recvdata, MAX_PKT_SIZE);
        if (not_udp_pkt(recvdata)) {
            return (NULL);
        }
        *recvlen -= UDP_ENCAP_SIZE;
        iph = (struct ip *)(recvdata + sizeof(struct ether_header));
        iplen = ntohs(iph->ip_len) -
                (UDP_ENCAP_SIZE - sizeof(struct ether_header));
        // There can be padding in the packet, so recvlen can be 
        // more than ip len
        if ((*recvlen <= 0) || (iplen <= 0) || (iplen > *recvlen)) {
            return (NULL);
        }
        *recvlen = iplen;
        return (recvdata+UDP_ENCAP_SIZE);
    } else if (raw_gre) {
        *recvlen = read(fd, recvdata, MAX_PKT_SIZE);
        if (not_gre_pkt(recvdata)) {
            return (NULL);
        }
        *recvlen -= GRE_ENCAP_SIZE;
        iph = (struct ip *)(recvdata + sizeof(struct ether_header));
        iplen = ntohs(iph->ip_len) -
                (GRE_ENCAP_SIZE - sizeof(struct ether_header));
        // There can be padding in the packet, so recvlen can be 
        // more than ip len
        if ((*recvlen <= 0) || (iplen <= 0) || (iplen > *recvlen)) {
            return (NULL);
        }
        *recvlen = iplen;
        return (recvdata+GRE_ENCAP_SIZE);
    } else if (raw_tcp) {
        *recvlen = read(fd, recvdata, MAX_PKT_SIZE);
        iph = (struct ip *)(recvdata + sizeof(struct ether_header));
        th = (struct tcphdr *)(recvdata + IP_ENCAP_SIZE);
        tcpoptlen = (th->doff - 5)*4;
        *recvlen -= (TCP_ENCAP_SIZE + tcpoptlen);
        iplen = ntohs(iph->ip_len) -
                (TCP_ENCAP_SIZE + tcpoptlen - sizeof(struct ether_header));
        // There can be padding in the packet, so recvlen can be 
        // more than ip len
        if ((*recvlen < 0) || (iplen < 0) || (iplen > *recvlen)) {
            // == 0 is fine, it might be a control pkt
            return (NULL);
        }
        if ((ntohs(th->dest) < SERVICE_PORT) ||
            (ntohs(th->dest) > (SERVICE_PORT + port_incr_max))) {
            return (NULL);
        }
        if (iplen == 0) {
            VLOG("Calling control %d, %d, %d\n",
                 *recvlen, iplen, tcpoptlen);
        }
        // Only control info, no data
        if (sock_tcp_process_control(iph, th, iplen)) {
            return (NULL);
        }
        if (*recvlen <= 0) {
            // No data !!
            return (NULL);
        }
        *recvlen = iplen;
        // Control processed, now give the data to the app
        return (recvdata + TCP_ENCAP_SIZE + tcpoptlen);
    }

    return (NULL);
}

static void *
send_bw2remote (void *arg)
{
    int                             i;
    int                             win;        
    int                             cnt;
    bw_stats                        cur_stats;

    for (;;) {
        // TODO: Wrap around of rd vs write not handled here
        for (win = stats_rd_win, cnt = 0;
            (win <= stats_wr_win) && (cnt < MAX_STATS);
             win++, cnt++) {
            cur_stats.recieved_bytes[cnt] = window_bytes[win];
            cur_stats.recieved_packets[cnt] = window_packets[win];
            VLOG("[%04d]: %lu bytes, %u packets, %lu b/w\n",
                 win, cur_stats.recieved_bytes[cnt],
                 cur_stats.recieved_packets[cnt],
                 cur_stats.recieved_bytes[cnt]*8);
        }
        if (!cnt) {
            usleep(1000);
            continue;      
        }
        cur_stats.index = stats_rd_win;
        cur_stats.cnt = cnt;
        stats_rd_win = (stats_rd_win + cnt) % MAX_WINDOW;

        // Unreliable udp, lets send 10 times just in case
        for (i = 0; i < MSG_RETRY_COUNT; i++) {
            (void)socket_send((uint8_t *)&cur_stats, sizeof(cur_stats),
                              senddata, sizeof(cur_stats), 0);
        }
        usleep(1000);
    }
}

static void
server_recv (void)
{
    int                     recvlen;
    bw_pkt                  *sent_ptr;
    int                     window;
    int                     lastwin = -1;

    while (1) {
        sent_ptr = (bw_pkt *)socket_recv(&recvlen);
        if (!sent_ptr) {
            continue;
        }            
        window = sent_ptr->cur_window;
        if (lastwin == -1) {
            lastwin = window;
        }
        if (window > lastwin) {
            stats_wr_win = (lastwin % MAX_WINDOW);
            lastwin = window;
        }
        bytes_rcvd += recvlen;
        packets_rcvd += 1;
        window_bytes[window % MAX_WINDOW] += recvlen;
        window_packets[window % MAX_WINDOW]++;
        if (!start_time) {
            start_time = get_time_ns();
        }
    }
}

static void *
client_recv (void *arg)
{
    int                     recvlen;
    bw_stats                *cur_stats;
    int                     index = -1;
    int                     i;

    while (1) {
        cur_stats = (bw_stats *)socket_recv(&recvlen);
        if (!cur_stats) {
            continue;
        }
        // We already got this report
        if (cur_stats->index == index) {
            continue;
        }
        //TODO: Again, wrap around of stats indices not handled here
        index = cur_stats->index;
        for (i = 0; i < cur_stats->cnt; i++) {
            bytes_rcvd += cur_stats->recieved_bytes[i];
            packets_rcvd += cur_stats->recieved_packets[i];
            VLOG("[%04d]: %lu Rx bytes, %u Rx packets, %u Tx packets, %lu b/w\n",
                 index+i, cur_stats->recieved_bytes[i],
                 cur_stats->recieved_packets[i],
                 window_packets[index+i],
                 cur_stats->recieved_bytes[i]*8);
        }            
    }
}

static void
client_send (void)
{
    bw_pkt                  *sent_ptr;
    uint32_t                wnum = 0;
    uint64_t                wstart = 0;
    uint32_t                wpkts = 0;
    uint32_t                wpktsms = 0;
    uint64_t                mswin = 0;
    uint64_t                curtime;
    bw_pkt                  bw;

    start_time = wstart = get_time_ns();
    
    while (1) {

        if (stop_tx) {
            sleep(1);
        }

        curtime = get_time_ns();
        if ((curtime < wstart) || 
            (curtime - wstart) >= (interval*1000000)) {
            mswin++;
            wpktsms = 0;
            wstart = get_time_ns();
            if (mswin && !(mswin % winint)) {
                window_packets[wnum] = wpkts;
                wpkts = 0;
                stats_wr_win = wnum;
                wnum++;
            }
        }
        if (wpktsms >= ppms) {
            continue;
        }

        bw.cur_window = wnum;
        if (socket_send((uint8_t *)&bw, sizeof(bw), senddata,
                        SEND_PKT_SIZE, 0)) {
            continue;
        }
        wpkts += 1;
        wpktsms += 1;
        if ((get_time_ns() - start_time)/ONE_SECOND  >= runtime) {
            VLOG("Sent packets for %d seconds, exiting in"
                 "case it screws up connectivity\n", runtime);
            process_signal(0);
            process_signal(0);
            process_signal(0);
            sleep(3600);
        }
    }
}

static void 
usage (char *pgm)
{
    VLOG(
            "Options are as follows\n"
            "--mode client or server\n"
            "--smac for src-mac [required only with -proto raw]\n"
            "--dmac for dest-mac [required only with -proto raw]\n"
            "--sip for self ip address [required only with -proto raw]\n"
            "--dip for remote ip address [required with any -proto]\n"
            "--intf for interface name [required only with -proto raw]\n"
            "--proto for udp or tcp or gre, defaults to gre\n"
            "--time for runtime of the sender (client) in seconds\n"
            "--bind for ip address to bind to in case of udp\n"
            "--pps for packets per second (1352 byte gre or 1328 byte ip)\n"
            "--int for interval in msec, ie send pps/int amount of packets per intveral\n"
            "--win what multiple of --int for incrementing window\n"
            "--port port number to be used (default is 21234)\n"
            "--sport source port number to be used (default is 21234)\n"
            "--nosyn if we want to ride on a previously created tcp connection (dont send SYN)\n"
            );
}

static void
handle_options (const char *name, char *arg)
{
    if (!strcmp(name, "sip")) {
        inet_aton(arg, &srcip);
    }

    if (!strcmp(name, "dip")) {
        inet_aton(arg, &dstip);
    }

    if (!strcmp(name, "intf")) {
        interface = strdup(arg);
    }

    if (!strcmp(name, "proto")) {
        if (!strcmp(arg, "udp")) {
            plain_udp = 1;
            raw_gre = 0;
        } else if (!strcmp(arg, "gre")) {
            raw_gre = 1;
        } else if (!strcmp(arg, "tcp")) {
            raw_tcp = 1;
            raw_gre = 0;
        } else if (!strcmp(arg, "rudp")) {
            raw_udp = 1;
            raw_gre = 0;
        }
    }

    if (!strcmp(name, "time")) {
        runtime = atoi(arg);
    }
    
    if (!strcmp(name, "smac")) {
        sscanf(arg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &srcmac[0], &srcmac[1], &srcmac[2], &srcmac[3],
               &srcmac[4], &srcmac[5]);
    }        

    if (!strcmp(name, "dmac")) {
        sscanf(arg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &dstmac[0], &dstmac[1], &dstmac[2], &dstmac[3],
               &dstmac[4], &dstmac[5]);
    }        

    if (!strcmp(name, "mode")) {
        if (!strcmp(arg, "client")) {    
            am_client = 1;
        }
        if (!strcmp(arg, "server")) {    
            am_server = 1;
        }
    }

    if (!strcmp(name, "bind")) {
        inet_aton(arg, &bindip);
    }

    if (!strcmp(name, "pps")) {
        pps = atoi(arg);
    }

    if (!strcmp(name, "int")) {
        interval = atoi(arg);
    }

    if (!strcmp(name, "win")) {
        winint = atoi(arg);
    }
    
    if (!strcmp(name, "port")) {
        service_port = atoi(arg);
    }

    if (!strcmp(name, "sport")) {
        service_port_src = atoi(arg);
    }

    if (!strcmp(name, "sincr")) {
        port_incr_max = atoi(arg);
        if (port_incr_max > PORT_INCR_MAX) {
            port_incr_max = PORT_INCR_MAX;
        }            
    }
    if (!strcmp(name, "nosyn")) {
        tcp_noconnect = atoi(arg);    
    }
}

static void
do_client_init (void)
{
    pthread_t                   tid;
    int                         port;
    tcp_socket                  *socket;

    pthread_create(&tid, NULL, client_recv, NULL);
    if (raw_tcp) {
        for (port = SERVICE_PORT; port <= SERVICE_PORT + port_incr_max;
             port++) {
            if (!tcp_noconnect) {
                sock_tcp_connect(srcip.s_addr, dstip.s_addr, port, port);
            } else {
                socket = tcp_create_est_socket(srcip.s_addr, dstip.s_addr,
                                               port, port, am_server);
            }
        }
        while (1) {
            for (port = SERVICE_PORT; port <= SERVICE_PORT + port_incr_max;
                 port++) {
                socket = tcp_find_socket(srcip.s_addr, dstip.s_addr,
                                         port, port);
                if (!tcp_is_established(socket)) {
                    break;
                }
            }
            if (port > (SERVICE_PORT + port_incr_max)) {
                VLOG("All sockets [%d] established\n", port);
                break;
            } else {
                SLOG(socket, "Waiting for sockets [%d] to establish\n", port);
                sleep(2);
            }
        }
    }
    VLOG("Going to send %u packets per %d milli seconds\n",
         ppms, interval);
    client_send();
}

static void
do_server_init (void)
{
    pthread_t                   tid;
    int                         port;
    tcp_socket                  *socket;

    if (raw_tcp) {
        for (port = SERVICE_PORT; port <= SERVICE_PORT + port_incr_max;
             port++) {
            if (!tcp_noconnect) {
                sock_tcp_listen(srcip.s_addr, dstip.s_addr, port, port);
            } else {
                socket = tcp_create_est_socket(srcip.s_addr, dstip.s_addr,
                                               port, port, am_server);
            }
        }
    }
    pthread_create(&tid, NULL, send_bw2remote, NULL);
    server_recv();
}

int
main (int argc, char **argv)
{
    struct sigaction            sa;
    int                         c;
    int                         option_index = 0;
    pthread_t                   tid;
    tcp_socket                  *socket;
    int                         port;

    while ((c = getopt_long(argc, argv, "",
                            long_options, &option_index)) != -1) {
        switch (c) {
        case 0:
            printf("option %s, arg %s\n", long_options[option_index].name,
                   optarg);
            handle_options(long_options[option_index].name, optarg);
            break;
        default:
            usage(argv[0]);
            exit(0);
            break;
        }
    }

    if (!am_client && !am_server) {
        usage(argv[0]);
        exit(0);
    }

    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = process_signal;
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
 
    inet_aton(GRE_CLIENT_IP, &srcgre);
    inet_aton(GRE_SERVER_IP, &dstgre);

    memset((char*)&destaddr, 0, sizeof(destaddr));
    destaddr.sin_family = AF_INET;
    destaddr.sin_port = htons(SERVICE_PORT);
    destaddr.sin_addr = dstip;

    ppms = (pps*interval)/1000;
    if (ppms == 0) {
        ppms = 1;
    }

    if (plain_udp) {
        if (sock_udp_init()) {
            return (1);
        }
    } else {
        if (sock_raw_init()) {
            return (1);
        }
    }

    if (am_client) {
        do_client_init();
    }

    if (am_server) {
        do_server_init();
    }

    return (0);
}

