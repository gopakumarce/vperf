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
/*
 * Basic TCP/IP just to get a session ESTABLISHED and CLOSED, no 
 * retransmissions, just ACK whatever has been recieved so far, 
 * assumes that the application retransmits (funny!! :) 
 */
#include <stdio.h>
#include <string.h>
#include "cmn.h"

static tcp_socket               my_socket[PORT_INCR_MAX+1];
static int                      tcp_sm_thread;

/*
 ****NOTE****: Throughout this file, the uint32_t source and dest ip
 * addresses are assumed to be already in network format, so no need 
 * for htonl on them
 */

tcp_socket *
tcp_find_socket (uint32_t saddr, uint32_t daddr,
                 uint16_t sport, uint16_t dport)
{
    return (&my_socket[dport-SERVICE_PORT]);
}

static tcp_socket *
tcp_create_socket (uint32_t saddr, uint32_t daddr,
                   uint16_t sport, uint16_t dport)
{
    memset(&my_socket[dport-SERVICE_PORT], 0, sizeof(my_socket[0]));
    return (&my_socket[dport-SERVICE_PORT]);
}

/*
 * Send a SYN with window scale option. We are basically spoofing a TCP
 * session, we dont bother retransmitting etc.., we just always ACK upto
 * the last recieved packet. There are sequence-number-checking firewalls
 * (though they are proven to do more bad than good, google ..) that will
 * drop packets if their sequence numbers are outside the window range plus
 * what has been ACKed so far. So to prevent/reduce the possibility of that,
 * use the max possible window range (1Gb) using window scale.
 */
int
sock_tcp_syn_encap (uint8_t *buf,
                    tcp_socket *socket,
                    uint8_t ack)
{
    struct tcphdr                   *th;
    tcp_wscale                      *wscale;
    uint16_t                        len = 0;

    th = (struct tcphdr *)buf;
    memset(th, 0, sizeof(*th));
    wscale = (tcp_wscale *)(buf + sizeof(*th));

    th->source = htons(socket->sport);
    th->dest = htons(socket->dport);
    th->seq = htonl(socket->my_seq);
    th->ack_seq = htonl(socket->rem_seq);
    /*
     * TCP Header plus just one option, change if options added/deled
     */
    th->doff = 6;
    th->syn = 1;
    if (ack) {
        th->ack = 1;
    }
    th->window = htons(TH_WINDOW_MAX);
    th->check = 0;
    th->urg_ptr = htons(0);
    
    /*
     * Add window scale to 1Gb (max allowed). NOTE: Some websites say
     * that there are firewalls around that doesnt recognize window scale
     * and can cause problems where packets are lost intermittently and
     * then recovers, need to be seen if such (old)firewalls still exist.
     */
    wscale->kind = TH_OPT_WSCALE;
    wscale->len = TH_OPT_WSCALE_LEN;
    wscale->shift = TH_OPT_WSCALE_MAX;
    /*
     * One byte pad since this is the last option, if more options are
     * added after this remove the pad and re-pad approrpriately.
     */
    wscale->pad[0] = 0; 

    // payload len (0) plus tcp plus option len + 1 byte pad .. Note that
    // padding will change if options are added/removed
    len += sizeof(*th) + sizeof(*wscale) + 1;
    th->check = tcp_cksum(socket->saddr, socket->daddr, len, th);

    socket->my_seq++;

    return (sizeof(*th) + sizeof(*wscale) + 1);
}

int
sock_tcp_fin_encap (uint8_t *buf,
                    tcp_socket *socket,
                    uint8_t ack)
{
    struct tcphdr                   *th;
    uint16_t                        len = 0;

    th = (struct tcphdr *)buf;
    memset(th, 0, sizeof(*th));

    th->source = htons(socket->sport);
    th->dest = htons(socket->dport);
    th->seq = htonl(socket->my_seq);
    th->ack_seq = htonl(socket->rem_seq);
    th->doff = 5;
    th->fin = 1;
    if (ack) {
        th->ack = 1;
    }
    th->window = htons(TH_WINDOW_MAX);
    th->check = 0;
    th->urg_ptr = htons(0);
    
    // payload len (0) plus tcp 
    len += sizeof(*th);
    th->check = tcp_cksum(socket->saddr, socket->daddr, len, th);

    socket->my_seq += sizeof(*th);

    SLOG(socket, "Sending FIN\n");

    return (sizeof(*th));
}

int
sock_tcp_ack_encap (uint8_t *buf, tcp_socket *socket)
{
    struct tcphdr                   *th;
    uint16_t                        len = 0;

    th = (struct tcphdr *)buf;
    memset(th, 0, sizeof(*th));

    th->source = htons(socket->sport);
    th->dest = htons(socket->dport);
    th->seq = htonl(socket->my_seq);
    th->ack_seq = htonl(socket->rem_seq);
    th->doff = 5;
    th->ack = 1;
    th->window = htons(TH_WINDOW_MAX);
    th->check = 0;
    th->urg_ptr = htons(0);

    // payload len (0) plus tcp
    len += sizeof(*th);
    th->check = tcp_cksum(socket->saddr, socket->daddr, len, th);

    socket->my_seq += sizeof(*th);

    return (sizeof(*th));
}

int
sock_tcp_rst_encap (uint8_t *buf, tcp_socket *socket)
{
    struct tcphdr                   *th;
    uint16_t                        len = 0;

    th = (struct tcphdr *)buf;
    memset(th, 0, sizeof(*th));

    th->source = htons(socket->sport);
    th->dest = htons(socket->dport);
    th->seq = htonl(socket->my_seq);
    th->ack_seq = htonl(socket->rem_seq);
    th->doff = 5;
    th->rst = 1;
    th->window = htons(TH_WINDOW_MAX);
    th->check = 0;
    th->urg_ptr = htons(0);

    // payload len (0) plus tcp
    len += sizeof(*th);
    th->check = tcp_cksum(socket->saddr, socket->daddr, len, th);

    socket->my_seq += sizeof(*th);

    return (sizeof(*th));
}

int
sock_tcp_data_encap (uint8_t *buf, uint16_t len,
                     uint32_t saddr, uint32_t daddr,
                     uint16_t sport, uint16_t dport)
{
    struct tcphdr                   *th;
    tcp_socket                      *socket;

    th = (struct tcphdr *)buf;
    memset(th, 0, sizeof(*th));
    socket = tcp_find_socket(saddr, daddr, sport, dport);

    th->source = htons(sport);
    th->dest = htons(sport);
    th->seq = htonl(socket->my_seq);
    th->ack_seq = htonl(socket->rem_seq);
    th->doff = 5;
    th->ack = 1;
    th->window = htons(TH_WINDOW_MAX);
    th->check = 0;
    th->urg_ptr = htons(0);

    // payload len plus tcp len 
    len += sizeof(*th);
    th->check = tcp_cksum(saddr, daddr, len, th);

    // Update my_seq
    socket->my_seq = socket->my_seq + len;

    return (sizeof(*th));
}

static void
process_syn (tcp_socket *socket, struct tcphdr *th)
{
    switch (socket->tcp_state) {
    case TCP_STATE_LISTEN:
        socket->rem_seq = ntohl(th->seq) + 1;
        socket->my_seq = 0;
        sock_tcp_control_send(socket, TH_SYN, 1);
        socket->tcp_state = TCP_STATE_SYN_RCVD;
        SLOG(socket, "Moving to SYN_RCVD, seq %u\n", socket->rem_seq);
        break;

    case TCP_STATE_SYN_SENT:
        if (!th->ack) {
            // We dont handle the simultaneous-open state since we know
            // that we have a client-server model where client will initiate
            // a connection to the server
            SLOG(socket, "SYN without ack, not handling simultaneous open\n");
            break;
        }
        socket->rem_seq = ntohl(th->seq) + 1;
        sock_tcp_control_send(socket, TH_ACK, 1);
        socket->tcp_state = TCP_STATE_ESTABLISHED;
        SLOG(socket, "Going established\n");
        break;

    case TCP_STATE_SYN_RCVD:
        if (th->ack) {
            // We can expect to see a SYN-SENT-retry here, but that shouldnt
            // have an ACK set !
            SLOG(socket, "SYN wit ack, not expected\n");
            break;
        }
        // Send a syn-ack again
        socket->rem_seq = ntohl(th->seq) + 1;
        sock_tcp_control_send(socket, TH_SYN, 1);
        break;
    
    default:
        SLOG(socket, "SYN recieved in unexpected state %d\n",
             socket->tcp_state);
        break;
    }
}

static void
process_ack (tcp_socket *socket, struct tcphdr *th)
{
    switch (socket->tcp_state) {
    case TCP_STATE_SYN_RCVD:
        socket->rem_seq = ntohl(th->seq) + 1;
        socket->tcp_state = TCP_STATE_ESTABLISHED;
        SLOG(socket, "Moving to ESTABLISHED %u\n", socket->rem_seq);
        break;

    case TCP_STATE_LAST_ACK:
        socket->tcp_state = TCP_STATE_CLOSED;
        SLOG(socket, "Moving to state closed\n");
        break;

    case TCP_STATE_FIN_WAIT1:
        socket->tcp_state = TCP_STATE_FIN_WAIT2;
        SLOG(socket, "Moving to FIN-WAIT2\n");
        break;

    case TCP_STATE_CLOSING:
        // skipping time-wait, going to closed directly
        socket->tcp_state = TCP_STATE_CLOSED;
        SLOG(socket, "Moving to closed\n");
        break;

    default:
        SLOG(socket, "ACK in unknown state %d\n", socket->tcp_state);
        break;
    }
}

/*
 * Not completely the right rst handling, but something minimal.
 */
static void
process_rst (tcp_socket *socket, struct tcphdr *th)
{
    switch (socket->tcp_state) {
    case TCP_STATE_FIN_WAIT1:
    case TCP_STATE_FIN_WAIT2:
    case TCP_STATE_CLOSING:
    case TCP_STATE_LAST_ACK:
        SLOG(socket, "Recieved RST in FIN state %d\n", socket->tcp_state);
        socket->tcp_state = TCP_STATE_CLOSED;
        break;

    default:
        SLOG(socket, "Recieved RST in unknown state %d\n", socket->tcp_state);
        break;
    }
}

/*
 * Assumption is that FIN is always sent without an ACK,
 * ie FIN-ACK will be sent as a ACK followed by FIN.
 */
static void
process_fin (tcp_socket *socket, struct tcphdr *th)
{
    if (th->ack) {
        SLOG(socket, "We dont handle ACK with FIN, ignoring ..\n");
        return;
    }

    switch(socket->tcp_state) {
    case TCP_STATE_ESTABLISHED:
        // We jump directly to last-ack, skip close-wait
        sock_tcp_control_send(socket, TH_ACK, 1);
        sock_tcp_control_send(socket, TH_FIN, 0);
        socket->tcp_state = TCP_STATE_LAST_ACK;
        SLOG(socket, "Moving to last-ack\n");

        break;       
    case TCP_STATE_FIN_WAIT1:
        sock_tcp_control_send(socket, TH_ACK, 1);
        socket->tcp_state = TCP_STATE_CLOSING;
        SLOG(socket, "Moving to closing\n");
        break;

    case TCP_STATE_FIN_WAIT2:
        // skipping time-wait, jumping directly to close
        sock_tcp_control_send(socket, TH_ACK, 1);
        socket->tcp_state = TCP_STATE_CLOSED;
        SLOG(socket, "Moving to closed\n");
        break;

    default:
        SLOG(socket, "FIN in uknown state %d\n", socket->tcp_state);
        sock_tcp_control_send(socket, TH_RST, 0);
        break;        
    }
}

int
sock_tcp_process_control (struct ip *iph, struct tcphdr *th, int recvlen)
{
    int                             tcpoptlen;
    uint32_t                        new_rem_seq;
    tcp_socket                      *socket;
    int                             ret = 1;

    socket = tcp_find_socket(iph->ip_src.s_addr, iph->ip_dst.s_addr,
                             ntohs(th->source), ntohs(th->dest));
    tcpoptlen = (th->doff - 5)*4;
    new_rem_seq = ntohl(th->seq) + sizeof(struct tcphdr) + tcpoptlen + recvlen + 1;

    
    pthread_mutex_lock(&socket->mutex);

    // syn with or without ack
    if (th->syn) {
        process_syn(socket, th);
        goto out;

    } else if (th->fin) {
        process_fin(socket, th);
        goto out;

    // Just an empty ack
    } else if ((recvlen == 0) && th->ack) { 
        process_ack(socket, th);
        goto out;

    // TCP Reset
    } else if (th->rst) {
        process_rst(socket, th);
        goto out;
            
    // need syn/syn-ack to go through first
    } else if (socket->tcp_state != TCP_STATE_ESTABLISHED) {
        goto out;

    // Regular data packet
    } else {        
        if (socket->tcp_state == TCP_STATE_SYN_RCVD) {
            if (th->ack) {
                socket->tcp_state = TCP_STATE_ESTABLISHED;
                SLOG(socket, "Going established\n");
            }
        }
        // Just acknowledge whatever is the latest sequence number we recvd
        if (new_rem_seq > socket->rem_seq) {
            socket->rem_seq = new_rem_seq;
        }
        ret = 0;
        goto out;
    }

out:
    pthread_mutex_unlock(&socket->mutex);

    return (ret);
}

static int
tcp_init_states (tcp_socket *socket)
{
    int                         is_init = 1;

    switch (socket->tcp_state) {
    case TCP_STATE_SYN_RCVD:
        if (socket->syn_retries >= TH_SYN_MAX_RETRY) {
            SLOG(socket, "SYN-ACK retry maxed\n");
            break;
        }
        socket->syn_retries++;
        socket->my_seq = 0;
        sock_tcp_control_send(socket, TH_SYN, 1);
        SLOG(socket, "Retry SYN-ACK %u\n", socket->rem_seq);
        break;

    case TCP_STATE_SYN_SENT:
        if (socket->syn_retries >= TH_SYN_MAX_RETRY) {
            SLOG(socket, "SYN retry maxed\n");
            break;
        }
        socket->syn_retries++;
        socket->my_seq = 0;
        sock_tcp_control_send(socket, TH_SYN, 0);
        SLOG(socket, "Retry SYN %u\n", socket->rem_seq);
        break;

    case TCP_STATE_LISTEN:
        // nothing to do
        break;

    default:
        is_init = 0;
        break;
    }

    return (is_init);
}

static int
tcp_final_states (tcp_socket *socket)
{
    int                         is_final = 1;

    switch(socket->tcp_state) {
    case TCP_STATE_FIN_WAIT1:
    case TCP_STATE_CLOSING:
    case TCP_STATE_LAST_ACK:
        if (socket->fin_retries >= TH_SYN_MAX_RETRY) {
            SLOG(socket, "FIN retry maxed\n");
            break;
        }
        socket->fin_retries++;
        sock_tcp_control_send(socket, TH_FIN, 0);
        SLOG(socket, "Retry FIN\n");
        break;

    default:
        is_final = 0;
        break;
    }

    return (is_final);
}

static void *
tcp_state_thread (void *arg)
{
    tcp_socket              *socket;
    uint16_t                port = SERVICE_PORT;
    int                     is_init = 0;
    int                     is_final = 0;

    while (1) {

        socket = tcp_find_socket(0, 0, port, port);
        if (!socket->inited) {
            goto next_port;
        }
        pthread_mutex_lock(&socket->mutex);

        is_init = tcp_init_states(socket);
        if (!is_init) {
            is_final = tcp_final_states(socket);
        }
        if (!is_init && !is_final) {
            switch (socket->tcp_state) {
            case TCP_STATE_ESTABLISHED:
            case TCP_STATE_CLOSED:
                break;
            default:
                SLOG(socket, "Uknown state %d\n", socket->tcp_state);
                break; 
            }
        }

next_port:
        pthread_mutex_unlock(&socket->mutex);
        port = port+1;
        if (port > (SERVICE_PORT + PORT_INCR_MAX)) {
            port = SERVICE_PORT;
            sleep(2);
        }
    }
}

static tcp_socket *
sock_tcp_connect_state (uint32_t saddr, uint32_t daddr,
                        uint16_t sport, uint16_t dport,
                        tcp_states state)
{
    pthread_t               tid;
    tcp_socket              *socket;

    socket = tcp_create_socket(saddr, daddr, sport, dport);
    pthread_mutex_init(&socket->mutex, NULL);

    pthread_mutex_lock(&socket->mutex);

    socket->saddr = saddr;
    socket->daddr = daddr;
    socket->dport = dport;
    socket->sport = sport;
    socket->inited = 1;
    socket->my_seq = 0;
    socket->rem_seq = 0;
    if (state == TCP_STATE_SYN_SENT) {
        sock_tcp_control_send(socket, TH_SYN, 0);
        socket->tcp_state = TCP_STATE_SYN_SENT;
        SLOG(socket, "Moving to state SYN_SENT\n");
    } else if (state == TCP_STATE_ESTABLISHED) {
        socket->tcp_state = TCP_STATE_ESTABLISHED;
        SLOG(socket, "Moving to state established");
    }

    pthread_mutex_unlock(&socket->mutex);

    if (!tcp_sm_thread) {
        tcp_sm_thread = 1;
        pthread_create(&tid, NULL, tcp_state_thread, NULL);
    }
}

tcp_socket *
sock_tcp_connect (uint32_t saddr, uint32_t daddr,
                  uint16_t sport, uint16_t dport)
{
    return (sock_tcp_connect_state(saddr, daddr, sport, dport, 
                                   TCP_STATE_SYN_SENT));
}

static tcp_socket *
sock_tcp_listen_state (uint32_t saddr, uint32_t daddr,
                       uint16_t sport, uint16_t dport,
                       tcp_states state)
{
    pthread_t               tid;
    tcp_socket              *socket;

    socket = tcp_create_socket(saddr, daddr, sport, dport);

    socket->saddr = saddr;
    socket->daddr = daddr;
    socket->sport = sport;
    socket->dport = dport;
    socket->my_seq = 0;
    socket->rem_seq = 0;
    socket->tcp_state = state;
    socket->inited = 1;
    if (state == TCP_STATE_LISTEN) {
        SLOG(socket, "Moving to state listen\n");
    } else if (state == TCP_STATE_ESTABLISHED) {
        SLOG(socket, "Moving to state established\n");
    }
    pthread_mutex_init(&socket->mutex, NULL);

    if (!tcp_sm_thread) {
        tcp_sm_thread = 1;
        pthread_create(&tid, NULL, tcp_state_thread, NULL);
    }

    return (socket);
}

tcp_socket *
sock_tcp_listen (uint32_t saddr, uint32_t daddr,
                 uint16_t sport, uint16_t dport)
{
    return (sock_tcp_listen_state(saddr, daddr, sport, dport,
                                  TCP_STATE_LISTEN));
}

int 
sock_tcp_close (uint32_t saddr, uint32_t daddr,
                uint16_t sport, uint16_t dport)
{
    tcp_socket              *socket;

    socket = tcp_find_socket(saddr, daddr, sport, dport);
    pthread_mutex_lock(&socket->mutex);
    sock_tcp_control_send(socket, TH_FIN, 0);
    SLOG(socket, "Moving to state FIN_WAIT1\n");
    socket->tcp_state =  TCP_STATE_FIN_WAIT1;   
    pthread_mutex_unlock(&socket->mutex);
}

int
tcp_is_established (tcp_socket *socket)
{
    int                         established = 0;

    pthread_mutex_lock(&socket->mutex);
    established = (socket->tcp_state == TCP_STATE_ESTABLISHED);
    pthread_mutex_unlock(&socket->mutex);

    return (established);
}

int
tcp_is_closed (tcp_socket *socket)
{
    int                         established = 0;

    pthread_mutex_lock(&socket->mutex);
    established = (socket->tcp_state == TCP_STATE_CLOSED);
    pthread_mutex_unlock(&socket->mutex);

    return (established);
}

tcp_socket *
tcp_create_est_socket (uint32_t saddr, uint32_t daddr,
                       uint16_t sport, uint16_t dport,
                       int server)
{
    tcp_states                  state = TCP_STATE_ESTABLISHED;
                      
    if (server) {
        return (sock_tcp_listen_state(saddr, daddr, sport, dport, state));
    } else {
        return (sock_tcp_connect_state(saddr, daddr, sport, dport, state));
    }

    return (NULL);
}

