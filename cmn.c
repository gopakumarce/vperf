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

#include "cmn.h"

typedef struct {
   uint32_t         saddr;
   uint32_t         daddr;
   uint8_t          zero;
   uint8_t          proto;
   uint16_t         len;
} __attribute__ ((packed)) tcp_cksumhdr;

uint16_t
ip_cksum (const void *data, int dlen, uint16_t start)
{
    uint32_t                        cksum;
    uint16_t                        *bits16;

    cksum = start;
    bits16 = (uint16_t *)data;

    while (dlen > 1) {
        cksum += *bits16++;
        dlen -= 2;
    }

    if (dlen == 1) {
        cksum += htons(*(uint8_t *)bits16 << 8);
    }

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return ((uint16_t)~cksum);
}

uint16_t
tcp_cksum (uint32_t saddr, uint32_t daddr, int len, struct tcphdr *tcp)
{
    uint16_t                        hdrcsum;
    uint16_t                        csum;
    tcp_cksumhdr                    hdr;

    hdr.saddr = saddr;
    hdr.daddr = daddr;
    hdr.zero = 0;
    hdr.proto = 6;
    hdr.len = htons(len);
    hdrcsum = ip_cksum(&hdr, sizeof(hdr), 0);

    csum = ip_cksum(tcp, len, hdrcsum);

    return (csum);
}

uint64_t
get_time_ns (void)
{
    struct timespec                 ts;
    uint64_t                        cur_time = 0;

    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
    cur_time = ts.tv_sec;
    cur_time *= (1000 * 1000);
    cur_time *= 1000;
    cur_time += (ts.tv_nsec);

    return cur_time;
}

