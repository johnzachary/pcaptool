/* -*- coding: utf-8 -*-
 *
 * Copyright 2012. All rights reserved.
 *
 * LICENSE
 *  <MIT License>
 *
 * AUTHORS
 *  John Zachary (johnzachary2@gmail.com)
 *
 * NAME
 *  pcaptool.h header file
 *
 * DESCRIPTION
 *  Header file for pcaptool and libpcaptool
 *
 */

#ifndef PCAPTOOL_H
#define PCAPTOOL_H


/* ----------------------------------------------------------------------
 * Pcaptool data types
 */

struct pcap_packet {
    size_t  id;
    const char  *source;
    cork_timestamp  ts;
    size_t  full_size;
    int  data_link;
    size_t  payload_size;
    const void  *payload;
};


const uint8_t  G_ETHERNET_SIZE = 8;

struct ethernet_packet {
    void  *header;
};

struct ipv4_packet {
    void  *header;
};

struct ipv6_packet {
    void  *header;
};

struct tcp_packet {
    void  *header;
};

struct udp_packet {
    void  *header;
};

struct icmp_packet {
    void  *header;
};

struct data_packet {
    void  *header;
};



#endif /* PCAPTOOL_H */
