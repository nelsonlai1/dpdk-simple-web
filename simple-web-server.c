/* simple-web-server: Simple WEB Server using DPDK
   james@ustc.edu.cn 2018.01.03

*/

/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2015 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdint.h>
#include <signal.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_byteorder.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_arp.h>
#include <rte_icmp.h>
#include <rte_ip.h>
#include <rte_tcp.h>

#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

#define NUM_MBUFS 	8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 	32

#define TCPMSS 1200
#define MAXIPLEN 64000

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10

#define TTL 64

//#define DEBUGPACKET
//#define DEBUGARP
//#define DEBUGICMP
#define DEBUGTCP

#define USINGHWCKSUM

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {.max_rx_pkt_len = ETHER_MAX_LEN},
	.txmode = {.mq_mode = ETH_MQ_TX_NONE},
};

struct rte_mempool *mbuf_pool;	// ?? for multicore

struct ether_addr my_eth_addr;	// My ethernet address
uint32_t my_ip;			// My IP Address in network order
uint8_t my_ipv6[16];		// My IPv6 Address in network order
uint8_t my_ipv6_m[16];		// My node multicast address
uint16_t tcp_port;		// listen tcp port in network order
int hardware_cksum = 0;
int hardware_cksum_v6 = 0;
int has_ipv6 = 0;

volatile int got_signal = 0;
#define STATS_PKTS 100000

uint64_t recv_pkts = 0;
uint64_t process_pkts = 0;
uint64_t drop_pkts = 0;
uint64_t recv_arp_pkts = 0;
uint64_t send_arp_pkts = 0;
uint64_t recv_icmp_pkts = 0;
uint64_t send_icmp_pkts = 0;
uint64_t recv_tcp_syn_pkts = 0;
uint64_t recv_tcp_data_pkts = 0;
uint64_t send_tcp_data_pkts = 0;
uint64_t send_tcp_data_multi_pkts = 0;
uint64_t recv_tcp_fin_pkts = 0;

uint64_t recv_icmpv6_pkts = 0;
uint64_t send_icmpv6_pkts = 0;
uint64_t recv_tcpv6_syn_pkts = 0;
uint64_t recv_tcpv6_data_pkts = 0;
uint64_t send_tcpv6_data_pkts = 0;
uint64_t recv_tcpv6_fin_pkts = 0;

void sig_handler_hup(int signo);
void sig_handler_hup(int signo __attribute__ ((unused)))
{
	got_signal = 1;
}

void print_stats(void);
void print_stats(void)
{
	printf("%s\n", "--------------------");
	printf("Ether Packets recevied: %ld processed: %ld dropped: %ld\n",
	       recv_pkts, process_pkts, drop_pkts);
	printf("ARP Packets recevied: %ld send: %ld\n", recv_arp_pkts, send_arp_pkts);
	printf("ICMP Packets recevied: %ld send: %ld\n", recv_icmp_pkts, send_icmp_pkts);
	printf("TCP Packets SYN: %ld, FIN: %ld, DATA: %ld/%ld/%ld\n",
	       recv_tcp_syn_pkts, recv_tcp_fin_pkts, recv_tcp_data_pkts, send_tcp_data_pkts,
	       send_tcp_data_multi_pkts);
	if (has_ipv6) {
		printf("ICMPv6 Packets recevied: %ld send: %ld\n",
		       recv_icmpv6_pkts, send_icmpv6_pkts);
		printf("TCPv6 Packets SYN: %ld, FIN: %ld, DATA: %ld/%ld\n",
		       recv_tcpv6_syn_pkts, recv_tcpv6_fin_pkts,
		       recv_tcpv6_data_pkts, send_tcpv6_data_pkts);
	}
	got_signal = 0;
}

static inline int user_init_func(int, char *[]);
static inline char *INET_NTOA(uint32_t ip);
static inline void swap_2bytes(unsigned char *a, unsigned char *b);
static inline void swap_4bytes(unsigned char *a, unsigned char *b);
static inline void swap_6bytes(unsigned char *a, unsigned char *b);
static inline void swap_16bytes(unsigned char *a, unsigned char *b);
static inline void dump_packet(unsigned char *buf, int len);
static inline void dump_arp_packet(struct ether_hdr *eh);
static inline int process_arp(struct rte_mbuf *mbuf, struct ether_hdr *eh, int len);
static inline int process_icmp(struct rte_mbuf *mbuf, struct ether_hdr *eh, struct ipv4_hdr *iph,
			       int ipv4_hdrlen, int len);
static inline int process_tcp(struct rte_mbuf *mbuf, struct ether_hdr *eh, struct ipv4_hdr *iph,
			      int ipv4_hdrlen, int len);
static inline int process_http(int ip_version, void *iph, struct tcp_hdr *tcph,
			       unsigned char *http_req, int req_len, unsigned char *http_resp,
			       int *resp_len, int *resp_in_req);

static inline char *INET_NTOA(uint32_t ip)	// ip in network order
{
	static char buf[100];
	sprintf(buf, "%d.%d.%d.%d", (int)(ip & 0xff), (int)((ip >> 8) & 0xff),
		(int)((ip >> 16) & 0xff), (int)((ip >> 24) & 0xff));
	return buf;
}

static inline void swap_2bytes(unsigned char *a, unsigned char *b)
{
	uint16_t t;
	t = *((uint16_t *) a);
	*((uint16_t *) a) = *((uint16_t *) b);
	*((uint16_t *) b) = t;
}

static inline void swap_4bytes(unsigned char *a, unsigned char *b)
{
	uint32_t t;
	t = *((uint32_t *) a);
	*((uint32_t *) a) = *((uint32_t *) b);
	*((uint32_t *) b) = t;
}

static inline void swap_6bytes(unsigned char *a, unsigned char *b)
{
	swap_4bytes(a, b);
	swap_2bytes(a + 4, b + 4);
}

static inline void swap_16bytes(unsigned char *a, unsigned char *b)
{
	swap_4bytes(a, b);
	swap_4bytes(a + 4, b + 4);
	swap_4bytes(a + 8, b + 8);
	swap_4bytes(a + 12, b + 12);
}

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;

	if (port >= rte_eth_dev_count())
		return -1;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval =
		    rte_eth_rx_queue_setup(port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL,
					   mbuf_pool);
		if (retval < 0)
			return retval;
	}

	struct rte_eth_dev_info dev_info;
	rte_eth_dev_info_get(port, &dev_info);
	if (dev_info.rx_offload_capa & DEV_RX_OFFLOAD_IPV4_CKSUM)
		printf("RX IPv4 checksum: support\n");
	if (dev_info.rx_offload_capa & DEV_RX_OFFLOAD_TCP_CKSUM)
		printf("RX TCP  checksum: support\n");
/*
	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_IPV6_CKSUM)
		printf("TX IPv6 checksum: support\n");
*/
	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_IPV4_CKSUM)
		printf("TX IPv4 checksum: support\n");
	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_TCP_CKSUM)
		printf("TX TCP  checksum: support\n");
#ifdef USINGHWCKSUM
	if ((dev_info.tx_offload_capa & DEV_TX_OFFLOAD_TCP_CKSUM)
	    && (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_IPV4_CKSUM)) {
		printf
		    ("TX IPv4/TCP checksum both supported, so I will use IPv4/IPv6 hardware checksum\n");
		hardware_cksum = 1;
		hardware_cksum_v6 = 1;
	} else
#endif
		printf("I will not use hardware checksum\n");

	/* Dsiable features that are not supported by port's HW */
	if (!(dev_info.tx_offload_capa & DEV_TX_OFFLOAD_TCP_CKSUM))
		dev_info.default_txconf.txq_flags |= ETH_TXQ_FLAGS_NOXSUMTCP;

	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval =
		    rte_eth_tx_queue_setup(port, q, nb_txd, rte_eth_dev_socket_id(port),
					   &dev_info.default_txconf);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct ether_addr addr;
	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
	       " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
	       port, addr.addr_bytes[0], addr.addr_bytes[1], addr.addr_bytes[2], addr.addr_bytes[3],
	       addr.addr_bytes[4], addr.addr_bytes[5]);

	my_eth_addr = addr;
	/* Enable RX in promiscuous mode for the Ethernet device. */
	// rte_eth_promiscuous_enable(port);

	rte_eth_allmulticast_enable(port);
	return 0;
}

static inline void dump_packet(unsigned char *buf, int len)
{
	printf("+++++++++++++++++++++++++++++++++++++++\n");
	printf("packet buf=%p len=%d\n", buf, len);
	int i, j;
	unsigned char c;
	for (i = 0; i < len; i++) {
		printf("%02X", buf[i]);
		if (i % 16 == 7)
			printf("  ");
		if ((i % 16) == 15 || (i == len - 1)) {
			if (i % 16 < 7)
				printf("  ");
			for (j = 0; j < 15 - (i % 16); j++)
				printf("  ");
			printf(" | ");
			for (j = (i - (i % 16)); j <= i; j++) {
				c = buf[j];
				if ((c > 31) && (c < 127))
					printf("%c", c);
				else
					printf(".");
			}
			printf("\n");
		}
	}
}

static inline void dump_arp_packet(struct ether_hdr *eh)
{
	struct arp_hdr *ah;
	ah = (struct arp_hdr *)((unsigned char *)eh + ETHER_HDR_LEN);
	printf("+++++++++++++++++++++++++++++++++++++++\n");
	printf("ARP PACKET: %p \n", eh);
	printf("ETHER DST MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
	       eh->d_addr.addr_bytes[0], eh->d_addr.addr_bytes[1],
	       eh->d_addr.addr_bytes[2], eh->d_addr.addr_bytes[3], eh->d_addr.addr_bytes[4],
	       eh->d_addr.addr_bytes[5]);
	printf("ETHER SRC MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n", eh->s_addr.addr_bytes[0],
	       eh->s_addr.addr_bytes[1], eh->s_addr.addr_bytes[2], eh->s_addr.addr_bytes[3],
	       eh->s_addr.addr_bytes[4], eh->s_addr.addr_bytes[5]);
	printf("H/D TYPE : %x PROTO TYPE : %X \n", ah->arp_hrd, ah->arp_pro);
	printf("H/D LEN  : %x PROTO LEN  : %X \n", ah->arp_hln, ah->arp_pln);
	printf("OPERATION : %x \n", ah->arp_op);
	printf("SENDER MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
	       ah->arp_data.arp_sha.addr_bytes[0], ah->arp_data.arp_sha.addr_bytes[1],
	       ah->arp_data.arp_sha.addr_bytes[2], ah->arp_data.arp_sha.addr_bytes[3],
	       ah->arp_data.arp_sha.addr_bytes[4], ah->arp_data.arp_sha.addr_bytes[5]);
	printf("SENDER IP address : %d.%d.%d.%d\n",
	       ((unsigned)((unsigned char *)&(ah->arp_data.arp_sip))[0]),
	       ((unsigned)((unsigned char *)&(ah->arp_data.arp_sip))[1]),
	       ((unsigned)((unsigned char *)&(ah->arp_data.arp_sip))[2]),
	       ((unsigned)((unsigned char *)&(ah->arp_data.arp_sip))[3]));
	printf("TARGET MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
	       ah->arp_data.arp_tha.addr_bytes[0], ah->arp_data.arp_tha.addr_bytes[1],
	       ah->arp_data.arp_tha.addr_bytes[2], ah->arp_data.arp_tha.addr_bytes[3],
	       ah->arp_data.arp_tha.addr_bytes[4], ah->arp_data.arp_tha.addr_bytes[5]);
	printf("TARGET IP address : %d.%d.%d.%d\n",
	       ((unsigned)((unsigned char *)&(ah->arp_data.arp_tip))[0]),
	       ((unsigned)((unsigned char *)&(ah->arp_data.arp_tip))[1]),
	       ((unsigned)((unsigned char *)&(ah->arp_data.arp_tip))[2]),
	       ((unsigned)((unsigned char *)&(ah->arp_data.arp_tip))[3]));
}

static inline int process_arp(struct rte_mbuf *mbuf, struct ether_hdr *eh, int len)
{
	struct arp_hdr *ah = (struct arp_hdr *)((unsigned char *)eh + ETHER_HDR_LEN);
#ifdef DEBUGARP
	dump_arp_packet(eh);
#endif
	recv_arp_pkts++;
	if (len < (int)(sizeof(struct ether_hdr) + sizeof(struct arp_hdr))) {
#ifdef DEBUGICMP
		printf("len = %d is too small for arp packet??\n", len);
#endif
		return 0;
	}
	if (rte_cpu_to_be_16(ah->arp_op) != ARP_OP_REQUEST) {	// ARP request
		return 0;
	}
	if (my_ip == ah->arp_data.arp_tip) {
#ifdef DEBUGARP
		printf("ARP asking me....\n");
#endif
		rte_memcpy((unsigned char *)&eh->d_addr, (unsigned char *)&eh->s_addr, 6);
		rte_memcpy((unsigned char *)&eh->s_addr, (unsigned char *)&my_eth_addr, 6);
		ah->arp_op = rte_cpu_to_be_16(ARP_OP_REPLY);
		ah->arp_data.arp_tha = ah->arp_data.arp_sha;
		rte_memcpy((unsigned char *)&ah->arp_data.arp_sha, (unsigned char *)&my_eth_addr,
			   6);
		ah->arp_data.arp_tip = ah->arp_data.arp_sip;
		ah->arp_data.arp_sip = my_ip;
#ifdef DEBUGARP
		printf("I will reply following \n");
		dump_arp_packet(eh);
#endif
		if (likely(1 == rte_eth_tx_burst(0, 0, &mbuf, 1))) {
			send_arp_pkts++;
			return 1;
		}
	}
	return 0;
}

static inline int process_icmp(struct rte_mbuf *mbuf, struct ether_hdr *eh, struct ipv4_hdr *iph,
			       int ipv4_hdrlen, int len)
{
	struct icmp_hdr *icmph = (struct icmp_hdr *)((unsigned char *)(iph) + ipv4_hdrlen);
#ifdef DEBUGICMP
	printf("icmp type=%d, code=%d\n", icmph->icmp_type, icmph->icmp_code);
#endif
	recv_icmp_pkts++;
	if (len < (int)(sizeof(struct ether_hdr) + sizeof(struct icmp_hdr))) {
#ifdef DEBUGICMP
		printf("len = %d is too small for icmp packet??\n", len);
#endif
		return 0;
	}
	if ((icmph->icmp_type == IP_ICMP_ECHO_REQUEST) && (icmph->icmp_code == 0)) {	// ICMP echo req
		rte_memcpy((unsigned char *)&eh->d_addr, (unsigned char *)&eh->s_addr, 6);
		rte_memcpy((unsigned char *)&eh->s_addr, (unsigned char *)&my_eth_addr, 6);
		iph->dst_addr = iph->src_addr;
		iph->src_addr = my_ip;
		iph->time_to_live = TTL;
		iph->hdr_checksum = 0;
		iph->hdr_checksum = rte_ipv4_cksum(iph);
		icmph->icmp_type = IP_ICMP_ECHO_REPLY;
		icmph->icmp_cksum = 0;
		icmph->icmp_cksum = ~rte_raw_cksum(icmph, len - ETHER_HDR_LEN - ipv4_hdrlen);
#ifdef DEBUGICMP
		printf("I will send reply\n");
		dump_packet(rte_pktmbuf_mtod(mbuf, unsigned char *), len);
#endif
		int ret = rte_eth_tx_burst(0, 0, &mbuf, 1);
		if (ret == 1) {
			send_icmp_pkts++;
			return 1;
		}
		printf("send icmp packet ret = %d\n", ret);
	}
	return 0;
}

static inline int process_icmpv6(struct rte_mbuf *mbuf, struct ether_hdr *eh, struct ipv6_hdr *ip6h,
				 int len)
{
	struct icmp_hdr *icmph =
	    (struct icmp_hdr *)((unsigned char *)(ip6h) + sizeof(struct ipv6_hdr));
#ifdef DEBUGICMP
	printf("icmp type=%d, code=%d\n", icmph->icmp_type, icmph->icmp_code);
#endif
	recv_icmpv6_pkts++;
	if (len <
	    (int)(sizeof(struct ether_hdr) + sizeof(struct ipv6_hdr) + sizeof(struct icmp_hdr))) {
#ifdef DEBUGICMP
		printf("len = %d is too small for icmp packet??\n", len);
#endif
		return 0;
	}
	if ((icmph->icmp_type == 135) && (icmph->icmp_code == 0)) {	// ICMPv NS
		if (memcmp((unsigned char *)icmph + 8, my_ipv6, 16) != 0) {	// target is not me
#ifdef DEBUGICMP
			printf("it's not to me\n");
			int i = 0;
			for (i = 0; i < 16; i++)
				printf("%02X ", *((unsigned char *)icmph + 8 + i));
			printf("\n");
#endif
			return 0;
		}
		*((unsigned char *)icmph + 4) = 0x60;	// ??? O+S bit
		rte_memcpy((unsigned char *)&eh->d_addr, (unsigned char *)&eh->s_addr, 6);
		rte_memcpy((unsigned char *)&eh->s_addr, (unsigned char *)&my_eth_addr, 6);
		rte_memcpy((unsigned char *)&ip6h->dst_addr, (unsigned char *)&ip6h->src_addr, 16);
		rte_memcpy((unsigned char *)&ip6h->src_addr, (unsigned char *)&my_ipv6, 16);
		ip6h->hop_limits = 255;
		icmph->icmp_type = 136;
		icmph->icmp_cksum = 0;
		*((unsigned char *)icmph + 24) = 2;	// dest-link options
		rte_memcpy((unsigned char *)icmph + 26, (unsigned char *)&my_eth_addr, 6);
		icmph->icmp_cksum = rte_ipv6_udptcp_cksum(ip6h, icmph);
#ifdef DEBUGICMP
		printf("I will send reply\n");
		dump_packet(rte_pktmbuf_mtod(mbuf, unsigned char *), len);
#endif
		int ret = rte_eth_tx_burst(0, 0, &mbuf, 1);
		if (ret == 1) {
			send_icmpv6_pkts++;
			return 1;
		}
		printf("send icmpv6 packet ret = %d\n", ret);

	} else if ((icmph->icmp_type == 128) && (icmph->icmp_code == 0)) {	// ICMPv6 echo req
		if (memcmp(ip6h->dst_addr, my_ipv6, 16) != 0)	// not to me
			return 0;
		rte_memcpy((unsigned char *)&eh->d_addr, (unsigned char *)&eh->s_addr, 6);
		rte_memcpy((unsigned char *)&eh->s_addr, (unsigned char *)&my_eth_addr, 6);
		swap_16bytes(ip6h->src_addr, ip6h->dst_addr);
		ip6h->hop_limits = 255;
		icmph->icmp_type = 129;
		icmph->icmp_cksum = 0;
		icmph->icmp_cksum = rte_ipv6_udptcp_cksum(ip6h, icmph);
#ifdef DEBUGICMP
		printf("I will send reply\n");
		dump_packet(rte_pktmbuf_mtod(mbuf, unsigned char *), len);
#endif
		int ret = rte_eth_tx_burst(0, 0, &mbuf, 1);
		if (ret == 1) {
			send_icmpv6_pkts++;
			return 1;
		}
		printf("send icmpv6 packet ret = %d\n", ret);
	}
	return 0;
}

static inline int process_tcp(struct rte_mbuf *mbuf, struct ether_hdr *eh, struct ipv4_hdr *iph,
			      int ipv4_hdrlen, int len)
{
	struct tcp_hdr *tcph = (struct tcp_hdr *)((unsigned char *)(iph) + ipv4_hdrlen);
	int pkt_len;
#ifdef DEBUGTCP
	printf("TCP packet, dport=%d\n", rte_be_to_cpu_16(tcph->dst_port));
	printf("TCP flags=%d\n", tcph->tcp_flags);
#endif
	if (len < (int)(sizeof(struct ether_hdr) + ipv4_hdrlen + sizeof(struct tcp_hdr))) {
#ifdef DEBUGICMP
		printf("len = %d is too small for tcp packet??\n", len);
#endif
		return 0;
	}
	if (tcph->dst_port != tcp_port)
		return 0;

	if ((tcph->tcp_flags & (TCP_SYN | TCP_ACK)) == TCP_SYN) {	// SYN packet, send SYN+ACK
#ifdef DEBUGTCP
		printf("SYN packet\n");
#endif
		recv_tcp_syn_pkts++;
		swap_6bytes((unsigned char *)&eh->s_addr, (unsigned char *)&eh->d_addr);
		swap_4bytes((unsigned char *)&iph->src_addr, (unsigned char *)&iph->dst_addr);
		swap_2bytes((unsigned char *)&tcph->src_port, (unsigned char *)&tcph->dst_port);
		tcph->tcp_flags = TCP_ACK | TCP_SYN;
		tcph->recv_ack = rte_cpu_to_be_32(rte_be_to_cpu_32(tcph->sent_seq) + 1);
		tcph->sent_seq = rte_cpu_to_be_32(1);
		tcph->data_off = (sizeof(struct tcp_hdr) / 4) << 4;
		tcph->cksum = 0;
		pkt_len = ipv4_hdrlen + sizeof(struct tcp_hdr);
		iph->total_length = rte_cpu_to_be_16(pkt_len);
		iph->hdr_checksum = 0;
		iph->time_to_live = TTL;
		rte_pktmbuf_data_len(mbuf) = pkt_len + ETHER_HDR_LEN;
		if (hardware_cksum) {
			// printf("ol_flags=%ld\n",mbuf->ol_flags);
			mbuf->ol_flags = PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_TCP_CKSUM;
			mbuf->l2_len = ETHER_HDR_LEN;
			mbuf->l3_len = ipv4_hdrlen;
			mbuf->l4_len = 0;
			tcph->cksum = rte_ipv4_phdr_cksum((const struct ipv4_hdr *)iph, 0);
		} else {
			tcph->cksum = rte_ipv4_udptcp_cksum(iph, tcph);
			iph->hdr_checksum = rte_ipv4_cksum(iph);
		}
#ifdef DEBUGTCP
		printf("I will reply following:\n");
		dump_packet((unsigned char *)eh, rte_pktmbuf_data_len(mbuf));
#endif
		int ret = rte_eth_tx_burst(0, 0, &mbuf, 1);
		if (ret == 1)
			return 1;
#ifdef DEBUGTCP
		printf("send tcp packet return %d\n", ret);
#endif
		return 0;
	} else if (tcph->tcp_flags & TCP_FIN) {	// FIN packet, send ACK
#ifdef DEBUGTCP
		fprintf(stderr, "FIN packet\n");
#endif
		recv_tcp_fin_pkts++;
		swap_6bytes((unsigned char *)&eh->s_addr, (unsigned char *)&eh->d_addr);
		swap_4bytes((unsigned char *)&iph->src_addr, (unsigned char *)&iph->dst_addr);
		swap_2bytes((unsigned char *)&tcph->src_port, (unsigned char *)&tcph->dst_port);
		swap_4bytes((unsigned char *)&tcph->sent_seq, (unsigned char *)&tcph->recv_ack);
		tcph->tcp_flags = TCP_ACK;
		tcph->recv_ack = rte_cpu_to_be_32(rte_be_to_cpu_32(tcph->recv_ack) + 1);
		tcph->data_off = (sizeof(struct tcp_hdr) / 4) << 4;
		tcph->cksum = 0;
		pkt_len = ipv4_hdrlen + sizeof(struct tcp_hdr);
		iph->total_length = rte_cpu_to_be_16(pkt_len);
		iph->hdr_checksum = 0;
		iph->time_to_live = TTL;
		rte_pktmbuf_data_len(mbuf) = pkt_len + ETHER_HDR_LEN;
		if (hardware_cksum) {
			// printf("ol_flags=%ld\n",mbuf->ol_flags);
			mbuf->ol_flags = PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_TCP_CKSUM;
			mbuf->l2_len = ETHER_HDR_LEN;
			mbuf->l3_len = ipv4_hdrlen;
			mbuf->l4_len = 0;
			tcph->cksum = rte_ipv4_phdr_cksum((const struct ipv4_hdr *)iph, 0);
		} else {
			tcph->cksum = rte_ipv4_udptcp_cksum(iph, tcph);
			iph->hdr_checksum = rte_ipv4_cksum(iph);
		}
#ifdef DEBUGTCP
		printf("I will reply following:\n");
		dump_packet((unsigned char *)eh, rte_pktmbuf_data_len(mbuf));
#endif
		int ret = rte_eth_tx_burst(0, 0, &mbuf, 1);
		if (ret == 1)
			return 1;
#ifdef DEBUGTCP
		fprintf(stderr, "send tcp packet return %d\n", ret);
#endif
		return 0;
	} else if ((tcph->tcp_flags & (TCP_SYN | TCP_ACK)) == TCP_ACK) {	// ACK packet, send DATA
		pkt_len = rte_be_to_cpu_16(iph->total_length);
		int tcp_payload_len = pkt_len - ipv4_hdrlen - (tcph->data_off >> 4) * 4;
		int ntcp_payload_len = MAXIPLEN;
		unsigned char *tcp_payload;
		unsigned char buf[MAXIPLEN + sizeof(struct tcp_hdr)];	// http_response
		int resp_in_req = 0;
		recv_tcp_data_pkts++;

#ifdef DEBUGTCP
		printf("ACK pkt len=%d(inc ether) ip len=%d\n", rte_pktmbuf_data_len(mbuf),
		       pkt_len);
		printf("tcp payload len=%d\n", tcp_payload_len);
#endif
		if (tcp_payload_len <= 5) {
#ifdef DEBUGTCP
			printf("tcp payload len=%d too small, ignore\n", tcp_payload_len);
#endif
			return 0;
		}
		tcp_payload = (unsigned char *)iph + ipv4_hdrlen + (tcph->data_off >> 4) * 4;
		if (process_http
		    (4, iph, tcph, tcp_payload, tcp_payload_len, buf + sizeof(struct tcp_hdr),
		     &ntcp_payload_len, &resp_in_req)
		    == 0)
			return 0;
#ifdef DEBUGTCP
		printf("http return new payload len=%d\n", ntcp_payload_len);
#endif
		uint32_t ack_seq =
		    rte_cpu_to_be_32(rte_be_to_cpu_32(tcph->sent_seq) + tcp_payload_len);
		swap_6bytes((unsigned char *)&eh->s_addr, (unsigned char *)&eh->d_addr);
		swap_4bytes((unsigned char *)&iph->src_addr, (unsigned char *)&iph->dst_addr);
		swap_2bytes((unsigned char *)&tcph->src_port, (unsigned char *)&tcph->dst_port);
		tcph->tcp_flags = TCP_ACK | TCP_PSH | TCP_FIN;
		tcph->sent_seq = tcph->recv_ack;
		tcph->recv_ack = ack_seq;
		tcph->cksum = 0;
		iph->hdr_checksum = 0;
		iph->time_to_live = TTL;

		if (ntcp_payload_len <= TCPMSS) {	// tcp packet fit in one IP packet
			if (!resp_in_req)
				rte_memcpy(tcp_payload, buf + sizeof(struct tcp_hdr),
					   ntcp_payload_len);
			pkt_len = ntcp_payload_len + ipv4_hdrlen + (tcph->data_off >> 4) * 4;
			iph->total_length = rte_cpu_to_be_16(pkt_len);
			iph->fragment_offset = 0;
#ifdef DEBUGTCP
			fprintf(stderr, "new pkt len=%d\n", pkt_len);
#endif
			rte_pktmbuf_data_len(mbuf) = pkt_len + ETHER_HDR_LEN;
			if (hardware_cksum) {
				// printf("ol_flags=%ld\n",mbuf->ol_flags);
				mbuf->ol_flags = PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_TCP_CKSUM;
				mbuf->l2_len = ETHER_HDR_LEN;
				mbuf->l3_len = ipv4_hdrlen;
				mbuf->l4_len = ntcp_payload_len;
				tcph->cksum = rte_ipv4_phdr_cksum((const struct ipv4_hdr *)iph, 0);
			} else {
				tcph->cksum = rte_ipv4_udptcp_cksum(iph, tcph);
				iph->hdr_checksum = rte_ipv4_cksum(iph);
			}
#ifdef DEBUGTCP
			printf("I will reply following:\n");
			dump_packet((unsigned char *)eh, rte_pktmbuf_data_len(mbuf));
#endif
			int ret = rte_eth_tx_burst(0, 0, &mbuf, 1);
			if (ret == 1) {
				send_tcp_data_pkts++;
				return 1;
			}
#ifdef DEBUGTCP
			fprintf(stderr, "send tcp packet return %d\n", ret);
#endif
			return 0;
		} else {	// tcp packet could not fit in one IP packet, I will send one by one
			struct rte_mbuf *frag;
			struct ether_hdr *neh;
			struct ipv4_hdr *niph;
			struct tcp_hdr *ntcph;
			int left = ntcp_payload_len + sizeof(struct tcp_hdr);
			uint32_t offset = 0;
			if (resp_in_req) {
				printf("BIG TCP packet, must returned in my buf\n");
				return 0;
			}
			iph->total_length = rte_cpu_to_be_16(left + sizeof(struct ipv4_hdr));
			iph->fragment_offset = 0;
			iph->packet_id = tcph->dst_port;
			tcph->data_off = (sizeof(struct tcp_hdr) / 4) << 4;
			ntcph = (struct tcp_hdr *)buf;
			rte_memcpy(ntcph, tcph, sizeof(struct tcp_hdr));	// copy tcp header to begin of buf
			ntcph->cksum = rte_ipv4_udptcp_cksum(iph, ntcph);	// trick but works, now eth/ip header in mbuf, tcp packet in buf
			while (left > 0) {
				len = left < TCPMSS ? left : (TCPMSS & 0xfff0);
				left -= len;
#ifdef DEBUGTCP
				printf("offset=%d len=%d\n", offset, len);
#endif
				frag = rte_pktmbuf_alloc(mbuf_pool);
				if (!frag) {
					printf("mutli packet alloc error\n");
					return 0;
				}
				neh = rte_pktmbuf_mtod(frag, struct ether_hdr *);
				rte_memcpy(neh, eh, ETHER_HDR_LEN + sizeof(struct ipv4_hdr));	// copy eth/ip header
				niph = (struct ipv4_hdr *)((unsigned char *)(neh) + ETHER_HDR_LEN);
				ntcph =
				    (struct tcp_hdr *)((unsigned char *)(niph) +
						       sizeof(struct ipv4_hdr));
				rte_memcpy(ntcph, buf + offset, len);

				pkt_len = len + sizeof(struct ipv4_hdr);
				niph->total_length = rte_cpu_to_be_16(pkt_len);
				niph->fragment_offset = rte_cpu_to_be_16(offset >> 3);
				if (left > 0)
					niph->fragment_offset |= rte_cpu_to_be_16(IPV4_HDR_MF_FLAG);
#ifdef DEBUGTCP
				fprintf(stderr, "frag offset %d, pkt len=%d\n", offset, pkt_len);
#endif
				rte_pktmbuf_data_len(frag) = pkt_len + ETHER_HDR_LEN;
				if (hardware_cksum) {
					printf("ol_flags=%ld\n", frag->ol_flags);
					frag->ol_flags = PKT_TX_IPV4 | PKT_TX_IP_CKSUM;
					frag->l2_len = ETHER_HDR_LEN;
					frag->l3_len = sizeof(struct ipv4_hdr);
					frag->l4_len = len;
				} else
					niph->hdr_checksum = rte_ipv4_cksum(niph);

#ifdef DEBUGTCP
//                              printf("I will reply following:\n");
//                              dump_packet((unsigned char *)neh, rte_pktmbuf_data_len(frag));
#endif
				int ret = rte_eth_tx_burst(0, 0, &frag, 1);
				if (ret != 1) {
#ifdef DEBUGTCP
					fprintf(stderr, "send tcp packet return %d\n", ret);
#endif
					rte_pktmbuf_free(frag);
					return 0;
				}
				send_tcp_data_multi_pkts++;
				offset += len;
			}
			rte_pktmbuf_free(mbuf);
			return 1;
		}
	}
	return 0;
}

static inline int process_tcpv6(struct rte_mbuf *mbuf, struct ether_hdr *eh, struct ipv6_hdr *ip6h,
				int len)
{
	struct tcp_hdr *tcph =
	    (struct tcp_hdr *)((unsigned char *)(ip6h) + sizeof(struct ipv6_hdr));
	int payload_len;
#ifdef DEBUGTCP
	printf("TCP packet, dport=%d\n", rte_be_to_cpu_16(tcph->dst_port));
	printf("TCP flags=%d\n", tcph->tcp_flags);
#endif
	if (len <
	    (int)(sizeof(struct ether_hdr) + sizeof(struct ipv6_hdr) + sizeof(struct tcp_hdr))) {
#ifdef DEBUGICMP
		printf("len = %d is too small for tcp packet??\n", len);
#endif
		return 0;
	}
	if (tcph->dst_port != tcp_port)
		return 0;

	if ((tcph->tcp_flags & (TCP_SYN | TCP_ACK)) == TCP_SYN) {	// SYN packet, send SYN+ACK
#ifdef DEBUGTCP
		printf("SYN packet\n");
#endif
		recv_tcpv6_syn_pkts++;
		swap_6bytes((unsigned char *)&eh->s_addr, (unsigned char *)&eh->d_addr);
		swap_16bytes((unsigned char *)&ip6h->src_addr, (unsigned char *)&ip6h->dst_addr);
		swap_2bytes((unsigned char *)&tcph->src_port, (unsigned char *)&tcph->dst_port);
		tcph->tcp_flags = TCP_ACK | TCP_SYN;
		tcph->recv_ack = rte_cpu_to_be_32(rte_be_to_cpu_32(tcph->sent_seq) + 1);
		tcph->sent_seq = rte_cpu_to_be_32(1);
		tcph->data_off = (sizeof(struct tcp_hdr) / 4) << 4;
		tcph->cksum = 0;
		payload_len = sizeof(struct tcp_hdr);
		ip6h->payload_len = rte_cpu_to_be_16(payload_len);
		ip6h->hop_limits = TTL;
		rte_pktmbuf_data_len(mbuf) = payload_len + sizeof(struct ipv6_hdr) + ETHER_HDR_LEN;
		if (hardware_cksum_v6) {
			// printf("ol_flags=%ld\n",mbuf->ol_flags);
			mbuf->ol_flags = PKT_TX_IPV6 | PKT_TX_TCP_CKSUM;
			mbuf->l2_len = sizeof(struct ether_hdr);
			mbuf->l3_len = sizeof(struct ipv6_hdr);
			mbuf->l4_len = sizeof(struct tcp_hdr);
			tcph->cksum = rte_ipv6_phdr_cksum((const struct ipv6_hdr *)ip6h, 0);
		} else {
			tcph->cksum = rte_ipv6_udptcp_cksum(ip6h, tcph);
		}
#ifdef DEBUGTCP
		printf("I will reply following:\n");
		dump_packet((unsigned char *)eh, rte_pktmbuf_data_len(mbuf));
#endif
		int ret = rte_eth_tx_burst(0, 0, &mbuf, 1);
		if (ret == 1)
			return 1;
#ifdef DEBUGTCP
		printf("send tcp packet return %d\n", ret);
#endif
		return 0;
	} else if (tcph->tcp_flags & TCP_FIN) {	// FIN packet, send ACK
#ifdef DEBUGTCP
		fprintf(stderr, "FIN packet\n");
#endif
		recv_tcpv6_fin_pkts++;
		swap_6bytes((unsigned char *)&eh->s_addr, (unsigned char *)&eh->d_addr);
		swap_16bytes((unsigned char *)&ip6h->src_addr, (unsigned char *)&ip6h->dst_addr);
		swap_2bytes((unsigned char *)&tcph->src_port, (unsigned char *)&tcph->dst_port);
		swap_4bytes((unsigned char *)&tcph->sent_seq, (unsigned char *)&tcph->recv_ack);
		tcph->tcp_flags = TCP_ACK;
		tcph->recv_ack = rte_cpu_to_be_32(rte_be_to_cpu_32(tcph->recv_ack) + 1);
		tcph->data_off = (sizeof(struct tcp_hdr) / 4) << 4;
		tcph->cksum = 0;
		payload_len = sizeof(struct tcp_hdr);
		ip6h->payload_len = rte_cpu_to_be_16(payload_len);
		ip6h->hop_limits = TTL;
		rte_pktmbuf_data_len(mbuf) = payload_len + sizeof(struct ipv6_hdr) + ETHER_HDR_LEN;
		if (hardware_cksum_v6) {
			// printf("ol_flags=%ld\n",mbuf->ol_flags);
			mbuf->ol_flags = PKT_TX_IPV6 | PKT_TX_TCP_CKSUM;
			mbuf->l2_len = sizeof(struct ether_hdr);
			mbuf->l3_len = sizeof(struct ipv6_hdr);
			mbuf->l4_len = sizeof(struct tcp_hdr);
			tcph->cksum = rte_ipv6_phdr_cksum((const struct ipv6_hdr *)ip6h, 0);
		} else {
			tcph->cksum = rte_ipv6_udptcp_cksum(ip6h, tcph);
		}
#ifdef DEBUGTCP
		printf("I will reply following:\n");
		dump_packet((unsigned char *)eh, rte_pktmbuf_data_len(mbuf));
#endif
		int ret = rte_eth_tx_burst(0, 0, &mbuf, 1);
		if (ret == 1)
			return 1;
#ifdef DEBUGTCP
		fprintf(stderr, "send tcp packet return %d\n", ret);
#endif
		return 0;
	} else if ((tcph->tcp_flags & (TCP_SYN | TCP_ACK)) == TCP_ACK) {	// ACK packet, send DATA
		payload_len = rte_be_to_cpu_16(ip6h->payload_len);
		int tcp_payload_len = payload_len - (tcph->data_off >> 4) * 4;
		int ntcp_payload_len = MAXIPLEN;
		unsigned char *tcp_payload;
		unsigned char buf[MAXIPLEN];	// http_respone
		int resp_in_req = 0;
		recv_tcpv6_data_pkts++;

#ifdef DEBUGTCP
		printf("ACK pkt len=%d(inc ether) ip len=%d\n", rte_pktmbuf_data_len(mbuf),
		       payload_len);
		printf("tcp payload len=%d\n", tcp_payload_len);
#endif
		if (tcp_payload_len <= 5) {
#ifdef DEBUGTCP
			printf("tcp payload len=%d too small, ignore\n", tcp_payload_len);
#endif
			return 0;
		}
		tcp_payload = (unsigned char *)tcph + (tcph->data_off >> 4) * 4;
		if (process_http
		    (6, ip6h, tcph, tcp_payload, tcp_payload_len, buf, &ntcp_payload_len,
		     &resp_in_req)
		    == 0)
			return 0;
#ifdef DEBUGTCP
		printf("new payload len=%d :%s:\n", ntcp_payload_len, buf);
#endif
		uint32_t ack_seq =
		    rte_cpu_to_be_32(rte_be_to_cpu_32(tcph->sent_seq) + tcp_payload_len);
		swap_6bytes((unsigned char *)&eh->s_addr, (unsigned char *)&eh->d_addr);
		swap_16bytes((unsigned char *)&ip6h->src_addr, (unsigned char *)&ip6h->dst_addr);
		swap_2bytes((unsigned char *)&tcph->src_port, (unsigned char *)&tcph->dst_port);
		tcph->tcp_flags = TCP_ACK | TCP_PSH | TCP_FIN;
		tcph->sent_seq = tcph->recv_ack;
		tcph->recv_ack = ack_seq;
		tcph->cksum = 0;
		ip6h->hop_limits = TTL;

		if (ntcp_payload_len <= TCPMSS) {	// tcp packet fit in one IP packet
			if (!resp_in_req)
				rte_memcpy(tcp_payload, buf, ntcp_payload_len);
			payload_len = ntcp_payload_len + (tcph->data_off >> 4) * 4;
			ip6h->payload_len = rte_cpu_to_be_16(payload_len);
#ifdef DEBUGTCP
			fprintf(stderr, "new payload len=%d\n", payload_len);
#endif
			rte_pktmbuf_data_len(mbuf) =
			    payload_len + sizeof(struct ipv6_hdr) + ETHER_HDR_LEN;
			if (hardware_cksum_v6) {
				// printf("ol_flags=%ld\n",mbuf->ol_flags);
				mbuf->ol_flags = PKT_TX_IPV6 | PKT_TX_TCP_CKSUM;
				mbuf->l2_len = sizeof(struct ether_hdr);
				mbuf->l3_len = sizeof(struct ipv6_hdr);
				mbuf->l4_len = sizeof(struct tcp_hdr) + ntcp_payload_len;
				tcph->cksum = rte_ipv6_phdr_cksum((const struct ipv6_hdr *)ip6h, 0);
			} else {
				tcph->cksum = rte_ipv6_udptcp_cksum(ip6h, tcph);
			}
#ifdef DEBUGTCP
			printf("I will reply following:\n");
			dump_packet((unsigned char *)eh, rte_pktmbuf_data_len(mbuf));
#endif
			int ret = rte_eth_tx_burst(0, 0, &mbuf, 1);
			if (ret == 1) {
				send_tcpv6_data_pkts++;
				return 1;
			}
#ifdef DEBUGTCP
			fprintf(stderr, "send tcp packet return %d\n", ret);
#endif
			return 0;
		} else {	// tcp packet could not fit in one IP packet, I will send one by one
			if (resp_in_req) {
				printf("BIG TCP packet, must returned in my buf\n");
				return 0;
			}
			uint32_t offset = 0;
			int left = ntcp_payload_len;
			uint32_t sent_seq = rte_be_to_cpu_32(tcph->sent_seq);
			while (left > 0) {
				struct rte_mbuf *frag;
				struct ether_hdr *neh;
				struct ipv6_hdr *nip6h;
				struct tcp_hdr *ntcph;
				len = left < TCPMSS ? left : TCPMSS;
				left -= len;
#ifdef DEBUGTCP
				printf("offset=%d len=%d\n", offset, len);
#endif
				frag = rte_pktmbuf_alloc(mbuf_pool);
				if (!frag) {
					printf("mutli packet alloc error\n");
					return 0;
				}
				neh = rte_pktmbuf_mtod(frag, struct ether_hdr *);
				rte_memcpy(neh, eh, ETHER_HDR_LEN + sizeof(struct ipv6_hdr) + (tcph->data_off >> 4) * 4);	// copy eth/ip/tcp header
				nip6h = (struct ipv6_hdr *)((unsigned char *)(neh) + ETHER_HDR_LEN);
				ntcph =
				    (struct tcp_hdr *)((unsigned char *)(nip6h) +
						       sizeof(struct ipv6_hdr));
				tcp_payload = (unsigned char *)ntcph + (tcph->data_off >> 4) * 4;
				rte_memcpy(tcp_payload, buf + offset, len);
				ntcph->sent_seq = rte_cpu_to_be_32(sent_seq + offset);	// header ok except sent_seq
				if (left > 0)
					ntcph->tcp_flags = TCP_ACK;
				else
					ntcph->tcp_flags = TCP_ACK | TCP_PSH | TCP_FIN;
				payload_len = len + (ntcph->data_off >> 4) * 4;
				nip6h->payload_len = rte_cpu_to_be_16(payload_len);
#ifdef DEBUGTCP
				fprintf(stderr, "new pkt len=%d\n", payload_len);
#endif
				rte_pktmbuf_data_len(frag) =
				    payload_len + sizeof(struct ipv6_hdr) + ETHER_HDR_LEN;
				if (hardware_cksum_v6) {
					frag->ol_flags = PKT_TX_IPV6 | PKT_TX_TCP_CKSUM;
					frag->l2_len = sizeof(struct ether_hdr);
					frag->l3_len = sizeof(struct ipv6_hdr);
					frag->l4_len = sizeof(struct tcp_hdr) + len;
					ntcph->cksum =
					    rte_ipv6_phdr_cksum((const struct ipv6_hdr *)nip6h, 0);
				} else {
					ntcph->cksum = rte_ipv6_udptcp_cksum(nip6h, ntcph);
				}
#ifdef DEBUGTCP
				printf("I will reply following:\n");
				dump_packet((unsigned char *)neh, rte_pktmbuf_data_len(frag));
#endif
				int ret = rte_eth_tx_burst(0, 0, &frag, 1);
				if (ret != 1) {
#ifdef DEBUGTCP
					fprintf(stderr, "send tcp packet return %d\n", ret);
#endif
					rte_pktmbuf_free(frag);
					return 0;
				}
				send_tcpv6_data_pkts++;
				offset += len;
			}
			rte_pktmbuf_free(mbuf);
			return 1;
		}
	}
	return 0;
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
static __attribute__ ((noreturn))
void lcore_main(void)
{
	const uint16_t nb_ports = rte_eth_dev_count();
	uint16_t port;

	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	for (port = 0; port < nb_ports; port++)
		if (rte_eth_dev_socket_id(port) > 0
		    && rte_eth_dev_socket_id(port) != (int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
			       "polling thread.\n\tPerformance will " "not be optimal.\n", port);

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n", rte_lcore_id());

	/* Run until the application is quit or killed. */
	for (;;) {
		/* Get burst of RX packets, from first port of pair. */
		int port = 0;
		int i;
		struct rte_mbuf *bufs[BURST_SIZE];
		const uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);
		if (unlikely(nb_rx == 0))
			continue;
#ifdef DEBUGPACKET
		printf("got %d packets\n", nb_rx);
#endif
		for (i = 0; i < nb_rx; i++) {
			int len = rte_pktmbuf_data_len(bufs[i]);
			struct ether_hdr *eh = rte_pktmbuf_mtod(bufs[i], struct ether_hdr *);
			recv_pkts++;
			if (recv_pkts % STATS_PKTS == 0)
				print_stats();
			if (got_signal)
				print_stats();
#ifdef DEBUGPACKET
			dump_packet((unsigned char *)eh, len);
			printf("ethernet proto=%4X\n", rte_cpu_to_be_16(eh->ether_type));
#endif
			if (eh->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4)) {	// IPv4 protocol
				struct ipv4_hdr *iph;
				iph = (struct ipv4_hdr *)((unsigned char *)(eh) + ETHER_HDR_LEN);
				int ipv4_hdrlen = (iph->version_ihl & IPV4_HDR_IHL_MASK) << 2;
#ifdef DEBUGPACKET
				printf("ver=%d, frag_off=%d, daddr=%s pro=%d\n",
				       (iph->version_ihl & 0xF0) >> 4,
				       rte_be_to_cpu_16(iph->fragment_offset) &
				       IPV4_HDR_OFFSET_MASK, INET_NTOA(iph->dst_addr),
				       iph->next_proto_id);
#endif
				if (((iph->version_ihl & 0xF0) == 0x40) && ((iph->fragment_offset & rte_cpu_to_be_16(IPV4_HDR_OFFSET_MASK)) == 0) && (iph->dst_addr == my_ip)) {	// ipv4
#ifdef DEBUGPACKET
					printf("ipv4 packet\n");
#endif
					if (iph->next_proto_id == 6) {	// TCP
						process_pkts++;
						if (process_tcp(bufs[i], eh, iph, ipv4_hdrlen, len))
							continue;
					} else if (iph->next_proto_id == 1) {	// ICMP
						process_pkts++;
						if (process_icmp
						    (bufs[i], eh, iph, ipv4_hdrlen, len))
							continue;
					}
				}
			} else if (eh->ether_type == rte_cpu_to_be_16(ETHER_TYPE_ARP)) {	// ARP protocol
				process_pkts++;
				if (process_arp(bufs[i], eh, len))
					continue;
			} else if ((has_ipv6) && (eh->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv6))) {	// IPv6 protocol
				struct ipv6_hdr *ip6h;
				int ver = 0;
				ip6h = (struct ipv6_hdr *)((unsigned char *)(eh) + ETHER_HDR_LEN);
				ver = (ip6h->vtc_flow & 0xF0) >> 4;
#ifdef DEBUGPACKET
				char h[100];
				inet_ntop(AF_INET6, ip6h->dst_addr, h, 100);
				printf("ver=%d, daddr=%s pro=%X\n", ver, h, ip6h->proto);
#endif
				if (ver == 6) {	// ipv6
#ifdef DEBUGPACKET
					printf("ipv6 packet\n");
#endif
					if (ip6h->proto == 6) {	// TCP
						process_pkts++;
						if (process_tcpv6(bufs[i], eh, ip6h, len))
							continue;
					} else if (ip6h->proto == 0x3a) {	// ICMPv6
						process_pkts++;
						if (process_icmpv6(bufs[i], eh, ip6h, len))
							continue;
					}
				}
			}
			drop_pkts++;
			rte_pktmbuf_free(bufs[i]);
		}
	}
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int main(int argc, char *argv[])
{
	unsigned nb_ports;

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	if (argc < 3)
		rte_exit(EXIT_FAILURE, "You need tell me my IP and port\n");

	int a, b, c, d;
	sscanf(argv[1], "%d.%d.%d.%d", &a, &b, &c, &d);
	my_ip = rte_cpu_to_be_32(IPv4(a, b, c, d));

	tcp_port = rte_cpu_to_be_16(atoi(argv[2]));

	printf("My IP is: %s, port is %d\n", INET_NTOA(my_ip), rte_be_to_cpu_16(tcp_port));

	argc -= 2;
	argv += 2;

	if ((argc > 2) && (strcmp(argv[1], "--ip6") == 0)) {
		char t[100];
		has_ipv6 = 1;
		if (inet_pton(AF_INET6, argv[2], &my_ipv6) != 1) {
			printf("%s is not a valid ipv6 address\n", argv[2]);
			exit(0);
		}
		printf("My IPv6 is: %s\n", inet_ntop(AF_INET6, &my_ipv6, t, 100));
		inet_pton(AF_INET6, "FF02::1:FF00:0000", &my_ipv6_m);
		my_ipv6_m[13] = my_ipv6[13];
		my_ipv6_m[14] = my_ipv6[14];
		my_ipv6_m[15] = my_ipv6[15];
		printf("My IPv6 node multicast address is: %s\n",
		       inet_ntop(AF_INET6, &my_ipv6_m, t, 100));
		argc -= 2;
		argv += 2;
	}

	signal(SIGHUP, sig_handler_hup);
	user_init_func(argc, argv);

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count();
	if (nb_ports != 1)
		rte_exit(EXIT_FAILURE, "Error: need 1 ports, but you have %d\n", nb_ports);

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool =
	    rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
				    RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initialize port. */
	if (port_init(0, mbuf_pool) != 0)
		rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", 0);
	printf("My ether addr is: %02X:%02X:%02X:%02X:%02X:%02X",
	       my_eth_addr.addr_bytes[0], my_eth_addr.addr_bytes[1],
	       my_eth_addr.addr_bytes[2], my_eth_addr.addr_bytes[3], my_eth_addr.addr_bytes[4],
	       my_eth_addr.addr_bytes[5]);

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	/* Call lcore_main on the master core only. */
	lcore_main();

	return 0;
}
