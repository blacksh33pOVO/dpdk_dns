

#include <stdio.h>
#include <arpa/inet.h>

#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>

#include "dns.h"

#define NUM_MBUFS		8192	
#define BURST_SIZE		64
#define DNS_PORT		53

#define QUEUE_SIZE		8

static int global_portid = 0;


static const struct rte_eth_conf port_conf_default = {
	.rxmode = { .max_rx_pkt_len = RTE_ETHER_MAX_LEN }
};

static void zdns_init_port(struct rte_mempool *mbuf_pool) {

	uint16_t nb_sys_port = rte_eth_dev_count_avail();
	if (nb_sys_port == 0) {
		rte_exit(EXIT_FAILURE, "No Supported eth found\n");
	}

	
	struct rte_eth_dev_info dev_info;
	rte_eth_dev_info_get(global_portid, &dev_info);

	const int num_rx_queues = QUEUE_SIZE;
	const int num_tx_queues = QUEUE_SIZE;
	struct rte_eth_conf port_conf = port_conf_default;
	rte_eth_dev_configure(global_portid, num_rx_queues, num_tx_queues, &port_conf);

	int i = 0;
	for (i = 0;i < QUEUE_SIZE;i ++) {
		if (rte_eth_rx_queue_setup(global_portid, i, 128, rte_eth_dev_socket_id(global_portid), NULL, mbuf_pool) < 0) {
			rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");
		}

		
		if (rte_eth_tx_queue_setup(global_portid, i, 512, rte_eth_dev_socket_id(global_portid), NULL) < 0) {
			rte_exit(EXIT_FAILURE, "Could not setup TX queue\n");
		}
	}

	if (rte_eth_dev_start(global_portid) < 0) {
		rte_exit(EXIT_FAILURE, "Could not start\n");
	}

}


static void zdns_echo(struct rte_ether_hdr *ehdr, struct rte_ipv4_hdr *iphdr, struct rte_udp_hdr *udphdr) {

	// eth hdr
	struct rte_ether_addr eth_addr;
	rte_memcpy(&eth_addr, &ehdr->s_addr, sizeof(struct rte_ether_addr));
	rte_memcpy(&ehdr->s_addr, &ehdr->d_addr, sizeof(struct rte_ether_addr));
	rte_memcpy(&ehdr->d_addr, &eth_addr, sizeof(struct rte_ether_addr));


	uint32_t ip_addr;
	rte_memcpy(&ip_addr, &iphdr->src_addr, sizeof(uint32_t));
	rte_memcpy(&iphdr->src_addr, &iphdr->dst_addr, sizeof(uint32_t));
	rte_memcpy(&iphdr->dst_addr, &ip_addr, sizeof(uint32_t));

	iphdr->hdr_checksum = 0;
	iphdr->hdr_checksum = rte_ipv4_cksum(iphdr);

	uint16_t udp_port;
	udp_port = udphdr->dst_port;
	udphdr->dst_port = udphdr->src_port;
	udphdr->src_port = udp_port;
	
	udphdr->dgram_cksum = 0;
	udphdr->dgram_cksum = rte_ipv4_udptcp_cksum(iphdr, udphdr);

}


static int dns_process(__attribute__((unused)) void *arg) {

	unsigned lcore_id = rte_lcore_id();
	printf("dns_process --> %d\n", lcore_id);
	
	while (1) {

		struct rte_mbuf *mbuf[BURST_SIZE] = {0};
		unsigned num_recvd = rte_eth_rx_burst(global_portid, lcore_id, mbuf, BURST_SIZE);
		if (num_recvd > BURST_SIZE) {
			rte_exit(EXIT_FAILURE, "rte_eth_rx_burst failed\n");
		}

		unsigned i = 0;
		for (i = 0;i < num_recvd;i ++) {  // udp : 53

			struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbuf[i], struct rte_ether_hdr *);
			if (ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
				continue;
			}

			struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbuf[i], struct rte_ipv4_hdr* , sizeof(struct rte_ether_hdr));
			//printf("iphdr->next_proto_id: %d\n", iphdr->next_proto_id);
			if (iphdr->next_proto_id == IPPROTO_UDP) {

				struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);
				uint16_t length = 0;
#if 1
				if (DNS_PORT == rte_cpu_to_be_16(udphdr->dst_port)) {
					//printf(" dns --> \n");

					uint8_t *data = (uint8_t *)(udphdr+1);
					uint16_t nbytes = ntohs(udphdr->dgram_len) - 8;

					struct Message msg;
					memset(&msg, 0, sizeof(struct Message));

					decode_msg(&msg, data, nbytes);
					resolve_query(&msg); //www.0voice.com

					uint8_t *p = data;
						
					encode_msg(&msg, &p);
					// 
					length =  p - data;
					//printf("encode_msg: %d\n", length);

					
					free_questions(msg.questions);
				    free_resource_records(msg.answers);
				    free_resource_records(msg.authorities);
				    free_resource_records(msg.additionals);

					
					mbuf[i]->pkt_len = length + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr);  //  eth 14, iphdr 20, udphdr 8 --> 42
					mbuf[i]->data_len = length + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr);
				}
				//uint16_t length = ntohs(udphdr->dgram_len);
				//*((char *)udphdr + length) = '\0';
#endif
				
				//printf("ctx: %s\n", (char *)(udphdr+1));

				zdns_echo(ehdr, iphdr, udphdr);

				
				rte_eth_tx_burst(global_portid, lcore_id, mbuf+i, 1);
				
			}
			
		}

	}
	
}

int main(int argc, char *argv[]) {

	if (rte_eal_init(argc, argv) < 0) {
		rte_exit(EXIT_FAILURE, "Error with EAL init\n");
	}

	struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", NUM_MBUFS, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL) {
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_pool_create failed\n");
	}


	zdns_init_port(mbuf_pool);

	unsigned lcore_id;
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		rte_eal_remote_launch(dns_process, NULL, lcore_id);
	}

	lcore_id = 0;
	while (1) {

		struct rte_mbuf *mbuf[BURST_SIZE] = {0};
		unsigned num_recvd = rte_eth_rx_burst(global_portid, lcore_id, mbuf, BURST_SIZE);
		if (num_recvd > BURST_SIZE) {
			rte_exit(EXIT_FAILURE, "rte_eth_rx_burst failed\n");
		}

		unsigned i = 0;
		for (i = 0;i < num_recvd;i ++) {  // udp : 53

			struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbuf[i], struct rte_ether_hdr *);
			if (ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
				continue;
			}

			struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbuf[i], struct rte_ipv4_hdr* , sizeof(struct rte_ether_hdr));
			//printf("iphdr->next_proto_id: %d\n", iphdr->next_proto_id);
			if (iphdr->next_proto_id == IPPROTO_UDP) {

				struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);
				uint16_t length = 0;
#if 1
				if (DNS_PORT == rte_cpu_to_be_16(udphdr->dst_port)) {
					//printf(" dns --> \n");

					uint8_t *data = (uint8_t *)(udphdr+1);
					uint16_t nbytes = ntohs(udphdr->dgram_len) - 8;

					struct Message msg;
					memset(&msg, 0, sizeof(struct Message));

					decode_msg(&msg, data, nbytes);
					resolve_query(&msg); //www.0voice.com

					uint8_t *p = data;
						
					encode_msg(&msg, &p);
					// 
					length =  p - data;
					//printf("encode_msg: %d\n", length);

					
					free_questions(msg.questions);
				    free_resource_records(msg.answers);
				    free_resource_records(msg.authorities);
				    free_resource_records(msg.additionals);

					
					mbuf[i]->pkt_len = length + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr);  //  eth 14, iphdr 20, udphdr 8 --> 42
					mbuf[i]->data_len = length + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr);
				}
				//uint16_t length = ntohs(udphdr->dgram_len);
				//*((char *)udphdr + length) = '\0';
#endif
				
				//printf("ctx: %s\n", (char *)(udphdr+1));

				zdns_echo(ehdr, iphdr, udphdr);

				
				rte_eth_tx_burst(global_portid, lcore_id, mbuf+i, 1);
				
			}
			
		}

	}

	//rte_eal_mp_wait_lcore();

	return 0;

}


