/* Includes */
#define CONFIG_RTE_MALLOC_DEBUG
#define _GNU_SOURCE
#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/queue.h>
#include <sys/syscall.h>
#include <math.h>
#include <sched.h>
#include <pthread.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_tailq.h>
#include <rte_errno.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_log.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
#include <rte_atomic.h>
#include <rte_version.h>

/* Useful macro for error handling */
#define FATAL_ERROR(fmt, args...)       rte_exit(EXIT_FAILURE, fmt "\n", ##args)

/* Function prototypes */
static int main_loop_consumer(__attribute__((unused)) void * arg);
static int main_loop_producer(__attribute__((unused)) void * arg);
static void sig_handler(int signo);
static void init_port(int i);
static int parse_args(int argc, char **argv);
void print_stats (void);
void alarm_routine (__attribute__((unused)) int unused);
int isPowerOfTwo (unsigned int x);

/* RSS symmetrical 40 Byte seed, according to "Scalable TCP Session Monitoring with Symmetric Receive-side Scaling" (Shinae Woo, KyoungSoo Park from KAIST)  */
uint8_t rss_seed [] = {	0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
			0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
			0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
			0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
			0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a
};

// Struct for devices configuration for const defines see rte_ethdev.h
static const struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode = ETH_MQ_RX_RSS,  	// Enable RSS
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = rss_seed,				// Set the seed,
			.rss_key_len = 40,				// and the seed length.
			.rss_hf = (ETH_RSS_TCP | ETH_RSS_UDP) ,	// Set the mask of protocols RSS will be applied to
		}
	}
};


/* Struct for configuring each rx queue. These are default values */
static const struct rte_eth_rxconf rx_conf = {
	.rx_thresh = {
		.pthresh = 8,   /* Ring prefetch threshold */
		.hthresh = 8,   /* Ring host threshold */
		.wthresh = 4,   /* Ring writeback threshold */
	},
	.rx_free_thresh = 32,    /* Immediately free RX descriptors */
};

/* Struct for configuring each tx queue. These are default values */
static const struct rte_eth_txconf tx_conf = {
	.tx_thresh = {
		.pthresh = 36,  /* Ring prefetch threshold */
		.hthresh = 0,   /* Ring host threshold */
		.wthresh = 0,   /* Ring writeback threshold */
	},
	.tx_free_thresh = 0,    /* Use PMD default values */
	.txq_flags = ETH_TXQ_FLAGS_NOOFFLOADS | ETH_TXQ_FLAGS_NOMULTSEGS,  /* IMPORTANT for vmxnet3, otherwise it won't work */
	.tx_rs_thresh = 0,      /* Use PMD default values */
};

// static struct rte_eth_conf port_conf = {
// 	.rxmode = {
// 		.mq_mode = ETH_MQ_RX_RSS,
// 		.max_rx_pkt_len = ETHER_MAX_LEN,
// 		.split_hdr_size = 0,
// 		.header_split   = 0, /**< Header Split disabled */
// 		.hw_ip_checksum = 1, /**< IP checksum offload enabled */
// 		.hw_vlan_filter = 0, /**< VLAN filtering disabled */
// 		.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
// 		.hw_strip_crc   = 0, /**< CRC stripped by hardware */
// 	},
// 	.rx_adv_conf = {
// 		.rss_conf = {
// 			.rss_key = rss_seed,
// 			.rss_key_len = 40,				// and the seed length.
// 			.rss_hf = (ETH_RSS_TCP | ETH_RSS_UDP) ,	// Set the mask of protocols RSS will be applied to
// 		},
// 	},
// 	.txmode = {
// 		.mq_mode = ETH_MQ_RX_RSS,
// 	},
// };


struct app_stats {
  struct timeval last_time;
  uint64_t num_pkts_sent;
  uint64_t num_bytes_sent;
};

struct pcap_entry{
  uint32_t caplen;
  char * capbytes;
};
