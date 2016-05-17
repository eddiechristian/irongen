#include "main.h"

/* Constants of the system */
#define MEMPOOL_NAME "cluster_mem_pool"				// Name of the NICs' mem_pool, useless comment....
#define MEMPOOL_ELEM_SZ 2048  					// Power of two greater than 1500
#define MEMPOOL_CACHE_SZ 512  					// Max is 512
#define BUFFER_RATIO 0.9
#define RING_NAME "cluster_ring"
#define RX_QUEUE_SZ 256			// The size of rx queue. Max is 4096 and is the one you'll have best performances with. Use lower if you want to use Burst Bulk Alloc.
#define TX_QUEUE_SZ 4096			// Unused, you don't tx packets
#define MAX_NUM_PCAP_PACKETS 100 //maximum number of frames in pcap file.

static int g_shutdown = 0;
static struct app_stats* g_new_stats = NULL;
static struct app_stats* g_old_stats = NULL;
static char * g_file_name = NULL;
static uint64_t g_buffer_size = 1048576;
static uint64_t g_num_packets =0;
static int g_nb_sys_ports;
static int g_sum_value = 0;
double g_rate = 0;
static struct rte_mempool * g_pktmbuf_pool = NULL;
static struct rte_ring * g_intermediate_ring = NULL;
static int g_times = 1;
struct timeval g_start_time;
struct pcap_entry* pcap_cache[MAX_NUM_PCAP_PACKETS];

static int main_loop_producer(__attribute__((unused)) void * arg){
  char ebuf[256];
  int ret = 1;;
  struct pcap_pkthdr *pcaphdrptr;
	void * pkt;
  /* Open the trace */
  printf("Opening file: %s\n", g_file_name);
  pcap_t *pt = pcap_open_offline(g_file_name, ebuf);
  if (pt == NULL){
    printf("Unable to open file: %s\n", g_file_name);
    exit(1);
  }

  // while(ret == 1){
  //   ret = pcap_next_ex(pt, &pcaphdrptr, (const u_char**)&pkt);
  //   pcap_cache[g_num_packets] = (struct pcap_entry*) rte_zmalloc("new pcap entry alloc",sizeof(struct pcap_entry),0);
  //   pcap_cache[g_num_packets]->caplen = pcaphdrptr->caplen;
  //   pcap_cache[g_num_packets]->capbytes = (char*) rte_zmalloc("new pcap bytes alloc",pcaphdrptr->caplen,0);
  //   rte_memcpy ( pcap_cache[g_num_packets]->capbytes, pkt, pcap_cache[g_num_packets]->caplen);
  //   g_num_packets++;
  //   if (g_num_packets == 1){
  //     printf("len = %d bytes = %#010x\n",pcap_cache[g_num_packets]->caplen,pcap_cache[g_num_packets]->capbytes);
  //   }
  // }
  pcap_close(pt);

  if(ret <= 0) {
    if (ret==-2){
      printf("read %d packets from file",g_num_packets);
    }
    if (ret==-1) FATAL_ERROR("Error in pcap: %s\n", pcap_geterr(pt));

  }
  sig_handler(SIGINT);
}

/* Loop function, batch timing implemented */
static int main_loop_consumer(__attribute__((unused)) void * arg){
	struct rte_mbuf * m, * m_copy;
	struct timeval now;
	struct ipv4_hdr * ip_h;
	double mult_start = 0, mult = 0, real_rate, deltaMillisec;
	int i, ix, ret, length;
	uint64_t tick_start;


	/* Prepare variables to rate setting if needed */
	if(g_rate != 0){
		mult_start = (double )rte_get_tsc_hz  () / 1000000000L;
		mult = mult_start;
		ix = 0;
	}

	/* Init start time */
	ret = gettimeofday(&g_start_time, NULL);
	if (ret != 0) FATAL_ERROR("Error: gettimeofday failed. Quitting...\n");
	g_old_stats->last_time = g_start_time;
	tick_start =   rte_get_tsc_cycles();

	/* Start stats */
   	alarm(1);
	for (i=0;i<g_nb_sys_ports; i++)
		rte_eth_stats_reset ( i );

	/* Infinite loop */
	for (;;) {

		/* Dequeue packet */
		ret = rte_ring_dequeue(g_intermediate_ring, (void**)&m);

		/* Continue polling if no packet available */
		if( unlikely (ret != 0)) continue;

		length = m->data_len;

		/* For each received packet. */
		for (i = 0; likely( i < g_nb_sys_ports * g_times ) ; i++) {

			/* Add a number to ip address if needed */
			ip_h = (struct ipv4_hdr*)((char*) m->buf_addr + m->data_off + sizeof(struct  ether_hdr));
			if (g_sum_value > 0){
				ip_h->src_addr+=g_sum_value*256*256*256;
				ip_h->dst_addr+=g_sum_value*256*256*256;
        ip_h->hdr_checksum = 0;
        m->ol_flags |=  PKT_TX_IP_CKSUM | PKT_TX_TCP_CKSUM;
        // ip_h->hdr_checksum =  _bswap16(csum((unsigned short*)ip_h,10));
        // char * ip_payload = (char*)ip_h;
        // ip_payload+=20;
        // compute_tcp_checksum(ip_h,(unsigned short*)ip_payload);
			}


			/* The last time sends 'm', the other times it makes a copy */
			if(i == g_nb_sys_ports * g_times-1){
				/* Loop untill it is not sent */
				while ( rte_eth_tx_burst (i / g_times, 0, &m, 1) != 1)
					if (unlikely(g_shutdown)) break;
			}
			else{

				/* Copy the packet from the previous when sending on multiple */
				while( (m_copy = rte_pktmbuf_alloc (g_pktmbuf_pool)) == NULL) {}

				/* Compile the buffer */
				m_copy->data_len = m_copy->pkt_len = length;
				rte_memcpy ( (char*) m_copy->buf_addr + m_copy->data_off, (char*) m->buf_addr + m->data_off, length);

				/* Loop untill it is not sent */
				while ( rte_eth_tx_burst (i / g_times, 0, &m_copy , 1) != 1)
					if (unlikely(g_shutdown)) break;

			}


		}

		/* Rate set */
		if(g_rate > 0) {
			/* Adjust the rate every 100 packets sent */
			if (ix++%1 ==0){
				/* Calculate the actual rate */
				ret = gettimeofday(&now, NULL);
				if (ret != 0) FATAL_ERROR("Error: gettimeofday failed. Quitting...\n");
        deltaMillisec =  (now.tv_sec - g_old_stats->last_time.tv_sec ) * 1000 + (now.tv_usec - g_old_stats->last_time.tv_usec ) / 1000 ;

				real_rate = (double)(g_new_stats->num_bytes_sent * 1000)/deltaMillisec * 8/(1000*1000*1000);
				mult = mult + (real_rate - g_rate); // CONTROL LAW;

				/* Avoid negative numbers. Avoid problems when the NICs are stuck for a while */
				if (mult < 0) mult = 0;
			}
			/* Wait to adjust the rate*/
			while(( rte_get_tsc_cycles() - tick_start) < (g_new_stats->num_bytes_sent * mult / g_rate ))
				if (unlikely(g_shutdown)) break;
		}

		/* Update stats */
		g_new_stats->num_pkts_sent += g_times;
		g_new_stats->num_bytes_sent += (m->data_len + 24) * g_times; /* 8 Preamble + 4 CRC + 12 IFG*/

	}

	sig_handler(SIGINT);
	return 0;
}


int main(int argc, char **argv)
{
  int ret;
  int i;
  /* Create handler for SIGINT for CTRL + C closing and SIGALRM to print stats*/
  signal(SIGINT, sig_handler);
  signal(SIGALRM, alarm_routine);

  /* Initialize DPDK enviroment with args, then shift argc and argv to get application parameters */
  ret = rte_eal_init(argc, argv);
  if (ret < 0) FATAL_ERROR("Cannot init EAL\n");
  argc -= ret;
  argv += ret;

  /* Check if this application can use 1 core*/
  ret = rte_lcore_count ();
  if (ret != 2) FATAL_ERROR("This application needs exactly 2 cores.");

  /* Parse arguments */
	parse_args(argc, argv);
	if (ret < 0) FATAL_ERROR("Wrong arguments\n");

  /* Get number of ethernet devices */
	g_nb_sys_ports = rte_eth_dev_count();
	if (g_nb_sys_ports <= 0) FATAL_ERROR("Cannot find ETH devices\n");

	/* Create a mempool with per-core cache, initializing every element for be used as mbuf, and allocating on the current NUMA node */
	g_pktmbuf_pool = rte_mempool_create(MEMPOOL_NAME, g_buffer_size-1, MEMPOOL_ELEM_SZ,
    MEMPOOL_CACHE_SZ, sizeof(struct rte_pktmbuf_pool_private), rte_pktmbuf_pool_init,
    NULL, rte_pktmbuf_init, NULL,rte_socket_id(), 0);
  if (g_pktmbuf_pool == NULL) FATAL_ERROR("Cannot create cluster_mem_pool. \n");


  g_new_stats = (struct app_stats*) rte_malloc_socket("new stat alloc",sizeof(struct app_stats),0,rte_socket_id());
  if(g_new_stats == NULL) FATAL_ERROR("Cannot allocate new stats\n");
  printf("test2 %llx \n",g_new_stats);
  g_new_stats->num_pkts_sent = 5;

  g_old_stats = (struct app_stats*) rte_zmalloc("old stat alloc",sizeof(struct app_stats),0);
  if(g_old_stats == NULL) FATAL_ERROR("Cannot allocate old stats\n");


  /* Create a ring for exchanging packets between cores, and allocating on the current NUMA node */
	g_intermediate_ring = rte_ring_create 	(RING_NAME, g_buffer_size, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ );
 	if (g_intermediate_ring == NULL ) FATAL_ERROR("Cannot create ring");


	/* Operations needed for each ethernet device */
	for(i=0; i < g_nb_sys_ports; i++)
		init_port(i);

	/* Start consumer and producer routine on 2 different cores: producer launched first... */
	//ret =  rte_eal_mp_remote_launch (main_loop_producer, NULL, SKIP_MASTER);
	//if (ret != 0) FATAL_ERROR("Cannot start consumer thread\n");

	/* ... and then loop in consumer */
	//main_loop_consumer ( NULL );


}

void print_stats (void){
	int ret;
	struct timeval now_time;
	double delta_ms;
	double tot_ms;
	double gbps_inst, gbps_tot, mpps_inst, mpps_tot;

	/* Get actual time */
	ret = gettimeofday(&now_time, NULL);
	if (ret != 0) FATAL_ERROR("Error: gettimeofday failed. Quitting...\n");

	/* Compute stats */
	delta_ms =  (now_time.tv_sec - g_old_stats->last_time.tv_sec ) * 1000 + (now_time.tv_usec - g_old_stats->last_time.tv_usec ) / 1000 ;
	tot_ms = (now_time.tv_sec - g_start_time.tv_sec ) * 1000 + (now_time.tv_usec - g_start_time.tv_usec ) / 1000 ;
	gbps_inst = (double)(g_new_stats->num_bytes_sent - g_old_stats->num_bytes_sent)/delta_ms/1000000*8;
	gbps_tot = (double)(g_new_stats->num_bytes_sent)/tot_ms/1000000*8;
	mpps_inst = (double)(g_new_stats->num_pkts_sent - g_old_stats->num_pkts_sent)/delta_ms/1000;
	mpps_tot = (double)(g_new_stats->num_pkts_sent)/tot_ms/1000;

	printf("Rate: %8.3fGbps  %8.3fMpps [Average rate: %8.3fGbps  %8.3fMpps], Buffer: %8.3f%% ", gbps_inst, mpps_inst, gbps_tot, mpps_tot, (double)rte_mempool_free_count (g_pktmbuf_pool)/g_buffer_size*100.0 );

	/* Update counters */
  g_old_stats->num_pkts_sent = g_new_stats->num_pkts_sent;
  g_old_stats->num_bytes_sent = g_new_stats->num_bytes_sent;
	g_old_stats->last_time = now_time;

}

void alarm_routine (__attribute__((unused)) int unused){

	/* If the program is quitting don't print anymore */
	if(g_shutdown) return;

	/* Print per port stats */
	print_stats();

	/* Schedule an other print */
	alarm(1);
	signal(SIGALRM, alarm_routine);

}

/* Signal handling function */
static void sig_handler(int signo)
{
	uint64_t diff;
	int ret;
	struct timeval t_end;

	/* Catch just SIGINT */
	if (signo == SIGINT){

		/* Signal the shutdown */
		g_shutdown=1;

		/* Print the per stats  */
		printf("\n\nQUITTING...\n");
		print_stats();

		exit(0);
	}
}

/* Init each port with the configuration contained in the structs. Every interface has nb_sys_cores queues */
static void init_port(int i) {

		int ret;
		uint8_t rss_key [40];
		struct rte_eth_link link;
		struct rte_eth_dev_info dev_info;
		struct rte_eth_rss_conf rss_conf;
		//struct rte_eth_fdir fdir_conf;

		/* Retreiving and printing device infos */
		rte_eth_dev_info_get(i, &dev_info);
		printf("Name:%s\n\tDriver name: %s\n\tMax rx queues: %d\n\tMax tx queues: %d\n", dev_info.pci_dev->driver->name,dev_info.driver_name, dev_info.max_rx_queues, dev_info.max_tx_queues);
		printf("\tPCI Adress: %04d:%02d:%02x:%01d\n", dev_info.pci_dev->addr.domain, dev_info.pci_dev->addr.bus, dev_info.pci_dev->addr.devid, dev_info.pci_dev->addr.function);

		/* Configure device with '1' rx queues and 1 tx queue */
		ret = rte_eth_dev_configure(i, 1, 1, &port_conf);
		if (ret < 0) rte_panic("Error configuring the port\n");

		/* For each RX queue in each NIC */
		/* Configure rx queue j of current device on current NUMA socket. It takes elements from the mempool */
		ret = rte_eth_rx_queue_setup(i, 0, RX_QUEUE_SZ, rte_socket_id(), &rx_conf, g_pktmbuf_pool);
		if (ret < 0) FATAL_ERROR("Error configuring receiving queue\n");

    /* Configure mapping [queue] -> [element in stats array] */
		//eddie ret = rte_eth_dev_set_rx_queue_stats_mapping 	(i, 0, 0);
		//eddie if (ret < 0) FATAL_ERROR("Error configuring receiving queue stats\n");


		/* Configure tx queue of current device on current NUMA socket. Mandatory configuration even if you want only rx packet */
		ret = rte_eth_tx_queue_setup(i, 0, TX_QUEUE_SZ, rte_socket_id(), &tx_conf);
		if (ret < 0) FATAL_ERROR("Error configuring transmitting queue. Errno: %d (%d bad arg, %d no mem)\n", -ret, EINVAL ,ENOMEM);

		/* Start device */
		ret = rte_eth_dev_start(i);
		if (ret < 0) FATAL_ERROR("Cannot start port\n");

		/* Enable receipt in promiscuous mode for an Ethernet device */
		rte_eth_promiscuous_enable(i);

		/* Print link status */
		rte_eth_link_get_nowait(i, &link);
		if (link.link_status) 	printf("\tPort %d Link Up - speed %u Mbps - %s\n", (uint8_t)i, (unsigned)link.link_speed,(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?("full-duplex") : ("half-duplex\n"));
		else			printf("\tPort %d Link Down\n",(uint8_t)i);

		/* Print RSS support, not reliable because a NIC could support rss configuration just in rte_eth_dev_configure whithout supporting rte_eth_dev_rss_hash_conf_get*/
		rss_conf.rss_key = rss_key;
		ret = rte_eth_dev_rss_hash_conf_get (i,&rss_conf);
		if (ret == 0) printf("\tDevice supports RSS\n"); else printf("\tDevice DOES NOT support RSS\n");


}

static int parse_args(int argc, char **argv)
{
	int option;

	/* Retrive arguments */
	while ((option = getopt(argc, argv,"f:s:r:B:t:")) != -1) {
      switch (option) {
        case 'f' : g_file_name = strdup(optarg); /* File name, mandatory */
          break;
        case 's': g_sum_value = atol (optarg); /* Sum this value each time duplicate a packet */
          break;
        case 'B': g_buffer_size = atol (optarg); /* Buffer size in packets. Must be a power of two . Default is 1048576 */
          break;
        case 'r': g_rate = atof (optarg); /* Rate in Gbps */
          break;
        case 't': g_times = atoi (optarg); /* Times to send a packet */
          break;
        default: return -1;
       }
   	}

	/* Returning bad value in case of wrong arguments */
	if(g_file_name == NULL || isPowerOfTwo (g_buffer_size)!=1 )
		return -1;

	return 0;

}

int isPowerOfTwo (unsigned int x)
{
  return ((x != 0) && !(x & (x - 1)));
}
