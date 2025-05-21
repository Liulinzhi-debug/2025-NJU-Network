#include "tcp.h"
#include "tcp_hash.h"
#include "tcp_sock.h"
#include "tcp_timer.h"
#include "ip.h"
#include "rtable.h"
#include "log.h"

// TCP socks should be hashed into table for later lookup: Those which
// occupy a port (either by *bind* or *connect*) should be hashed into
// bind_table, those which listen for incoming connection request should be
// hashed into listen_table, and those of established connections should
// be hashed into established_table.

struct tcp_hash_table tcp_sock_table;
#define tcp_established_sock_table	tcp_sock_table.established_table
#define tcp_listen_sock_table		tcp_sock_table.listen_table
#define tcp_bind_sock_table			tcp_sock_table.bind_table
#ifndef max
#	define max(x,y) ((x)>(y) ? (x) : (y))
#endif
inline void tcp_set_state(struct tcp_sock *tsk, int state)
{
	log(DEBUG, IP_FMT":%hu switch state, from %s to %s.", \
			HOST_IP_FMT_STR(tsk->sk_sip), tsk->sk_sport, \
			tcp_state_str[tsk->state], tcp_state_str[state]);
	tsk->state = state;
}
//pthread_mutex_t tcp_sock_table_lock;
// init tcp hash table and tcp timer
void init_tcp_stack()
{
	for (int i = 0; i < TCP_HASH_SIZE; i++)
		init_list_head(&tcp_established_sock_table[i]);

	for (int i = 0; i < TCP_HASH_SIZE; i++)
		init_list_head(&tcp_listen_sock_table[i]);

	for (int i = 0; i < TCP_HASH_SIZE; i++)
		init_list_head(&tcp_bind_sock_table[i]);

	init_list_head(&timer_list);
	init_list_head(&retrans_timer_list);
	//pthread_mutex_init(&tcp_sock_table_lock, NULL);
	pthread_t timer1, timer2;
	pthread_create(&timer1, NULL, tcp_timer_thread, NULL);
	pthread_create(&timer2, NULL, tcp_retrans_timer_thread, NULL);
}
// allocate tcp sock, and initialize all the variables that can be determined
// now
struct tcp_sock *alloc_tcp_sock()
{
	struct tcp_sock *tsk = malloc(sizeof(struct tcp_sock));

	memset(tsk, 0, sizeof(struct tcp_sock));

	tsk->state = TCP_CLOSED;
	tsk->NewReno_state = OPEN;

	tsk->cwnd = 1;
	tsk->ssthresh = 16;
	tsk->dupACKcount  = 0;
	tsk->rcv_wnd = TCP_DEFAULT_WINDOW;
	tsk->snd_wnd = TCP_DEFAULT_WINDOW;
	tsk->adv_wnd = TCP_DEFAULT_WINDOW;

	init_list_head(&tsk->list);
	init_list_head(&tsk->listen_queue);
	init_list_head(&tsk->accept_queue);
	init_list_head(&tsk->send_buf);
	init_list_head(&tsk->rcv_ofo_buf);

	tsk->rcv_buf = alloc_ring_buffer(tsk->rcv_wnd);

	tsk->wait_connect = alloc_wait_struct();
	tsk->wait_accept = alloc_wait_struct();
	tsk->wait_recv = alloc_wait_struct();
	tsk->wait_send = alloc_wait_struct();

	init_list_head(&tsk->timewait.list);
	init_list_head(&tsk->retrans_timer.list);

	tsk->retrans_timer.enable = 0;

	return tsk;
}

// release all the resources of tcp sock
//
// To make the stack run safely, each time the tcp sock is refered (e.g. hashed), 
// the ref_cnt is increased by 1. each time free_tcp_sock is called, the ref_cnt
// is decreased by 1, and release the resources practically if ref_cnt is
// decreased to zero.
void free_tcp_sock(struct tcp_sock *tsk)
{
	//fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
//fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);

	tsk->ref_cnt--;
	
	if (tsk->ref_cnt <= 0) {
		log(DEBUG, "free tcp sock: ["IP_FMT":%hu<->"IP_FMT":%hu].", \
			HOST_IP_FMT_STR(tsk->sk_sip), tsk->sk_sport,
			HOST_IP_FMT_STR(tsk->sk_dip), tsk->sk_dport);
		if (tsk->rcv_buf) {
			free_ring_buffer(tsk->rcv_buf);
			tsk->rcv_buf = NULL;
		}
		if (tsk->wait_connect) {
			free_wait_struct(tsk->wait_connect);
			tsk->wait_connect = NULL;
		}
		if (tsk->wait_accept) {
			free_wait_struct(tsk->wait_accept);
			tsk->wait_accept = NULL;
		}
		if (tsk->wait_recv) {
			free_wait_struct(tsk->wait_recv);
			tsk->wait_recv = NULL;
		}
		if (tsk->wait_send) {
			free_wait_struct(tsk->wait_send);
			tsk->wait_send = NULL;
		}
		free(tsk);
	}
}

// lookup tcp sock in established_table with key (saddr, daddr, sport, dport)
struct tcp_sock *tcp_sock_lookup_established(u32 saddr, u32 daddr, u16 sport, u16 dport)
{
	//fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	int hash = tcp_hash_function(saddr, daddr, sport, dport);


    struct tcp_sock *tsk;
	list_for_each_entry(tsk, &tcp_established_sock_table[hash], hash_list) {
        if (tsk->sk_sip == saddr && 
			tsk->sk_dip == daddr &&
            tsk->sk_sport == sport &&
            tsk->sk_dport == dport) 
		{
            return tsk;
        }
    }
	return NULL;
}

// lookup tcp sock in listen_table with key (sport)
//
// In accordance with BSD socket, saddr is in the argument list, but never used.
struct tcp_sock *tcp_sock_lookup_listen(u32 saddr, u16 sport)
{
    int hash = tcp_hash_function(0, 0, sport, 0) ;
    struct tcp_sock *tsk;
    list_for_each_entry(tsk, &tcp_listen_sock_table[hash], hash_list) {
        if (tsk->sk_sport == sport ) 
		{
            return tsk;
        }
    }
	return NULL;
}

// lookup tcp sock in both established_table and listen_table
struct tcp_sock *tcp_sock_lookup(struct tcp_cb *cb)
{
	u32 saddr = cb->daddr,
		daddr = cb->saddr;
	u16 sport = cb->dport,
		dport = cb->sport;

	struct tcp_sock *tsk = tcp_sock_lookup_established(saddr, daddr, sport, dport);
	if (!tsk)
		tsk = tcp_sock_lookup_listen(saddr, sport);

	return tsk;
}

// hash tcp sock into bind_table, using sport as the key
static int tcp_bind_hash(struct tcp_sock *tsk)
{
	int bind_hash_value = tcp_hash_function(0, 0, tsk->sk_sport, 0);
	struct list_head *list = &tcp_bind_sock_table[bind_hash_value];
	list_add_head(&tsk->bind_hash_list, list);

	tsk->ref_cnt += 1;

	return 0;
}

// unhash the tcp sock from bind_table
void tcp_bind_unhash(struct tcp_sock *tsk)
{
	if (!list_empty(&tsk->bind_hash_list)) {
		list_delete_entry(&tsk->bind_hash_list);
		free_tcp_sock(tsk);
	}
}

// lookup bind_table to check whether sport is in use
static int tcp_port_in_use(u16 sport)
{
	int value = tcp_hash_function(0, 0, sport, 0);
	struct list_head *list = &tcp_bind_sock_table[value];
	struct tcp_sock *tsk;
	//list_for_each_entry(tsk, list, hash_list) {
	list_for_each_entry(tsk, list, bind_hash_list) {
		if (tsk->sk_sport == sport)
			return 1;
	}

	return 0;
}

// find a free port by looking up bind_table
static u16 tcp_get_port()
{
	for (u16 port = PORT_MIN; port < PORT_MAX; port++) {
		if (!tcp_port_in_use(port))
			return port;
	}

	return 0;
}

// tcp sock tries to use port as its source port
static int tcp_sock_set_sport(struct tcp_sock *tsk, u16 port)
{
	if ((port && tcp_port_in_use(port)) ||
			(!port && !(port = tcp_get_port())))
		return -1;

	tsk->sk_sport = port;

	tcp_bind_hash(tsk);

	return 0;
}

// hash tcp sock into either established_table or listen_table according to its
// TCP_STATE
int tcp_hash(struct tcp_sock *tsk)
{
	struct list_head *list;
	int hash;

	if (tsk->state == TCP_CLOSED)
		return -1;

	if (tsk->state == TCP_LISTEN) {
		hash = tcp_hash_function(0, 0, tsk->sk_sport, 0);
		list = &tcp_listen_sock_table[hash];
	}
	else {
		int hash = tcp_hash_function(tsk->sk_sip, tsk->sk_dip, \
				tsk->sk_sport, tsk->sk_dport); 
		list = &tcp_established_sock_table[hash];

		struct tcp_sock *tmp;
		list_for_each_entry(tmp, list, hash_list) {
			if (tsk->sk_sip == tmp->sk_sip &&
					tsk->sk_dip == tmp->sk_dip &&
					tsk->sk_sport == tmp->sk_sport &&
					tsk->sk_dport == tmp->sk_dport)
				return -1;
		}
	}

	list_add_head(&tsk->hash_list, list);
	tsk->ref_cnt += 1;

	return 0;
}

// unhash tcp sock from established_table or listen_table
void tcp_unhash(struct tcp_sock *tsk)
{
	if (!list_empty(&tsk->hash_list)) {
		list_delete_entry(&tsk->hash_list);
		free_tcp_sock(tsk);
	}
}

// XXX: skaddr here contains network-order variables
int tcp_sock_bind(struct tcp_sock *tsk, struct sock_addr *skaddr)
{
	int err = 0;

	// omit the ip address, and only bind the port
	err = tcp_sock_set_sport(tsk, ntohs(skaddr->port));

	return err;
}


// connect to the remote tcp sock specified by skaddr
//
// XXX: skaddr here contains network-order variables
// 1. initialize the four key tuple (sip, sport, dip, dport);
// 2. hash the tcp sock into bind_table;
// 3. send SYN packet, switch to TCP_SYN_SENT state, wait for the incoming
//    SYN packet by sleep on wait_connect;
// 4. if the SYN packet of the peer arrives, this function is notified, which
//    means the connection is established.
int tcp_sock_connect(struct tcp_sock *tsk, struct sock_addr *skaddr)
{
	tsk->sk_dip   = ntohl(skaddr->ip);
	tsk->sk_dport = ntohs(skaddr->port);
	int err = 0;
	rt_entry_t *rt = longest_prefix_match(tsk->sk_dip);
    if (!rt) {
        fprintf(stdout, "tcp_sock_connect: No route to host\n");
        return -1;
    }

	tsk->sk_sip = rt->iface->ip;
	err = tcp_sock_set_sport(tsk, 0);
	if(err){
		fprintf(stdout, "tcp_sock_connect: Failed to set source port\n");
        return -1;
	}


	if(tsk->sk_sport == 0){
		log(ERROR, "tcp get port %d.", tsk->sk_sport);
		return 1;		
	}



 	tcp_set_state(tsk, TCP_SYN_SENT);
	err = tcp_hash(tsk);
	if(err){
		fprintf(stderr, "tcp_sock_connect: Failed to hash TCP socket\n");
		return -1;
	}


	tsk->iss = tcp_new_iss();
	tsk->snd_una = tsk->iss;
	tsk->snd_nxt = tsk->iss;
	tcp_send_control_packet(tsk, TCP_SYN);
	err = sleep_on(tsk->wait_connect);
	if(err){
		log(ERROR, "sleep failed.");
		return -1;
	}

	return 0;
}

// set backlog (the maximum number of pending connection requst), switch the
// TCP_STATE, and hash the tcp sock into listen_table
int tcp_sock_listen(struct tcp_sock *tsk, int backlog)
{
	if (!tsk) {
		fprintf(stderr, "tcp_sock_listen: Invalid tcp_sock pointer\n");
		return -1;
	}
	if (tsk->sk_sport == 0) {
        fprintf(stderr, "tcp_sock_listen: Socket is not bound to a port\n");
        return -1;
    }
	if (backlog <= 0 || backlog > TCP_MAX_BACKLOG) {
		fprintf(stderr, "tcp_sock_listen: Invalid backlog value %d\n", backlog);
		return -1;
	}
	tsk->backlog = backlog;
    tcp_set_state(tsk, TCP_LISTEN);
	return tcp_hash(tsk);
}

// check whether the accept queue is full
inline int tcp_sock_accept_queue_full(struct tcp_sock *tsk)
{
	if (tsk->accept_backlog >= tsk->backlog) {
		log(ERROR, "tcp accept queue (%d) is full.", tsk->accept_backlog);
		return 1;
	}

	return 0;
}

// push the tcp sock into accept_queue
inline void tcp_sock_accept_enqueue(struct tcp_sock *tsk)
{
	if (!list_empty(&tsk->list))
		list_delete_entry(&tsk->list);
	list_add_tail(&tsk->list, &tsk->parent->accept_queue);
	tsk->parent->accept_backlog += 1;
}

// pop the first tcp sock of the accept_queue
inline struct tcp_sock *tcp_sock_accept_dequeue(struct tcp_sock *tsk)
{
	struct tcp_sock *new_tsk = list_entry(tsk->accept_queue.next, struct tcp_sock, list);
	list_delete_entry(&new_tsk->list);
	init_list_head(&new_tsk->list);
	tsk->accept_backlog -= 1;

	return new_tsk;
}

// push the tcp sock into listen_queue
inline void tcp_sock_listen_enqueue(struct tcp_sock *tsk)
{
	if (!list_empty(&tsk->list))
		list_delete_entry(&tsk->list);
	list_add_tail(&tsk->list, &tsk->parent->listen_queue);
}

// pop the first tcp sock of the listen_queue
inline struct tcp_sock *tcp_sock_listen_dequeue(struct tcp_sock *tsk)
{
	struct tcp_sock *new_tsk = list_entry(tsk->listen_queue.next, struct tcp_sock, list);
	list_delete_entry(&new_tsk->list);
	init_list_head(&new_tsk->list);

	return new_tsk;
}

// if accept_queue is not emtpy, pop the first tcp sock and accept it,
// otherwise, sleep on the wait_accept for the incoming connection requests
struct tcp_sock *tcp_sock_accept(struct tcp_sock *tsk)
{
    while (list_empty(&tsk->accept_queue)) {
        log(DEBUG, "waiting for incoming connection request.");
        sleep_on(tsk->wait_accept);
    }
    struct tcp_sock *child = tcp_sock_accept_dequeue(tsk);
    if (!child)
        return NULL;

    child->parent = NULL;
	child->NewReno_state = OPEN;
	child->cwnd = 1;
	child->ssthresh = 16;
	child->dupACKcount  = 0;


    return child;
}

// close the tcp sock, by releasing the resources, sending FIN/RST packet
// to the peer, switching TCP_STATE to closed
void tcp_sock_close(struct tcp_sock *tsk)
{
	switch (tsk->state) {
        case TCP_ESTABLISHED:
            tcp_set_state(tsk, TCP_FIN_WAIT_1);
            tcp_send_control_packet(tsk, TCP_FIN|TCP_ACK);
            break;
        case TCP_CLOSE_WAIT:
            tcp_set_state(tsk, TCP_LAST_ACK);
            tcp_send_control_packet(tsk, TCP_FIN|TCP_ACK);
            break;
        default:
            break;
    }
}

int tcp_sock_read(struct tcp_sock *tsk, char *buf, int len)
{
	while (ring_buffer_empty(tsk->rcv_buf)) {
		if (tsk->state == TCP_CLOSE_WAIT) {
			return 0;
		}
		sleep_on(tsk->wait_recv);
	}

	//pthread_mutex_lock(&tsk->rcv_buf->rw_lock);
	int rlen = read_ring_buffer(tsk->rcv_buf, buf, len);
	tsk->rcv_wnd += rlen;
	//pthread_mutex_unlock(&tsk->rcv_buf->rw_lock);

	wake_up(tsk->wait_recv);
	return rlen;
}

#define TCP_MSS (ETH_FRAME_LEN - ETHER_HDR_SIZE - IP_BASE_HDR_SIZE - TCP_BASE_HDR_SIZE)

int tcp_sock_write(struct tcp_sock *tsk, char *buf, int len)
{
	int send_len, packet_len;
	int remain_len = len;
	int already_len = 0;

	while (!list_empty(&tsk->send_buf)) {
		sleep_on(tsk->wait_send);
	}

	while (remain_len) {
		//log(DEBUG, "remain: %d, already: %d\n", remain_len, already_len);
		send_len = min(remain_len, TCP_MSS);
		packet_len = send_len + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;		
		char *packet = (char *)malloc(packet_len);
		memcpy(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE, buf + already_len, send_len);
		tcp_send_packet(tsk, packet, packet_len);
		remain_len -= send_len;
		already_len += send_len;
	}
	return len;
}
// 通用内存分配与数据拷贝函数
static void *tcp_alloc_copy_data(const void *data, size_t len)
{
    void *new_data = malloc(len);
    if (!new_data) {
        log(ERROR, "Memory allocation failed for data copy");
        return NULL;
    }
    memcpy(new_data, data, len);
    return new_data;
}
void tcp_send_buffer_add_packet(struct tcp_sock *tsk, char *packet, int len)
{
	send_buffer_entry *entry = malloc(sizeof(send_buffer_entry));
    if (!entry) {
        log(ERROR, "malloc send_buffer_entry failed");
        return;
    }
    entry->packet = tcp_alloc_copy_data(packet, len);
    if (!entry->packet) {
        log(ERROR, "malloc packet copy failed");
        free(entry);
        return;
    }
    entry->len = len;
    memcpy(entry->packet, packet, len);
    init_list_head(&entry->list);
    list_add_tail(&entry->list, &tsk->send_buf);
}
/*
基于收到的ACK包，遍历发送队列，将已经接收的数据包从队列中移除

提取报文的tcp头可以使用packet_to_tcp_hdr，注意报文中的字段是大端序
*/
int tcp_update_send_buffer(struct tcp_sock *tsk, u32 ack)
{
	int flag = 0;
    send_buffer_entry *entry, *entry_q;
    list_for_each_entry_safe(entry, entry_q, &tsk->send_buf, list) {
        struct tcphdr *tcp = packet_to_tcp_hdr(entry->packet);
        u32 seq = ntohl(tcp->seq);
        if (less_than_32b(seq, ack)) {
            list_delete_entry(&entry->list);
            free(entry->packet);
            free(entry);
			flag = 1;
        }
    }
	return flag;
}
/*
获取重传队列第一个包，修改ack号和checksum并通过ip_send_packet发送。

注意不要更新snd_nxt之类的参数，这是一个独立的重传报文。
*/
int tcp_retrans_send_buffer(struct tcp_sock *tsk)
{
	if (list_empty(&tsk->send_buf)) {
        log(ERROR, "no packet to retransmit");
        return -1;
    }
    send_buffer_entry *first_entry = list_entry(tsk->send_buf.next, send_buffer_entry, list);
    char *packet =tcp_alloc_copy_data(first_entry->packet, first_entry->len);
    if (!packet) {
        log(ERROR, "malloc failed in retransmission");
        return -1;
    }
    //memcpy(packet, first_entry->packet, first_entry->len);
    struct iphdr *ip = packet_to_ip_hdr(packet);
    struct tcphdr *tcp = packet_to_tcp_hdr(packet);

    tcp->ack = htonl(tsk->rcv_nxt);
    tcp->checksum = tcp_checksum(ip, tcp);
    ip->checksum = ip_checksum(ip);

    int tcp_data_len = ntohs(ip->tot_len) - IP_BASE_HDR_SIZE - TCP_BASE_HDR_SIZE;
   // log(DEBUG, "Retransmitting packet, seq: %u", ntohl(tcp->seq));

    ip_send_packet(packet, first_entry->len);
    return 0;
}

void tcp_recv_ofo_buffer_add_packet(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	recv_ofo_buf_entry *recv_entry = (recv_ofo_buf_entry *)malloc(sizeof(recv_ofo_buf_entry));
	recv_entry->seq = cb->seq;
	recv_entry->len = cb->pl_len;
	recv_entry->data = (char *)malloc(cb->pl_len);
	memcpy(recv_entry->data, cb->payload, cb->pl_len);
	init_list_head(&recv_entry->list);
	int inserted = 0;
	recv_ofo_buf_entry *entry, *entry_q;
	list_for_each_entry_safe(entry, entry_q, &tsk->rcv_ofo_buf, list) {
    	if (recv_entry->seq == entry->seq) {
        	return;
    	}
   	 	if (less_than_32b(recv_entry->seq, entry->seq)) {
        	list_add_tail(&recv_entry->list, &entry->list);
        	inserted = 1;
        	break;
    	}
	}
	if (!inserted) {
    	list_add_tail(&recv_entry->list, &tsk->rcv_ofo_buf);
	}
	tcp_move_recv_ofo_buffer(tsk);
}

int tcp_move_recv_ofo_buffer(struct tcp_sock *tsk)
{
	recv_ofo_buf_entry *entry, *entry_q;
	list_for_each_entry_safe(entry, entry_q, &tsk->rcv_ofo_buf, list) {
		if (tsk->rcv_nxt == entry->seq) {
			while (ring_buffer_free(tsk->rcv_buf) < entry->len) {
				sleep_on(tsk->wait_recv);
			}

			//pthread_mutex_lock(&tsk->rcv_buf->rw_lock);
			write_ring_buffer(tsk->rcv_buf, entry->data, entry->len);
			tsk->rcv_wnd -= entry->len;
			//pthread_mutex_unlock(&tsk->rcv_buf->rw_lock);
			wake_up(tsk->wait_recv);

			tsk->rcv_nxt += entry->len;
			list_delete_entry(&entry->list);
			free(entry->data);
			free(entry);
		}
		else if (less_than_32b(tsk->rcv_nxt, entry->seq)) {
			break;
		}
		// else {
		// 	log(ERROR, "rcv_nxt(%u) > entry->seq(%u)", tsk->rcv_nxt, entry->seq);
        //     return -1;
		// }
	}
	return 0;
}

void tcp_send_probe_packet(struct tcp_sock *tsk)
{
    char probe_data = 0;
    u32 probe_seq = tsk->snd_una - 1;

    int tcp_hdr_size = sizeof(struct tcphdr);
    char *tcp_segment = malloc(tcp_hdr_size + 1);
    if (!tcp_segment) {
        log(ERROR, "Memory allocation failed for probe packet");
        return;
    }

    struct tcphdr *tcp = (struct tcphdr *)tcp_segment;
    memset(tcp, 0, tcp_hdr_size);
    tcp->sport = htons(tsk->sk_sport);
    tcp->dport = htons(tsk->sk_dport);
    tcp->seq = htonl(probe_seq);
    tcp->off = tcp_hdr_size / 4;
    tcp->flags = TCP_ACK;
    tcp->rwnd = htons(tsk->rcv_wnd);

    memcpy(tcp_segment + tcp_hdr_size, &probe_data, 1);

    struct iphdr pseudo_ip;
    memset(&pseudo_ip, 0, sizeof(pseudo_ip));
    pseudo_ip.saddr = tsk->sk_sip;
    pseudo_ip.daddr = tsk->sk_dip;
    pseudo_ip.protocol = IPPROTO_TCP;
    pseudo_ip.tot_len = htons(tcp_hdr_size + 1);

    tcp->checksum = tcp_checksum(&pseudo_ip, tcp);
    ip_send_packet(tcp_segment, tcp_hdr_size + 1);
    free(tcp_segment);

    log(DEBUG, "Sent ZWP probe: snd_una=%u, adv_wnd=%u", tsk->snd_una, tsk->adv_wnd);
}
