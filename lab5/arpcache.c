#include "arpcache.h"
#include "arp.h"
#include "ether.h"
#include "icmp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>

static arpcache_t arpcache;
void update_ethernet_header(struct ether_header *eh, iface_info_t *iface, u8 *dst_mac,int flag);
// initialize IP->mac mapping, request list, lock and sweep thread
void arpcache_init()
{
	bzero(&arpcache, sizeof(arpcache_t));

	init_list_head(&(arpcache.req_list));

	pthread_mutex_init(&arpcache.lock, NULL);

	pthread_create(&arpcache.thread, NULL, arpcache_sweep, NULL);
}

// release all the resources when exiting
void arpcache_destroy()
{
	pthread_mutex_lock(&arpcache.lock);

	struct arp_req *req_entry = NULL, *req_q;
	list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
		struct cached_pkt *pkt_entry = NULL, *pkt_q;
		list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list) {
			list_delete_entry(&(pkt_entry->list));
			free(pkt_entry->packet);
			free(pkt_entry);
		}

		list_delete_entry(&(req_entry->list));
		free(req_entry);
	}

	pthread_kill(arpcache.thread, SIGTERM);

	pthread_mutex_unlock(&arpcache.lock);
}

// look up the IP->mac mapping, need pthread_mutex_lock/unlock
// Traverse the table to find whether there is an entry with the same IP and mac address with the given arguments.
int arpcache_lookup(u32 ip4, u8 mac[ETH_ALEN])
{
	//assert(0 && "TODO: function arpcache_lookup not implemented!");
    int found = 0;

    pthread_mutex_lock(&arpcache.lock);
    for (int i = 0; i < MAX_ARP_SIZE; i++) {
        if (arpcache.entries[i].valid && arpcache.entries[i].ip4 == ip4) {
            memcpy(mac, arpcache.entries[i].mac, ETH_ALEN);
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&arpcache.lock);

    return found;
}
int get_empty_entry_with_rand(void)
{
	for (int i=0; i<MAX_ARP_SIZE; i++) {
		if (arpcache.entries[i].valid == 0) {
			return i;
		}
	}
	// 如果没有空闲条目，则随机替换一个
	return rand() % MAX_ARP_SIZE;
}

// insert the IP->mac mapping into arpcache, need pthread_mutex_lock/unlock
// If there is a timeout entry (attribute valid in struct) in arpcache, replace it.
// If there isn't a timeout entry in arpcache, randomly replace one.
// If there are pending packets waiting for this mapping, fill the ethernet header for each of them, and send them out.
// Tips:
// arpcache_t是完整的arp缓存表，里边的req_list是一个链表，它的每个节点(用arp_req结构体封装)里又存着一个链表头，这些二级链表(节点类型是cached_pkt)缓存着相同目标ip但不知道mac地址的包
void arpcache_insert(u32 ip4, u8 mac[ETH_ALEN])
{
	//assert(0 && "TODO: function arpcache_insert not implemented!");
		pthread_mutex_lock(&arpcache.lock);

	// 如果映射已存在，则更新条目
	for (int i=0; i<MAX_ARP_SIZE; i++) {
		if (arpcache.entries[i].valid  && arpcache.entries[i].ip4 == ip4) {
			memcpy(arpcache.entries[i].mac, mac, ETH_ALEN);
			arpcache.entries[i].added = time(NULL);
			pthread_mutex_unlock(&arpcache.lock);
			return;
		}
	}

	// 获取一个空闲或待替换的条目的下标
	int entry_id = get_empty_entry_with_rand();
	arpcache.entries[entry_id].ip4 = ip4;
	arpcache.entries[entry_id].added = time(NULL);
	arpcache.entries[entry_id].valid = 1;
	memcpy(arpcache.entries[entry_id].mac, mac, ETH_ALEN);

	// 遍历等待该 IP 映射的 ARP 请求，并发送所有缓存的数据包
	struct arp_req *req_entry = NULL, *req_q;
	list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
		if (req_entry->ip4 == ip4) {
			struct cached_pkt *pkt_entry, *pkt_q;
			list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list) {
				struct ether_header *eh = (struct ether_header *)pkt_entry->packet;

				update_ethernet_header(eh, req_entry->iface, mac,ETH_P_IP);
				iface_send_packet(req_entry->iface, pkt_entry->packet, pkt_entry->len);
				list_delete_entry(&(pkt_entry->list));
				//free(pkt_entry->packet);
				free(pkt_entry);
			}

			list_delete_entry(&(req_entry->list));
			free(req_entry);
		}
	}

	pthread_mutex_unlock(&arpcache.lock);
}

// append the packet to arpcache
// Look up in the list which stores pending packets, if there is already an entry with the same IP address and iface, 
// which means the corresponding arp request has been sent out, just append this packet at the tail of that entry (The entry may contain more than one packet).
// Otherwise, malloc a new entry with the given IP address and iface, append the packet, and send arp request.
// Tips:
// arpcache_t是完整的arp缓存表，里边的req_list是一个链表，它的每个节点(类型是arp_req)里又存着一个链表头，这些二级链表(节点类型是cached_pkt)缓存着相同目标ip但不知道mac地址的包
void arpcache_append_packet(iface_info_t *iface, u32 ip4, char *packet, int len)
{
	 pthread_mutex_lock(&arpcache.lock);

    char *packet_copy = malloc(len);
    if (!packet_copy) {
        pthread_mutex_unlock(&arpcache.lock);
        return;
    }
    memcpy(packet_copy, packet, len);

    struct arp_req *target_entry = NULL;
    struct arp_req *entry = NULL;
    list_for_each_entry(entry, &arpcache.req_list, list) {
        if (entry->ip4 == ip4 && entry->iface == iface) {
            target_entry = entry;
            break;
        }
    }

    if (!target_entry) {
        target_entry = malloc(sizeof(struct arp_req));
        if (!target_entry) {
            free(packet_copy);  
            pthread_mutex_unlock(&arpcache.lock);
            return;
        }

        target_entry->ip4 = ip4;
        target_entry->iface = iface;
        target_entry->sent = time(NULL);
        target_entry->retries = 0;
        init_list_head(&target_entry->cached_packets);
        list_add_tail(&target_entry->list, &arpcache.req_list);
    }

    struct cached_pkt *pkt_entry = malloc(sizeof(struct cached_pkt));
    if (!pkt_entry) {

        if (list_empty(&target_entry->cached_packets)) {
            list_delete_entry(&target_entry->list);
            free(target_entry);
        }
        free(packet_copy);
        pthread_mutex_unlock(&arpcache.lock);
        return;
    }
    pkt_entry->packet = packet_copy;
    pkt_entry->len = len;
    list_add_tail(&pkt_entry->list, &target_entry->cached_packets);

    int need_send_arp = 0;
    if (target_entry->retries == 0) {
        target_entry->retries = 1;
        target_entry->sent = time(NULL);
        need_send_arp = 1;
    }
    pthread_mutex_unlock(&arpcache.lock);
 
    if (need_send_arp) {
        arp_send_request(iface, ip4);
    }
}

// sweep arpcache periodically
// for IP->mac entry, if the entry has been in the table for more than 15 seconds, remove it from the table
// for pending packets, if the arp request is sent out 1 second ago, while the reply has not been received, retransmit the arp request
// If the arp request has been sent 5 times without receiving arp reply, for each pending packet, send icmp packet (DEST_HOST_UNREACHABLE), and drop these packets
// tips
// arpcache_t是完整的arp缓存表，里边的req_list是一个链表，它的每个节点(类型是arp_req)里又存着一个链表头，这些二级链表(节点类型是cached_pkt)缓存着相同目标ip但不知道mac地址的包
void *arpcache_sweep(void *arg) 
{
	while (1) {
		//1ms
		sleep(1);
		//fprintf(stderr, "TODO: sweep arpcache periodically: remove old entries, resend arp requests .\n");
		pthread_mutex_lock(&arpcache.lock);

		time_t now = time(NULL);
        for (int i = 0; i < MAX_ARP_SIZE; i++) {

            if (arpcache.entries[i].valid && (now - arpcache.entries[i].added > ARP_ENTRY_TIMEOUT)) {
                arpcache.entries[i].valid = 0;
            }
        }


		struct list_head drop_list;
		init_list_head(&drop_list);

		struct arp_req *req_entry = NULL, *req_q;
		list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
			if(now-req_entry->sent >= 1){
				req_entry->retries++;
				req_entry->sent = now;
				if(req_entry->retries <= ARP_REQUEST_MAX_RETRIES){
					arp_send_request(req_entry->iface, req_entry->ip4);
				}else{
					struct cached_pkt *pkt_entry = NULL, *pkt_q;
					list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list) {
						list_delete_entry(&pkt_entry->list);
						list_add_tail(&pkt_entry->list, &drop_list);
					}
					list_delete_entry(&req_entry->list);
					free(req_entry);
				}
			}
		}
		pthread_mutex_unlock(&arpcache.lock);

		struct cached_pkt *pkt_entry = NULL, *pkt_q;
		list_for_each_entry_safe(pkt_entry, pkt_q, &drop_list, list){
			icmp_send_packet(pkt_entry->packet, pkt_entry->len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
			free(pkt_entry);
		}
	}

	return NULL;

}
