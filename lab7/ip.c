#include "ip.h"
#include "icmp.h"
#include "arpcache.h"
#include "rtable.h"
#include "arp.h"

#include "mospf_proto.h"
#include "mospf_daemon.h"

#include "log.h"

#include <stdlib.h>
#include <assert.h>


void handle_ip_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *iphdr = packet_to_ip_hdr(packet);
	u32 dest_ip = ntohl(iphdr->daddr);
	//log(DEBUG, "handle ip packet\n");

	if (dest_ip == iface->ip) {
		if (iphdr->protocol == IPPROTO_ICMP) {
			unsigned char *icmp_type = (unsigned char *)iphdr + IP_HDR_SIZE(iphdr);
			if (*icmp_type == ICMP_ECHOREQUEST) {
				log(DEBUG, "handle icmp request packet\n");
				icmp_send_packet(packet, len, ICMP_ECHOREPLY, 0);
			}
		}
		else if (iphdr->protocol == IPPROTO_MOSPF) {
			handle_mospf_packet(iface, packet, len);
		}
		free(packet);
	}
	else if (dest_ip == MOSPF_ALLSPFRouters) {
		if (iphdr->protocol == IPPROTO_MOSPF) {
			handle_mospf_packet(iface, packet, len);
		}
		else {
			log(ERROR, "handle mospf packet, but protocol != IPPROTO_MOSPF\n");
		}
		free(packet);
	}
	else { // forward the packet
		ip_forward_packet(dest_ip, packet, len);
	}
}

// When forwarding the packet, you should check the TTL, update the checksum and TTL.
// Then, determine the next hop to forward the packet, then send the packet by iface_send_packet_by_arp.
// The interface to forward the packet is specified by longest_prefix_match.
void ip_forward_packet(u32 ip_dst, char *packet, int len)
{
	//assert(0 && "TODO: function ip_forward_packet not implemented!");
	rt_entry_t *rt_entry = longest_prefix_match(ip_dst);
    if (!rt_entry) {

        icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);
        return;
    }
    
    struct iphdr *ip = packet_to_ip_hdr(packet);
    ip->ttl--;
    if (ip->ttl <= 0) {
        icmp_send_packet(packet, len, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);
        return;
    }
    
    ip->checksum = ip_checksum(ip);
    u32 next_hop = rt_entry->gw ? rt_entry->gw : ip_dst;
    iface_send_packet_by_arp(rt_entry->iface, next_hop, packet, len);
}
