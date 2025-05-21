#include "arp.h"
#include "base.h"
#include "types.h"
#include "ether.h"
#include "arpcache.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>
static void arp_send_common(iface_info_t *iface, 
                           u8 *dst_mac,          
                           u16 arp_op,           
                           u32 target_ip);

const u8 eth_broadcast_addr[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
const u8 arp_request_addr[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

// Utility function to update the Ethernet header 
void update_ethernet_header(struct ether_header *eh, iface_info_t *iface, u8 *dst_mac,int flag) {
    memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
    memcpy(eh->ether_dhost, dst_mac, ETH_ALEN);
    eh->ether_type = htons(flag);
}

// handle arp packet
// If the dest ip address of this arp packet is not equal to the ip address of the incoming iface, drop it.
// If it is an arp request packet, send arp reply to the destination, insert the ip->mac mapping into arpcache.
// If it is an arp reply packet, insert the ip->mac mapping into arpcache.
// Tips:
// You can use functions: htons, htonl, ntohs, ntohl to convert host byte order and network byte order (16 bits use ntohs/htons, 32 bits use ntohl/htonl).
// You can use function: packet_to_ether_arp() in arp.h to get the ethernet header in a packet.
void handle_arp_packet(iface_info_t *iface, char *packet, int len)
{
	struct ether_arp *arp = packet_to_ether_arp(packet);
    u32 target_ip = ntohl(arp->arp_tpa);  

    if (target_ip != iface->ip) {
        log(DEBUG, "Discard ARP packet: target IP %x not match iface %x", 
            target_ip, iface->ip);
        free(packet);
        return;
    }
    switch (ntohs(arp->arp_op)) {
    case ARPOP_REQUEST:
        log(DEBUG, "ARP Request from %x", ntohl(arp->arp_spa));
        arpcache_insert(ntohl(arp->arp_spa), arp->arp_sha);
        arp_send_reply(iface, arp);
        break;
    case ARPOP_REPLY:
        log(DEBUG, "ARP Reply from %x", ntohl(arp->arp_spa));
        arpcache_insert(ntohl(arp->arp_spa), arp->arp_sha);
        break;
    default:
        log(ERROR, "Unknown ARP opcode 0x%04x", ntohs(arp->arp_op));
    }
    free(packet);  

}

// send an arp reply packet
// Encapsulate an arp reply packet, send it out through iface_send_packet.
void arp_send_reply(iface_info_t *iface, struct ether_arp *req_hdr)
{
    arp_send_common(iface, 
                   req_hdr->arp_sha,  // 使用请求方的MAC作为目标
                   ARPOP_REPLY,
                   ntohl(req_hdr->arp_spa));	
}

// send an arp request
// Encapsulate an arp request packet, send it out through iface_send_packet.
void arp_send_request(iface_info_t *iface, u32 dst_ip)
{
	arp_send_common(iface, 
                eth_broadcast_addr, 
                ARPOP_REQUEST,
                dst_ip);
}

// send (IP) packet through arpcache lookup 
// Lookup the mac address of dst_ip in arpcache.
// If it is found, fill the ethernet header and emit the packet by iface_send_packet.
// Otherwise, pending this packet into arpcache and send arp request.
void iface_send_packet_by_arp(iface_info_t *iface, u32 dst_ip, char *packet, int len)
{
	struct ether_header *eh = (struct ether_header *)packet;

	u8 dst_mac[ETH_ALEN];
	int found = arpcache_lookup(dst_ip, dst_mac);
	if (found) {
		//log(DEBUG, "Found MAC address for IP %u, sending packet\n", dst_ip);
		update_ethernet_header(eh, iface, dst_mac,ETH_P_IP);
		iface_send_packet(iface, packet, len);
	}
	else {
		// log(DEBUG, "MAC address for IP %u not found, pending packet\n", dst_ip);
		arpcache_append_packet(iface, dst_ip, packet, len);
	}
	//assert(0 && "TODO: function iface_send_packet_by_arp not implemented!");
}
static void arp_send_common(iface_info_t *iface, 
                           u8 *dst_mac,          // 目标MAC
                           u16 arp_op,           // ARP操作码
                           u32 target_ip)       // 目标IP
						   {
    // 统一内存分配和初始化
    char *packet = malloc(ETHER_HDR_SIZE + sizeof(struct ether_arp));
    if (!packet) {
        log(ERROR, "ARP packet malloc failed");
        return;
    }
    memset(packet, 0, ETHER_HDR_SIZE + sizeof(struct ether_arp));
    // 统一以太网头设置
    struct ether_header *eh = (struct ether_header *)packet;
    memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
    memcpy(eh->ether_dhost, dst_mac, ETH_ALEN);
    eh->ether_type = htons(ETH_P_ARP);
    // 统一ARP头公共部分
    struct ether_arp *arp = (struct ether_arp *)(packet + ETHER_HDR_SIZE);
    arp->arp_hrd = htons(ARPHRD_ETHER);
    arp->arp_pro = htons(ETH_P_IP);
    arp->arp_hln = ETH_ALEN;
    arp->arp_pln = 4;
    arp->arp_op = htons(arp_op);
    memcpy(arp->arp_sha, iface->mac, ETH_ALEN);
    arp->arp_spa = htonl(iface->ip);
    // 差异化处理
    if (arp_op == ARPOP_REPLY) { // 应答包特殊处理
        memcpy(arp->arp_tha, dst_mac, ETH_ALEN); 
        arp->arp_tpa = htonl(target_ip);
    } else { // 请求包特殊处理
        memcpy(arp->arp_tha, arp_request_addr, ETH_ALEN);
        arp->arp_tpa = htonl(target_ip);
    }
    iface_send_packet(iface, packet, ETHER_HDR_SIZE + sizeof(struct ether_arp));
    //free(packet);
}