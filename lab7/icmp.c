#include "icmp.h"
#include "ip.h"
#include "rtable.h"
#include "arp.h"
#include "base.h"
#include "log.h"
#include <stdlib.h>
#include <assert.h>

// icmp_send_packet has two main functions:
// 1.handle icmp packets sent to the router itself (ICMP ECHO REPLY).
// 2.when an error occurs, send icmp error packets.
// Note that the structure of these two icmp packets is different, you need to malloc different sizes of memory.
// Some function and macro definitions in ip.h/icmp.h can help you.
void icmp_send_packet(const char *in_pkt, int len, u8 type, u8 code)
{
	//assert(0 && "TODO: function icmp_send_packet not implemented!");
    // 解析输入数据包中的以太网头和 IP 头
    struct ether_header *in_eh = (struct ether_header *)in_pkt;
    struct iphdr *in_iphdr = packet_to_ip_hdr(in_pkt);

    // 计算输入包中 ICMP 部分的长度：总长度 - Ethernet 头 - IP 头
    int len_icmp = len - ETHER_HDR_SIZE - IP_HDR_SIZE(in_iphdr);
    int packet_len;

	 // 根据类型选择构造数据包的总长度
	if(type == ICMP_ECHOREPLY)
		packet_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + len_icmp;
	else
		packet_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + ICMP_HDR_SIZE + 
					 	IP_HDR_SIZE(in_iphdr) + ICMP_COPIED_DATA_LEN;
	
	char *packet = (char *)malloc(packet_len);
    if(packet == NULL) {
        fprintf(stderr, "malloc failed in icmp_send_packet\n");
        return;
    }
	struct ether_header *eh = (struct ether_header *)packet;
	memcpy(eh->ether_dhost, in_eh->ether_shost, ETH_ALEN);
	memcpy(eh->ether_shost, in_eh->ether_dhost, ETH_ALEN);
	eh->ether_type = htons(ETH_P_IP);

	struct iphdr *iphdr = packet_to_ip_hdr(packet);
	rt_entry_t *src_entry = longest_prefix_match(ntohl(in_iphdr->saddr));
	if (src_entry == NULL) {
        fprintf(stderr, "No matching route found for ICMP packet\n");
        free(packet);
        return;
    }
    ip_init_hdr(iphdr,
                src_entry->iface->ip,        
                ntohl(in_iphdr->saddr),      
                packet_len - ETHER_HDR_SIZE, 
                IPPROTO_ICMP);              
	struct icmphdr *icmp = (struct icmphdr *)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE);
	if (type == ICMP_ECHOREPLY) {
		// 对于 Echo Reply：复制原 ICMP 部分（排除以太网和 IP 头）到新包，然后更新 type 和 code
		memcpy((char*)icmp, (in_pkt + ETHER_HDR_SIZE + IP_HDR_SIZE(in_iphdr)), len_icmp);
		icmp->type = type;
		icmp->code = code;
	}
	else {
	 	// 对于错误信息：设定 ICMP 的 type 与 code，清零后4字节（标识符和序号部分），
        // 然后从偏移 8 开始复制原 IP 头和后续固定数据（ICMP_COPIED_DATA_LEN 字节）
		icmp->type = type;
		icmp->code = code;
		memset((char*)icmp + 4, 0, 4);
		memcpy((char*)icmp + 8, (char*)in_iphdr, IP_HDR_SIZE(in_iphdr) + ICMP_COPIED_DATA_LEN);
	}
	icmp->checksum = icmp_checksum(icmp, packet_len - ETHER_HDR_SIZE - IP_BASE_HDR_SIZE);

	ip_send_packet(packet, packet_len);


	
}
