#include "mospf_daemon.h"
#include "mospf_proto.h"
#include "mospf_nbr.h"
#include "mospf_database.h"
#include "arp.h"
#include "ip.h"
#include "list.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

extern ustack_t *instance;
pthread_mutex_t mospf_lock;
// 放到文件顶部或单独的头里
#define CLEANUP_TIMEOUT(ENTRY_TYPE, HEAD_PTR, ALIVE_FIELD, TIMEOUT, ON_CHANGE) do { \
    ENTRY_TYPE *ent, *tmp;                                                      \
    int changed = 0;                                                             \
    list_for_each_entry_safe(ent, tmp, HEAD_PTR, list) {                         \
        if (++ent->ALIVE_FIELD > (TIMEOUT)) {                                    \
            list_delete_entry(&ent->list); /* 从链表移除 */                     \
            free(ent);                                                           \
            changed = 1;                                                         \
        }                                                                        \
    }                                                                            \
    if (changed) { ON_CHANGE; }                                                  \
} while (0)

/* All-routers multicast MAC */
const u8 eth_allrouter_addr[ETH_ALEN] = {
    0x01,0x00,0x5e,0x00,0x00,0x05
};
void mospf_init()
{
	pthread_mutex_init(&mospf_lock, NULL);

	instance->area_id = 0;
	// get the ip address of the first interface
	iface_info_t *iface = list_entry(instance->iface_list.next, iface_info_t, list);
	instance->router_id = iface->ip;
	instance->sequence_num = 0;
	instance->lsuint = MOSPF_DEFAULT_LSUINT;

	iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		iface->helloint = MOSPF_DEFAULT_HELLOINT;
		init_list_head(&iface->nbr_list);
	}

	init_mospf_db();
}

void *sending_mospf_hello_thread(void *param);
void *sending_mospf_lsu_thread(void *param);
void *checking_nbr_thread(void *param);
void *checking_database_thread(void *param);

void mospf_run()
{
	pthread_t hello, lsu, nbr, db;
	pthread_create(&hello, NULL, sending_mospf_hello_thread, NULL);
	pthread_create(&lsu, NULL, sending_mospf_lsu_thread, NULL);
	pthread_create(&nbr, NULL, checking_nbr_thread, NULL);
	pthread_create(&db, NULL, checking_database_thread, NULL);
}
/*
 * allocate and zero a buffer of given length
 */
static char *alloc_zeroed(int len) {
    char *b = calloc(1, len);
    if (!b) log(ERROR, "calloc failed\n");
    return b;
}

/*
 * build Ethernet + IP headers into buf, pointing at payload_len bytes after IP
 * returns pointer to start of Ethernet header
 */
static void build_eth_ip_hdr(char *buf, iface_info_t *iface,
                             u32 dst_ip, int payload_len)
{
    struct ether_header *eh = (struct ether_header*)buf;
    struct iphdr         *ip = packet_to_ip_hdr(buf);

    ip_init_hdr(ip, iface->ip, dst_ip,
                IP_BASE_HDR_SIZE + payload_len, IPPROTO_MOSPF);
    memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
    memcpy(eh->ether_dhost, eth_allrouter_addr, ETH_ALEN);
    eh->ether_type = htons(ETH_P_IP);
}

/*
 * build and checksum an mOSPF message of given type + payload
 *   data    : pointer to the payload bytes (Hello or LSU struct + LSA array)
 *   data_len: length of that payload in bytes
 * fills mospf header and returns newly-allocated buffer of total length,
 * writing *out_len = total mOSPF portion length.
 */
static char *build_mospf_msg(u8 type, void *data, int data_len,
                             u32 rid, u32 aid, u16 *out_len)
{
    int total_len = MOSPF_HDR_SIZE + data_len;
    char *msg = alloc_zeroed(total_len);
    struct mospf_hdr *mh = (void*)msg;
    /* copy payload after header */
    memcpy(msg + MOSPF_HDR_SIZE, data, data_len);
    /* init and checksum */
    mospf_init_hdr(mh, type, total_len, rid, aid);
    mh->checksum = mospf_checksum(mh);
    *out_len = total_len;
    return msg;
}

/* Periodic Hello thread */
void *sending_mospf_hello_thread(void *p) {
    while (1) {
        sleep(MOSPF_DEFAULT_HELLOINT);
        pthread_mutex_lock(&mospf_lock);

        iface_info_t *iface;
        list_for_each_entry(iface, &instance->iface_list, list) {
            /* prepare Hello payload */
            struct mospf_hello h = { .mask = iface->mask,
                                     .helloint = htons(iface->helloint) };
            u16 mlen;
            char *mospf = build_mospf_msg(
                MOSPF_TYPE_HELLO, &h, MOSPF_HELLO_SIZE,
                instance->router_id, instance->area_id, &mlen
            );
            /* build full packet */
            int pktlen = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + mlen;
            char *pkt = alloc_zeroed(pktlen);
            build_eth_ip_hdr(pkt, iface, MOSPF_ALLSPFRouters, mlen);
            memcpy(pkt + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE, mospf, mlen);

            iface_send_packet(iface, pkt, pktlen);
            free(pkt);
            free(mospf);
        }

        pthread_mutex_unlock(&mospf_lock);
    }
    return NULL;
}

/* Periodic LSU thread */
void *sending_mospf_lsu_thread(void *p) {
    while (1) {
        sleep(MOSPF_DEFAULT_LSUINT);
        pthread_mutex_lock(&mospf_lock);

        /* 1) collect all LSAs */
        int cnt = 0;
        iface_info_t *iface;
        list_for_each_entry(iface, &instance->iface_list, list)
            cnt += iface->num_nbr ? iface->num_nbr : 1;

        struct mospf_lsa *lsa = calloc(cnt, sizeof(*lsa));
        int idx = 0;
        list_for_each_entry(iface, &instance->iface_list, list) {
            if (iface->num_nbr) {
                mospf_nbr_t *nbr;
                list_for_each_entry(nbr, &iface->nbr_list, list)
                    lsa[idx++] = (struct mospf_lsa){
                        .network = iface->ip & iface->mask,
                        .mask    = iface->mask,
                        .rid     = nbr->nbr_id
                    };
            } else {
                lsa[idx++] = (struct mospf_lsa){
                    .network = iface->ip & iface->mask,
                    .mask    = iface->mask,
                    .rid     = 0
                };
            }
        }

        /* 2) build LSU payload (struct + array) */
        instance->sequence_num++;
        int payload_len = MOSPF_LSU_SIZE + cnt * MOSPF_LSA_SIZE;
        char *payload = alloc_zeroed(payload_len);
        struct mospf_lsu *ml = (void*)payload;
        mospf_init_lsu(ml, cnt);
        ml->seq = htons(instance->sequence_num);
        ml->ttl = MOSPF_MAX_LSU_TTL;
        memcpy(payload + MOSPF_LSU_SIZE, lsa, cnt * MOSPF_LSA_SIZE);
        free(lsa);

        /* 3) wrap in mOSPF header */
        u16 mlen;
        char *mospf = build_mospf_msg(
            MOSPF_TYPE_LSU, payload, payload_len,
            instance->router_id, instance->area_id, &mlen
        );
        free(payload);

        /* 4) send to each neighbor via ARP */
        list_for_each_entry(iface, &instance->iface_list, list) {
            mospf_nbr_t *nbr;
            list_for_each_entry(nbr, &iface->nbr_list, list) {
                int pktlen = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + mlen;
                char *pkt = alloc_zeroed(pktlen);
                build_eth_ip_hdr(pkt, iface, nbr->nbr_ip, mlen);
                memcpy(pkt + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE, mospf, mlen);
                iface_send_packet_by_arp(iface, nbr->nbr_ip, pkt, pktlen);
                free(pkt);
            }
        }

        free(mospf);
        pthread_mutex_unlock(&mospf_lock);
    }
    return NULL;
}
/* Flood an LSU packet to all neighbors except the incoming interface */
static void flood_lsu(iface_info_t *incoming, char *pkt, int len) {
    iface_info_t *iface;
    list_for_each_entry(iface, &instance->iface_list, list) {
        if (iface == incoming) continue;
        mospf_nbr_t *nbr;
        list_for_each_entry(nbr, &iface->nbr_list, list) {
            char *copy = malloc(len);
            memcpy(copy, pkt, len);
            struct iphdr *ip = packet_to_ip_hdr(copy);
            ip->daddr = htonl(nbr->nbr_ip);
            ip->checksum = ip_checksum(ip);
            iface_send_packet_by_arp(iface, nbr->nbr_ip, copy, len);
        }
    }
}

/* Build and send a Hello on the given iface */
static void send_hello(iface_info_t *iface) {
    int pktlen = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE;
    char *buf = calloc(1, pktlen);
    struct ether_header *eh = (void*)buf;
    struct iphdr *ip = packet_to_ip_hdr(buf);
    struct mospf_hdr *mh = (void*)ip + IP_BASE_HDR_SIZE;
    struct mospf_hello *h = (void*)mh + MOSPF_HDR_SIZE;

    mospf_init_hello(h, iface->mask);
    mospf_init_hdr(mh, MOSPF_TYPE_HELLO,
                   MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE,
                   instance->router_id, instance->area_id);
    mh->checksum = mospf_checksum(mh);

    ip_init_hdr(ip, iface->ip, MOSPF_ALLSPFRouters,
                IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE,
                IPPROTO_MOSPF);

    memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
    memcpy(eh->ether_dhost, eth_allrouter_addr, ETH_ALEN);
    eh->ether_type = htons(ETH_P_IP);

    iface_send_packet(iface, buf, pktlen);
    free(buf);
}

/* Build and send an LSU to all neighbors */
static void send_lsu(void) {
    int cnt = 0;
    iface_info_t *iface;
    list_for_each_entry(iface, &instance->iface_list, list) {
        cnt += iface->num_nbr ? iface->num_nbr : 1;
    }

    int mlen = MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + cnt * MOSPF_LSA_SIZE;
    char *buf = calloc(1, mlen);
    struct mospf_hdr *mh = (void*)buf;
    struct mospf_lsu *ml = (void*)mh + MOSPF_HDR_SIZE;
    struct mospf_lsa *lsa = (void*)ml + MOSPF_LSU_SIZE;

    /* fill out LSAs */
    int i = 0;
    list_for_each_entry(iface, &instance->iface_list, list) {
        if (iface->num_nbr) {
            mospf_nbr_t *nbr;
            list_for_each_entry(nbr, &iface->nbr_list, list) {
                lsa[i++] = (struct mospf_lsa){
                    iface->ip & iface->mask,
                    iface->mask,
                    nbr->nbr_id
                };
            }
        } else {
            lsa[i++] = (struct mospf_lsa){
                iface->ip & iface->mask,
                iface->mask,
                0
            };
        }
    }

    mospf_init_lsu(ml, cnt);
    instance->sequence_num++;
    mospf_init_hdr(mh, MOSPF_TYPE_LSU, mlen,
                   instance->router_id, instance->area_id);
    mh->checksum = mospf_checksum(mh);

    /* send to each neighbor */
    list_for_each_entry(iface, &instance->iface_list, list) {
        mospf_nbr_t *nbr;
        list_for_each_entry(nbr, &iface->nbr_list, list) {
            int tot = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + mlen;
            char *pkt = calloc(1, tot);
            struct ether_header *eh = (void*)pkt;
            struct iphdr *ip2 = packet_to_ip_hdr(pkt);

            /* copy the mOSPF message behind Ethernet+IP */
            memcpy(pkt + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE, buf, mlen);
            ip_init_hdr(ip2, iface->ip, nbr->nbr_ip,
                        IP_BASE_HDR_SIZE + mlen, IPPROTO_MOSPF);

            memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
            eh->ether_type = htons(ETH_P_IP);

            iface_send_packet_by_arp(iface, nbr->nbr_ip, pkt, tot);
        }
    }

    free(buf);
}



/* 检查邻居超时线程 */
void *checking_nbr_thread(void *p) {
    while (1) {
        sleep(1);
        pthread_mutex_lock(&mospf_lock);

        iface_info_t *iface;
        list_for_each_entry(iface, &instance->iface_list, list) {
            /* 按邻居链表清理超时 nbr，触发 send_lsu() */
            CLEANUP_TIMEOUT(
                mospf_nbr_t,
                &iface->nbr_list,
                alive,
                3 * iface->helloint,
                send_lsu()
            );

            /* nbr 删除后重新计算 num_nbr */
            int cnt = 0;
            mospf_nbr_t *nbr;
            list_for_each_entry(nbr, &iface->nbr_list, list) {
                cnt++;
            }
            iface->num_nbr = cnt;
        }

        pthread_mutex_unlock(&mospf_lock);
    }
    return NULL;
}

/* 检查数据库超时线程 */
void *checking_database_thread(void *p) {
    while (1) {
        sleep(1);
        pthread_mutex_lock(&mospf_lock);

        /* 按 LSDB 清理超时 entry，触发 build_route_table() */
        CLEANUP_TIMEOUT(
            mospf_db_entry_t,
            &mospf_db,
            alive,
            MOSPF_DATABASE_TIMEOUT,
            build_route_table()
        );

        pthread_mutex_unlock(&mospf_lock);
    }
    return NULL;
}


/* 通用：查找或新增一个 LSDB 条目 */
static mospf_db_entry_t *
get_or_add_db_entry(u32 rid, u16 seq, int nadv, struct mospf_lsa *src)
{
    mospf_db_entry_t *db;
    list_for_each_entry(db, &mospf_db, list) {
        if (db->rid == rid) return db;
    }
    /* 不存在则新建 */
    db = malloc(sizeof(*db));
    *db = (mospf_db_entry_t){ .rid = rid };
    init_list_head(&db->list);
    list_add_tail(&db->list, &mospf_db);
    return db;
}

/* 通用：为一个 db_entry 分配并复制 LSA 数组 */
static void
copy_lsa_array(mospf_db_entry_t *db, int nadv, struct mospf_lsa *src)
{
    free(db->array);
    db->array = malloc(nadv * sizeof(*db->array));
    memcpy(db->array, src, nadv * sizeof(*db->array));
    db->nadv = nadv;
    db->alive = 0;
}

/* Handle incoming Hello: 更新或新增邻居，然后触发 LSU */
void handle_mospf_hello(iface_info_t *iface, const char *pkt, int len) {
    struct iphdr     *ip  = packet_to_ip_hdr(pkt);
    struct mospf_hdr *mh  = (void*)ip + IP_HDR_SIZE(ip);
    struct mospf_hello*h   = (void*)mh + MOSPF_HDR_SIZE;
    u32 rid  = ntohl(mh->rid),
        sip  = ntohl(ip->saddr),
        mask = ntohl(h->mask);

    pthread_mutex_lock(&mospf_lock);

    /* 查找或新增 */
    mospf_nbr_t *nbr;
    list_for_each_entry(nbr, &iface->nbr_list, list) {
        if (nbr->nbr_id == rid) {
            nbr->nbr_ip   = sip;
            nbr->nbr_mask = mask;
            nbr->alive    = 0;
            goto done_hello;
        }
    }
    /* 新邻居 */
    nbr = malloc(sizeof(*nbr));
    *nbr = (mospf_nbr_t){ .nbr_id = rid, .nbr_ip = sip,
                          .nbr_mask = mask, .alive = 0 };
    init_list_head(&nbr->list);
    list_add_tail(&nbr->list, &iface->nbr_list);
    iface->num_nbr++;
    instance->sequence_num++;

    send_lsu();

done_hello:
    pthread_mutex_unlock(&mospf_lock);
}

/* Handle incoming LSU: 更新／新增 LSDB 条目，TTL 递减后 Flood 并重建路由 */
void handle_mospf_lsu(iface_info_t *iface, char *pkt, int len) {
    struct iphdr    *ip = packet_to_ip_hdr(pkt);
    struct mospf_hdr*mh = (void*)ip + IP_HDR_SIZE(ip);
    struct mospf_lsu *ml = (void*)mh + MOSPF_HDR_SIZE;
    int nadv = ntohl(ml->nadv);
    u32 rid  = ntohl(mh->rid);

    if (rid == instance->router_id) return;

    pthread_mutex_lock(&mospf_lock);

    /* 查找或新增 DB 条目 */
    mospf_db_entry_t *db = get_or_add_db_entry(rid,
                                               ntohs(ml->seq),
                                               nadv,
                                               (void*)ml + MOSPF_LSU_SIZE);

    /* 只有序号更大或新创建才替换数组 */
    if (db->seq < ntohs(ml->seq) || db->array == NULL) {
        db->seq = ntohs(ml->seq);
        copy_lsa_array(db, nadv, (void*)ml + MOSPF_LSU_SIZE);

        if (ml->ttl > 1) {
            ml->ttl--;
            mh->checksum = mospf_checksum(mh);
            flood_lsu(iface, pkt, len);
        }
        build_route_table();
    }

    pthread_mutex_unlock(&mospf_lock);
}


/* Dispatcher for mOSPF packets */
void handle_mospf_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
	struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));

	if (mospf->version != MOSPF_VERSION) {
		log(ERROR, "received mospf packet with incorrect version (%d)", mospf->version);
		return ;
	}
	if (mospf->checksum != mospf_checksum(mospf)) {
		log(ERROR, "received mospf packet with incorrect checksum");
		return ;
	}
	if (ntohl(mospf->aid) != instance->area_id) {
		log(ERROR, "received mospf packet with incorrect area id");
		return ;
	}

	switch (mospf->type) {
		case MOSPF_TYPE_HELLO:
			handle_mospf_hello(iface, packet, len);
			break;
		case MOSPF_TYPE_LSU:
			handle_mospf_lsu(iface, packet, len);
			break;
		default:
			log(ERROR, "received mospf packet with unknown type (%d).", mospf->type);
			break;
	}
}
