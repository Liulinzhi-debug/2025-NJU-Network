#include "mospf_database.h"
#include "mospf_nbr.h"
#include "rtable.h"      
#include "ip.h"
#include "list.h"
#include "log.h"

#include <limits.h>
#include <stdlib.h>
#include <stdio.h>

#define MAX_NODE 128

struct list_head mospf_db;
static int       node_num;
static u32       node_map[MAX_NODE];
static int       graph[MAX_NODE][MAX_NODE];
static int       dist[MAX_NODE], prevv[MAX_NODE], used[MAX_NODE];
static int       stack[MAX_NODE], stack_top;

// 初始化 LSDB
void init_mospf_db(void)
{
    init_list_head(&mospf_db);
}

// 将 rid 映射到索引，若不存在返回 -1
static int rid_to_index(u32 rid)
{
    for (int i = 0; i < node_num; i++) {
        if (node_map[i] == rid) return i;
    }
    return -1;
}

// 检查是否已映射
static int node_mapped(u32 rid)
{
    return rid_to_index(rid) >= 0;
}

// 构建节点映射（Router ID 列表）
static void get_node_mapped(void)
{
    node_map[0] = instance->router_id;
    node_num    = 1;
    // 邻居
    iface_info_t *ifp;
    list_for_each_entry(ifp, &instance->iface_list, list) {
        mospf_nbr_t *nbr;
        list_for_each_entry(nbr, &ifp->nbr_list, list) {
            if (!node_mapped(nbr->nbr_id) && node_num < MAX_NODE)
                node_map[node_num++] = nbr->nbr_id;
        }
    }
    // 数据库
    mospf_db_entry_t *db;
    list_for_each_entry(db, &mospf_db, list) {
        if (!node_mapped(db->rid) && node_num < MAX_NODE)
            node_map[node_num++] = db->rid;
        for (int i = 0; i < db->nadv; i++) {
            u32 rid = db->array[i].rid;
            if (rid && !node_mapped(rid) && node_num < MAX_NODE)
                node_map[node_num++] = rid;
        }
    }
}

// 初始化拓扑图邻接矩阵
static void init_graph(void)
{
    for (int i = 0; i < node_num; i++)
        for (int j = 0; j < node_num; j++)
            graph[i][j] = (i == j ? 0 : INT_MAX);

    // 添加边：接口->邻居
    iface_info_t *ifp;
    list_for_each_entry(ifp, &instance->iface_list, list) {
        mospf_nbr_t *nbr;
        list_for_each_entry(nbr, &ifp->nbr_list, list) {
            int u = 0;
            int v = rid_to_index(nbr->nbr_id);
            if (v >= 0) graph[u][v] = graph[v][u] = 1;
        }
    }
    // 添加边：数据库条目间
    mospf_db_entry_t *db;
    list_for_each_entry(db, &mospf_db, list) {
        int u = rid_to_index(db->rid);
        if (u < 0) continue;
        for (int i = 0; i < db->nadv; i++) {
            int v = rid_to_index(db->array[i].rid);
            if (v >= 0) graph[u][v] = graph[v][u] = 1;
        }
    }
}

// Dijkstra 最短路径
static void run_dijkstra(void)
{
    for (int i = 0; i < node_num; i++) {
        dist[i] = INT_MAX;
        used[i] = 0;
        prevv[i] = -1;
    }
    dist[0] = 0;
    stack_top = 0;

    for (int it = 0; it < node_num; it++) {
        int u = -1, best = INT_MAX;
        for (int i = 0; i < node_num; i++) {
            if (!used[i] && dist[i] < best) {
                best = dist[i];
                u = i;
            }
        }
        if (u < 0) break;
        used[u] = 1;
        stack[stack_top++] = u;
        for (int v = 0; v < node_num; v++) {
            if (!used[v] && graph[u][v] < INT_MAX && dist[u] + graph[u][v] < dist[v]) {
                dist[v] = dist[u] + graph[u][v];
                prevv[v] = u;
            }
        }
    }
}

// 从 prevv 回溯到下一跳
static int find_next_hop(int idx, u32 *gw, iface_info_t **oif)
{
    int cur = idx;
    while (prevv[cur] != 0) cur = prevv[cur];
    u32 nrid = node_map[cur];
    iface_info_t *ifp;
    list_for_each_entry(ifp, &instance->iface_list, list) {
        mospf_nbr_t *nbr;
        list_for_each_entry(nbr, &ifp->nbr_list, list) {
            if (nbr->nbr_id == nrid) {
                *gw = nbr->nbr_ip;
                *oif = ifp;
                return 1;
            }
        }
    }
    return 0;
}

// 安装单个节点的路由
static void install_for(int idx)
{
    u32 rid = node_map[idx];
    u32 gw;
    iface_info_t *oif;
    if (!find_next_hop(idx, &gw, &oif)) return;

    mospf_db_entry_t *db;
    list_for_each_entry(db, &mospf_db, list) {
        if (db->rid == rid) {
            for (int i = 0; i < db->nadv; i++) {
                rt_entry_t *e = new_rt_entry(
                    db->array[i].network,
                    db->array[i].mask,
                    gw, oif
                );
                add_rt_entry(e);
            }
            break;
        }
    }
}
void clear_route_table(void)
{
	rt_entry_t *rt_entry, *rt_q;
	list_for_each_entry_safe(rt_entry, rt_q, &rtable, list) {
		if (rt_entry->gw) {
            remove_rt_entry(rt_entry);
        } 
	}
}

// 构建路由表
void build_route_table(void)
{
    clear_route_table();
    get_node_mapped();
    init_graph();
    run_dijkstra();
    for (int i = 1; i < stack_top; i++) {
        install_for(stack[i]);
    }
}
