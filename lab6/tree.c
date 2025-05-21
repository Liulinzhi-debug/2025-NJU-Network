#include "tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>


static node_t* rootBasic = NULL;

static node_t* new_node_basic() {
    node_t* n = malloc(sizeof(node_t));
    if (!n) { perror("malloc basic"); exit(1); }
    n->type = I_NODE;
    n->port = 0;
    n->dest = 0;
    n->lchild = n->rchild = NULL;
    return n;
}

static uint32_t parse_ip(const char* s) {
    unsigned a,b,c,d;
    if (sscanf(s, "%u.%u.%u.%u", &a,&b,&c,&d) != 4) return 0;
    return (a<<24)|(b<<16)|(c<<8)|d;
}

uint32_t* read_test_data(const char* lookup_file) {
    FILE* fp = fopen(lookup_file, "r");
    if (!fp) { perror("fopen lookup"); return NULL; }
    uint32_t* arr = malloc(sizeof(uint32_t)*TEST_SIZE);
    char buf[64];
    for (int i = 0; i < TEST_SIZE; i++) {
        if (!fgets(buf, sizeof(buf), fp)) { arr[i] = 0; continue; }
        char* nl = strchr(buf, '\n'); if (nl) *nl = '\0';
        arr[i] = parse_ip(buf);
    }
    fclose(fp);
    return arr;
}

void create_tree(const char* forward_file) {
    FILE* fp = fopen(forward_file, "r");
    if (!fp) { perror("fopen basic"); return; }
    if (!rootBasic) rootBasic = new_node_basic();
    char ip_s[64]; int prefix, port;
    while (fscanf(fp, "%63s %d %d", ip_s, &prefix, &port) == 3) {
        uint32_t ip = parse_ip(ip_s);
        uint32_t mask = prefix ? (0xFFFFFFFFu << (32-prefix)) : 0;
        uint32_t ip_m = ip & mask;
        node_t* cur = rootBasic;
        for (int i = 0; i < prefix; i++) {
            int b = (ip_m >> (31-i)) & 1;
            if (b == 0) {
                if (!cur->lchild) cur->lchild = new_node_basic();
                cur = cur->lchild;
            } else {
                if (!cur->rchild) cur->rchild = new_node_basic();
                cur = cur->rchild;
            }
        }
        cur->type = M_NODE;
        cur->port = (uint32_t)port;
    }
    fclose(fp);
}

uint32_t* lookup_tree(uint32_t* ip_vec) {
    uint32_t* res = malloc(sizeof(uint32_t)*TEST_SIZE);
    for (int i = 0; i < TEST_SIZE; i++) {
        uint32_t ip = ip_vec[i];
        uint32_t best = (uint32_t)-1;
        node_t* cur = rootBasic;
        if (cur && cur->type == M_NODE) best = cur->port;
        for (int b = 31; b >= 0 && cur; b--) {
            cur = ((ip >> b) & 1) ? cur->rchild : cur->lchild;
            if (cur && cur->type == M_NODE) best = cur->port;
        }
        res[i] = best;
    }
    return res;
}

/* ====================================
   16位一级表 + 4位stride二级Trie
   ==================================== */

#define FIRST_LEVEL (1 << MAP_SHIFT)  // 65536
#define STRIDE 4
#define CHILDREN (1 << STRIDE)        // 16


typedef struct Node4 {
    struct Node4* child[CHILDREN];
    int port;  // -1 if none
} Node4;


typedef struct {
    int port;    
    Node4* trie; 
} AdvEntry;

static AdvEntry advMap[FIRST_LEVEL];

static Node4* new_node4() {
    Node4* n = malloc(sizeof(Node4));
    if (!n) { perror("mallocNode4"); exit(1); }
    for (int i = 0; i < CHILDREN; i++) n->child[i] = NULL;
    n->port = -1;
    return n;
}

void create_tree_advance(const char* forward_file) {
    for (int i = 0; i < FIRST_LEVEL; i++) {
        advMap[i].port = -1;
        advMap[i].trie = NULL;
    }
    FILE* fp = fopen(forward_file, "r");
    if (!fp) { perror("fopen adv"); return; }
    char ip_s[64]; int prefix, port;
    while (fscanf(fp, "%63s %d %d", ip_s, &prefix, &port) == 3) {
        uint32_t ip = parse_ip(ip_s);
        if (prefix <= MAP_SHIFT) {
            int span = 1 << (MAP_SHIFT - prefix);
            int start = (ip >> MAP_SHIFT) & (~(span - 1));
            for (int j = 0; j < span; j++) {
                advMap[start + j].port = port;
            }
        } else {
            int idx = ip >> MAP_SHIFT;
            int rem = prefix - MAP_SHIFT;
            if (!advMap[idx].trie) advMap[idx].trie = new_node4();
            Node4* node = advMap[idx].trie;
            uint32_t suffix = ip & 0xFFFF;
            int full = rem / STRIDE;
            int last = rem % STRIDE;
            for (int s = 0; s < full; s++) {
                int shift = 16 - STRIDE * (s + 1);
                int c = (suffix >> shift) & (CHILDREN - 1);
                if (!node->child[c]) node->child[c] = new_node4();
                node = node->child[c];
            }
            if (last) {
                int shift = 16 - STRIDE * full - last;
                int base = (suffix >> shift) & ((1 << last) - 1);
                int span = 1 << (STRIDE - last);
                int start = base << (STRIDE - last);
                for (int j = 0; j < span; j++) {
                    if (!node->child[start + j]) node->child[start + j] = new_node4();
                    node->child[start + j]->port = port;
                }
            } else {
                node->port = port;
            }
        }
    }
    fclose(fp);
}

uint32_t* lookup_tree_advance(uint32_t* ip_vec) {
    uint32_t* res = malloc(sizeof(uint32_t)*TEST_SIZE);
    for (int i = 0; i < TEST_SIZE; i++) {
        uint32_t ip = ip_vec[i];
        int idx = ip >> MAP_SHIFT;
        int best = advMap[idx].port;
        Node4* node = advMap[idx].trie;
        if (node) {
            uint32_t suffix = ip & 0xFFFF;
            for (int s = 0; s < 16/STRIDE; s++) {
                int shift = 16 - STRIDE * (s + 1);
                int c = (suffix >> shift) & (CHILDREN - 1);
                node = node->child[c];
                if (!node) break;
                if (node->port != -1) best = node->port;
            }
        }
        res[i] = best;
    }
    return res;
}
