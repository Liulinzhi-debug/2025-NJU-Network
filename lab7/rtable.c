#include "rtable.h"
#include "ip.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

struct list_head rtable;
pthread_mutex_t rt_lock;

void init_rtable()
{
	init_list_head(&rtable);

	pthread_mutex_init(&rt_lock, NULL);
}

rt_entry_t *new_rt_entry(u32 dest, u32 mask, u32 gw, iface_info_t *iface)
{
	rt_entry_t *entry = malloc(sizeof(*entry));
	memset(entry, 0, sizeof(*entry));

	init_list_head(&(entry->list));
	entry->dest = dest;
	entry->mask = mask;
	entry->gw = gw;
	entry->iface = iface;
	strcpy(entry->if_name, iface->name);

	return entry;
}

void add_rt_entry(rt_entry_t *entry)
{
	pthread_mutex_lock(&rt_lock);
	list_add_tail(&entry->list, &rtable);
	pthread_mutex_unlock(&rt_lock);
}

void remove_rt_entry(rt_entry_t *entry)
{
	pthread_mutex_lock(&rt_lock);
	list_delete_entry(&entry->list);
	free(entry);
	pthread_mutex_unlock(&rt_lock);
}

void load_rtable(struct list_head *new_rtable)
{
	pthread_mutex_lock(&rt_lock);

	rt_entry_t *entry, *q;
	list_for_each_entry_safe(entry, q, new_rtable, list) {
		list_delete_entry(&entry->list);
		list_add_tail(&entry->list, &rtable);
	}

	pthread_mutex_unlock(&rt_lock);
}

void clear_rtable()
{
	pthread_mutex_lock(&rt_lock);
	rt_entry_t *entry, *q;
	list_for_each_entry_safe(entry, q, &rtable, list) {
		list_delete_entry(&(entry->list));
		free(entry);
	}
	pthread_mutex_unlock(&rt_lock);
}

void print_rtable()
{
	// Print the routing table
	fprintf(stdout, "Routing Table:\n");
	fprintf(stdout, "dest\tmask\tgateway\tif_name\n");
	fprintf(stdout, "--------------------------------------\n");
	rt_entry_t *entry = NULL;

	pthread_mutex_lock(&rt_lock);

	list_for_each_entry(entry, &rtable, list) {
		fprintf(stdout, IP_FMT"\t"IP_FMT"\t"IP_FMT"\t%s\n", \
				HOST_IP_FMT_STR(entry->dest), \
				HOST_IP_FMT_STR(entry->mask), \
				HOST_IP_FMT_STR(entry->gw), \
				entry->if_name);
	}

	pthread_mutex_unlock(&rt_lock);

	fprintf(stdout, "--------------------------------------\n");
}

void load_rtable_from_kernel()
{
	struct list_head new_rtable;
	init_list_head(&new_rtable);

	read_kernel_rtable(&new_rtable);

	load_rtable(&new_rtable);
}
