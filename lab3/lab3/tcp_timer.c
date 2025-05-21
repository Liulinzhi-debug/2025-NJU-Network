#include "tcp.h"
#include "tcp_timer.h"
#include "tcp_sock.h"
#include "log.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>

#ifndef max
#	define max(x,y) ((x)>(y) ? (x) : (y))
#endif

struct list_head timer_list;
struct list_head retrans_timer_list;
pthread_mutex_t timer_list_lock;
#define TIMER_TYPE_TIMEWAIT 0
#define TIMER_TYPE_RETRANS 1
#define TIMER_TYPE_PERSIST 2

#define TCP_MSS (ETH_FRAME_LEN - ETHER_HDR_SIZE - IP_BASE_HDR_SIZE - TCP_BASE_HDR_SIZE)
// scan the timer_list, find the tcp sock which stays for at 2*MSL, release it
void tcp_scan_timer_list()
{
	//fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	struct tcp_timer *time_entry = NULL, *time_q = NULL;
	list_for_each_entry_safe(time_entry, time_q, &timer_list, list) {
		if (time_entry->enable == 1 && time_entry->type == 0 && ((time(NULL) - time_entry->timeout) > TCP_TIMEWAIT_TIMEOUT / 1000000)) {
			struct tcp_sock *tsk = timewait_to_tcp_sock(time_entry);
			list_delete_entry(&time_entry->list);
			tcp_set_state(tsk, TCP_CLOSED);
			tcp_unhash(tsk);
			tcp_bind_unhash(tsk);
		}
	}
}

// set the timewait timer of a tcp sock, by adding the timer into timer_list
void tcp_set_timewait_timer(struct tcp_sock *tsk)
{
	//fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	tsk->timewait.type = 0;
	tsk->timewait.enable = 1;
	tsk->timewait.timeout = time(NULL);
	list_add_tail(&tsk->timewait.list, &timer_list);
}

// scan the timer_list periodically by calling tcp_scan_timer_list
void *tcp_timer_thread(void *arg)
{
	init_list_head(&timer_list);
	while (1) {
		usleep(TCP_TIMER_SCAN_INTERVAL);
		tcp_scan_timer_list();
	}

	return NULL;
}

// set the restrans timer of a tcp sock, by adding the timer into timer_list
void tcp_set_retrans_timer(struct tcp_sock *tsk)
{
	if (tsk->retrans_timer.enable) {
		tsk->retrans_timer.timeout = TCP_RETRANS_INTERVAL_INITIAL;
		return;
	}
	tsk->retrans_timer.type = 1;
	tsk->retrans_timer.enable = 1;
	tsk->retrans_timer.timeout = TCP_RETRANS_INTERVAL_INITIAL;
	tsk->retrans_timer.rtt_cnt = 0;
	init_list_head(&tsk->retrans_timer.list);
	list_add_tail(&tsk->retrans_timer.list, &retrans_timer_list);
	//log(DEBUG, "Set retrans timer, timeout = %d", tsk->retrans_timer.timeout);
}

void tcp_update_retrans_timer(struct tcp_sock *tsk)
{
	if (list_empty(&tsk->send_buf) && tsk->retrans_timer.enable) {
		tsk->retrans_timer.enable = 0;
		list_delete_entry(&tsk->retrans_timer.list);
		wake_up(tsk->wait_send);
	}
	 //log(DEBUG, "Updated retrans timer");
}

void tcp_unset_retrans_timer(struct tcp_sock *tsk)
{
	if (!list_empty(&tsk->retrans_timer.list)) {
		tsk->retrans_timer.enable = 0;
		list_delete_entry(&tsk->retrans_timer.list);
		wake_up(tsk->wait_send);
	}
	else {
		log(ERROR, "unset an empty retrans timer\n");
	}
}

void tcp_scan_retrans_timer_list(void)
{
	struct tcp_sock *tsk;
	struct tcp_timer *time_entry, *time_q;

	list_for_each_entry_safe(time_entry, time_q, &retrans_timer_list, list) {
		time_entry->timeout -= TCP_RETRANS_SCAN_INTERVAL;
		tsk = retranstimer_to_tcp_sock(time_entry);
		if (time_entry->timeout <= 0) {
			if(time_entry->rtt_cnt >= MAX_RETRANS_NUM && tsk->state != TCP_CLOSED){
				list_delete_entry(&time_entry->list);
				if (!tsk->parent) {
					tcp_unhash(tsk);
				}	
				wait_exit(tsk->wait_connect);
				wait_exit(tsk->wait_accept);
				wait_exit(tsk->wait_recv);
				wait_exit(tsk->wait_send);
				
				tcp_set_state(tsk, TCP_CLOSED);
				tcp_send_control_packet(tsk, TCP_RST);
			}
			else if (tsk->state != TCP_CLOSED) {
				log(DEBUG, "retrans time: %d\n", time_entry->rtt_cnt + 1);
				tsk->ssthresh = max((u32)(tsk->cwnd / 2), 1);
				tsk->cwnd = 1;
				tsk->dupACKcount=0;
				tsk->NewReno_state = LOSS;
				tsk->loss_point = tsk->snd_nxt;
				time_entry->rtt_cnt += 1;
				time_entry->timeout = TCP_RETRANS_INTERVAL_INITIAL * (1 << time_entry->rtt_cnt);
				tcp_retrans_send_buffer(tsk);
			}
		}
	}
}

void *tcp_retrans_timer_thread(void *arg)
{
	init_list_head(&retrans_timer_list);
	while(1){
		usleep(TCP_RETRANS_SCAN_INTERVAL);
		tcp_scan_retrans_timer_list();
	}

	return NULL;
}

/* 
 * 计算发送窗口剩余大小，公式：
 *    remaining = snd_una + snd_wnd - snd_nxt
 * 如果剩余窗口大小 >= TCP_MSS，则返回1，否则返回0
 */
  int tcp_tx_window_test(struct tcp_sock *tsk) {
	 u32 remaining = tsk->snd_una + tsk->snd_wnd - tsk->snd_nxt;
	 return (remaining >= TCP_MSS) ? 1 : 0;
 }
 /*
  * 启用 persist timer
  * 1. 若已启用，则直接返回
  * 2. 初始化定时器参数，timeout 设置为 TCP_RETRANS_INTERVAL_INITIAL
  * 3. 增加引用计数，并加入 timer_list
  */
  void tcp_set_persist_timer(struct tcp_sock *tsk)
  {
	  //pthread_mutex_lock(&timer_list_lock);
	  // 假设 tsk->persist_timer 是 struct tcp_timer 类型的成员
	  if (tsk->persist_timer.enable) {
		 // pthread_mutex_unlock(&timer_list_lock);
		  return;
	  }
	  tsk->persist_timer.type = 2;  
	  tsk->persist_timer.timeout = TCP_RETRANS_INTERVAL_INITIAL;  // 初始超时设置
	  tsk->persist_timer.enable = 1;
	  tsk->ref_cnt++;  
	  list_add_tail(&tsk->persist_timer.list, &timer_list);
	  //pthread_mutex_unlock(&timer_list_lock);
	  
	 // log(DEBUG, "Set persist timer, timeout = %d", tsk->persist_timer.timeout);
  }
  
  
 /*
  * 禁用 persist timer
  * 1. 若已经禁用，则直接返回
  * 2. 从 timer_list 中移除，并减少引用计数
  */
  void tcp_unset_persist_timer(struct tcp_sock *tsk)
  {
	  //pthread_mutex_lock(&timer_list_lock);
	  if (!tsk->persist_timer.enable) {
		 // pthread_mutex_unlock(&timer_list_lock);
		  return;
	  }
	  tsk->persist_timer.enable = 0;
	  list_delete_entry(&tsk->persist_timer.list);
	  free_tcp_sock(tsk);  // 释放多余的引用
	  //pthread_mutex_unlock(&timer_list_lock);
	  
	  //log(DEBUG, "Unset persist timer");
  }

//cwnd 记录函数：
void *tcp_cwnd_thread(void *arg) {
    struct tcp_sock *tsk = (struct tcp_sock *)arg;
    FILE *fp = fopen("cwnd.txt", "w");

    int time_us = 0;
    while (tsk->state == TCP_ESTABLISHED && time_us < 1000000) {
        usleep(500);
        time_us += 500;
        fprintf(fp, "%d %f %u %u\n", time_us, tsk->cwnd, tsk->ssthresh, tsk->adv_wnd);
    }
    fclose(fp);
    return NULL;
}