#include "tcp.h"
#include "tcp_sock.h"
#include "tcp_timer.h"

#include "log.h"
#include "ring_buffer.h"

#include <stdlib.h>
void *tcp_cwnd_thread(void *arg);
// update the snd_wnd of tcp_sock
//
// if the snd_wnd before updating is zero, notify tcp_sock_send (wait_send)
static inline void tcp_update_window(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	// u16 old_snd_wnd = tsk->snd_wnd;
	// tsk->snd_wnd = min(cb->rwnd, tsk->cwnd * TCP_MSS);
	// //tsk->snd_una = greater_than_32b(cb->ack, tsk->snd_una) ? cb->ack : tsk->snd_una;
	// tsk->snd_una = cb->ack;
	// tsk->adv_wnd=cb->rwnd;
	// if (old_snd_wnd <= 0)
	// 	wake_up(tsk->wait_send);
	int old_window_ok = tcp_tx_window_test(tsk);
    //tsk->adv_wnd += (cb->ack - tsk->snd_una);
	tsk->snd_una = greater_than_32b(cb->ack, tsk->snd_una) ? cb->ack : tsk->snd_una;
    tsk->snd_una = cb->ack;

    tsk->snd_wnd =min(cb->rwnd, tsk->cwnd * TCP_MSS);
    int new_window_ok = tcp_tx_window_test(tsk);
	if(tsk->snd_wnd<TCP_MSS){
		//log(DEBUG, "tsk->snd_wnd   <   TCP_MSS");
		tcp_set_persist_timer(tsk);
	}
	else{
		//log(DEBUG, "tsk->snd_wnd   >   TCP_MSS");
		tcp_unset_persist_timer(tsk);
	}
    if (!old_window_ok && new_window_ok) {
		//log(DEBUG,"in tcp_update_window_locked wake_up");
        wake_up(tsk->wait_send);
    }
}

// update the snd_wnd safely: cb->ack should be between snd_una and snd_nxt
static inline void tcp_update_window_safe(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	if (less_or_equal_32b(tsk->snd_una, cb->ack) && less_or_equal_32b(cb->ack, tsk->snd_nxt))
		tcp_update_window(tsk, cb);
}

#ifndef max
#	define max(x,y) ((x)>(y) ? (x) : (y))
#endif

// check whether the sequence number of the incoming packet is in the receiving
// window
static inline int is_tcp_seq_valid(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u32 rcv_end = tsk->rcv_nxt + max(tsk->rcv_wnd, 1);
	if (less_than_32b(cb->seq, rcv_end) && less_or_equal_32b(tsk->rcv_nxt, cb->seq_end)) {
		return 1;
	}
	else {
		log(ERROR, "received packet with invalid seq, drop it.");
		//log(ERROR, "cb->seq: %d, rcv_end: %d, rcv_nxt: %d, cb->seq_end: %d\n", cb->seq, rcv_end, tsk->rcv_nxt, cb->seq_end);
		return 0;
	}
}


void solve_receive_data(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	if (less_than_32b(cb->seq, tsk->rcv_nxt)) {
		tcp_send_control_packet(tsk, TCP_ACK);
		return;
	}

	while (ring_buffer_full(tsk->rcv_buf)) {
		sleep_on(tsk->wait_recv);
	}

	tcp_recv_ofo_buffer_add_packet(tsk, cb);
	//tcp_move_recv_ofo_buffer(tsk);
	//tsk->snd_una = greater_than_32b(cb->ack, tsk->snd_una) ? cb->ack : tsk->snd_una;

	tcp_update_send_buffer(tsk, cb->ack);
	tcp_update_retrans_timer(tsk);

	tcp_send_control_packet(tsk, TCP_ACK);
}

void tcp_congestion_control(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet) {
	int ack_valid = tcp_update_send_buffer(tsk, cb->ack);
	switch (tsk->NewReno_state) {
		case OPEN:
   		case DISORDER: {
          	if (ack_valid) {
                // 收到新ACK：如果 cwnd 小于 ssthresh 进入慢启动，否则处于拥塞避免状态
                if (tsk->cwnd < tsk->ssthresh)
                    tsk->cwnd += 1;             // 慢启动：每个新ACK增加1个MSS
                else
                    tsk->cwnd += 1.0 / tsk->cwnd; // 拥塞避免：每个新ACK增加 1/cwnd 个MSS
                // 新 ACK 到来，重置重复 ACK 计数
                tsk->dupACKcount = 0;
                // 如果之前处于数据包乱序状态则切换回 OPEN 状态
                if (tsk->NewReno_state == DISORDER)
                    tsk->NewReno_state = OPEN;
            } else {
                // 收到重复ACK：仅更新重复 ACK 计数
                tsk->dupACKcount++;
                if (tsk->dupACKcount >= 3) {
                    // 达到三个重复ACK，触发快速重传
                    tsk->ssthresh = max((u32)(tsk->cwnd / 2), 1);
                    tsk->cwnd = tsk->ssthresh + 3;  // 初始化快恢复窗口（加上3个MSS）
                    tsk->recovery_point = tsk->snd_nxt; // 记录下一个需要确认的序号
                    tsk->NewReno_state = RECOVERY;  // 进入快恢复状态
                    tcp_retrans_send_buffer(tsk);   // 触发重传
                }
            }
            break;
        }
        // LOSS 状态下：处于丢包恢复阶段
        case LOSS: {
            if (ack_valid) {
                // 根据当前 cwnd 大小调整：慢启动或者拥塞避免
                if (tsk->cwnd < tsk->ssthresh)
                    tsk->cwnd += 1;
                else
                    tsk->cwnd += 1.0 / tsk->cwnd;

                // 收到新ACK且确认号达到丢包点后，退出 LOSS 状态
                if (cb->ack >= tsk->loss_point) {
                    tsk->NewReno_state = OPEN;
                    tsk->dupACKcount  = 0;
                }
            } else {
                // 重复ACK：增加重复 ACK 计数
                tsk->dupACKcount++;
            }
            break;
        }
        // 快恢复（RECOVERY）状态下：处于快速重传恢复过程中
        case RECOVERY: {
            if (ack_valid) {
                // 如果新ACK确认的序号仍未超过恢复点，则继续在快恢复阶段内
                if (cb->ack < tsk->recovery_point) {
                    tsk->cwnd += 1;             // 收到每个新ACK后增加1个MSS
                    tcp_retrans_send_buffer(tsk); // 重传未被确认的数据包
                } else {
                    // 新ACK确认号超过恢复点，退出快恢复，进入拥塞避免(或正常OPEN)状态
                    tsk->NewReno_state = DISORDER;  // 设置为DISORDER，等待后续新ACK调整 cwnd
                    tsk->dupACKcount  = 0;
                }
            } else {
                // 在快恢复中收到重复ACK：每个重复ACK使 cwnd 增加一个MSS，并累加重复计数
                tsk->cwnd += 1;
                tsk->dupACKcount++;
                // 唤醒发送等待队列，可能触发后续数据发送
                wake_up(tsk->wait_send);
            }
            break;
        }
        default:
            break;
    }

	tcp_update_retrans_timer(tsk);
}
void tcp_state_listen(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet);
void tcp_state_syn_sent(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet);
void tcp_state_syn_recv(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet);
void tcp_state_closed(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet);
void tcp_state_established(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet);
void tcp_state_fin_wait_1(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet);
void tcp_state_fin_wait_2(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet);
void tcp_state_last_ack(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet);
// Process the incoming packet according to TCP state machine. 
void tcp_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	//fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	struct tcphdr *tcp = packet_to_tcp_hdr(packet);
	if (tcp->flags & TCP_RST) {
		tcp_sock_close(tsk);
		return;
	}

	switch (tsk->state) {
		case TCP_LISTEN: tcp_state_listen(tsk, cb, packet);break;
		case TCP_SYN_SENT:tcp_state_syn_sent(tsk, cb, packet);break;
		case TCP_SYN_RECV: tcp_state_syn_recv(tsk, cb, packet);break;
		default: break;
	}

	if (!is_tcp_seq_valid(tsk, cb)) {
		tcp_send_control_packet(tsk, TCP_ACK);
		return;
	}

	switch (tsk->state) {
		case TCP_ESTABLISHED: tcp_state_established(tsk, cb, packet);break;
		case TCP_FIN_WAIT_1: tcp_state_fin_wait_1(tsk, cb, packet);break;
		case TCP_FIN_WAIT_2: tcp_state_fin_wait_2(tsk, cb, packet);break;
		case TCP_LAST_ACK: tcp_state_last_ack(tsk, cb, packet);break;
		default: break;
	}
}

void tcp_state_listen(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
    if (cb->flags & TCP_SYN) {
		struct tcp_sock *child = alloc_tcp_sock();
		child->parent = tsk;
		child->sk_sip = cb->daddr;
		child->sk_sport = cb->dport;
		child->sk_dip = cb->saddr;
		child->sk_dport = cb->sport;
		child->iss = tcp_new_iss();
		child->snd_nxt = child->iss;
		//child->rcv_nxt = cb->seq_end;
		child->rcv_nxt = cb->seq + 1;

		tcp_sock_listen_enqueue(child);
		tcp_set_state(child, TCP_SYN_RECV);
		tcp_hash(child);
        tcp_send_control_packet(child, TCP_SYN | TCP_ACK);
    }
    // else {
    //     log(ERROR, "tcp_state_listen: received non-SYN packet, sending reset.");
    //     tcp_send_reset(cb);
    // }
}
// 当tcp_sock处于TCP_SYN_SENT状态时，说明处于主动连接阶段，等待服务器回复SYN+ACK
// 如果收到SYN+ACK包，则更新序号、回复ACK并将状态设置为ESTABLISHED
void tcp_state_syn_sent(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
    if (cb->flags  == (TCP_SYN | TCP_ACK)) {
        tsk->rcv_nxt = cb->seq_end;  
		//tsk->snd_una = cb->ack;
        tcp_update_window_safe(tsk, cb);
        tcp_unset_retrans_timer(tsk);
        tcp_update_send_buffer(tsk, cb->ack);
		tcp_set_state(tsk, TCP_ESTABLISHED);
		wake_up(tsk->wait_connect);
		tcp_send_control_packet(tsk, TCP_ACK);
		pthread_t cwnd_record;
		pthread_create(&cwnd_record, NULL, tcp_cwnd_thread, (void *)tsk);
    }
    else {
        log(ERROR, "tcp_state_syn_sent: unexpected flags, sending reset.");
        tcp_send_reset(cb);
    }
}

// 当tcp_sock处于TCP_SYN_RECV状态时，说明服务器已发送SYN+ACK，等待客户端ACK确认
// 如果收到ACK包，则进一步检查序号，并将连接加入到accept队列（如果未满）
void tcp_state_syn_recv(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
    if (cb->flags & TCP_ACK) {
        if (!is_tcp_seq_valid(tsk, cb)) {
            log(ERROR, "tcp_state_syn_recv: invalid sequence, drop packet.");
            return;
        }
        tcp_update_window_safe(tsk, cb);
        if (tcp_sock_accept_queue_full(tsk->parent)) {
            return;
        }
        tcp_unset_retrans_timer(tsk);
        tcp_update_send_buffer(tsk, cb->ack);
        
        tcp_set_state(tsk, TCP_ESTABLISHED);
        tcp_sock_accept_enqueue(tsk);
		tsk->rcv_nxt = cb->seq_end;
		//tsk->snd_una = cb->ack;
        wake_up(tsk->parent->wait_accept);

    }
    else {
        log(ERROR, "tcp_state_syn_recv: expected ACK packet.");
    }
}
// TCP_ESTABLISHED 状态处理
void tcp_state_established(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	if (cb->flags & TCP_FIN) {
		if (tsk->rcv_nxt != cb->seq) {
			return;
		}
		tcp_update_send_buffer(tsk, cb->ack);
		tcp_update_retrans_timer(tsk);
		if (tsk->retrans_timer.enable) {
			log(DEBUG, "still have no ack packet before close wait\n");
		}
	
		tcp_set_state(tsk, TCP_CLOSE_WAIT);
		if (cb->pl_len == 0) {
			tsk->rcv_nxt = cb->seq + 1;
			//log(DEBUG, "cb->pl_len == 0\n");
			//tsk->snd_una = cb->ack;
		}
		else {
			//log(DEBUG, "cb->pl_len > 0\n");
			solve_receive_data(tsk, cb);
			tsk->rcv_nxt += 1;
		}
		tcp_send_control_packet(tsk, TCP_ACK);
		wake_up(tsk->wait_recv);
	}
else if (cb->flags & TCP_ACK) {
	if (cb->pl_len == 0) {
		//log(DEBUG, "cb->flags & TCP_ACK: cb->pl_len == 0\n");
		if (tsk->rcv_nxt != cb->seq) {
			//log(DEBUG, "tsk->rcv_nxt != cb->seq\n");
			return;
		}
		tsk->rcv_nxt = cb->seq_end;
		if (cb->ack > tsk->snd_una) {
			//log(DEBUG, "cb->ack > tsk->snd_una\n");
			tsk->retrans_timer.rtt_cnt = 0;
			tsk->retrans_timer.timeout = TCP_RETRANS_INTERVAL_INITIAL;
		}
		//tsk->snd_una = cb->ack;
		tcp_update_window_safe(tsk, cb);
		tcp_congestion_control(tsk, cb, packet);
		tcp_update_send_buffer(tsk, cb->ack);
		tcp_update_retrans_timer(tsk);
	}
	else {
		//log(DEBUG, "cb->flags & TCP_ACK: cb->pl_len > 0\n");
		if (!is_tcp_seq_valid(tsk, cb)) {
			return;
		}
		solve_receive_data(tsk, cb);
	}
}
}
// TCP_FIN_WAIT_2 状态处理
void tcp_state_fin_wait_2(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
    if (!is_tcp_seq_valid(tsk, cb))
        return;
    
    // if (cb->flags & TCP_ACK) {
    //     tcp_update_window_safe(tsk, cb);
    // }
    if (cb->flags & TCP_FIN) {
        tsk->rcv_nxt = cb->seq_end;
        tcp_set_state(tsk, TCP_TIME_WAIT);
		//tsk->rcv_nxt = cb->seq + 1;
		//tsk->snd_una = cb->ack;
        tcp_send_control_packet(tsk, TCP_ACK);
        tcp_set_timewait_timer(tsk);
    }
}

void tcp_state_fin_wait_1(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
    if (!is_tcp_seq_valid(tsk, cb))
        return;
    
    if (cb->flags & TCP_ACK) {

        tcp_update_send_buffer(tsk, cb->ack);
        tcp_unset_retrans_timer(tsk);
        tcp_update_window_safe(tsk, cb);
        tcp_set_state(tsk, TCP_FIN_WAIT_2);
		tsk->rcv_nxt = cb->seq_end;
		//tsk->snd_una = cb->ack;
    }
}
// TCP_LAST_ACK 状态处理
void tcp_state_last_ack(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
    if (!is_tcp_seq_valid(tsk, cb))
        return;
    
    if (cb->flags & TCP_ACK) {
        tcp_update_window_safe(tsk, cb);
        tcp_update_send_buffer(tsk, cb->ack);
        tcp_unset_retrans_timer(tsk);
        tcp_set_state(tsk, TCP_CLOSED);
		tsk->rcv_nxt = cb->seq;
		//tsk->snd_una = cb->ack;
        tcp_unhash(tsk);
    }
}