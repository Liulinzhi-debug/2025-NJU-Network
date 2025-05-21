#include "tcp.h"
#include "tcp_sock.h"
#include "tcp_timer.h"

#include "log.h"
#include "ring_buffer.h"

#include <stdlib.h>
// update the snd_wnd of tcp_sock
//
// if the snd_wnd before updating is zero, notify tcp_sock_send (wait_send)
static inline void tcp_update_window(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u16 old_snd_wnd = tsk->snd_wnd;
	tsk->snd_wnd = cb->rwnd;
	if (old_snd_wnd == 0)
		wake_up(tsk->wait_send);
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
		return 0;
	}
}

int tcp_sock_recv(struct tcp_sock *tsk, struct tcp_cb *cb){
	if(cb->pl_len == 0){
		return 0;
	}
	while(ring_buffer_free(tsk->rcv_buf) < cb->pl_len){
		wake_up(tsk->wait_recv);
		sleep_on(tsk->wait_recv);
	}
	write_ring_buffer(tsk->rcv_buf, cb->payload, cb->pl_len);
	tsk->rcv_wnd = ring_buffer_free(tsk->rcv_buf);
	wake_up(tsk->wait_recv);
	return cb->pl_len;
}


void tcp_state_listen(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet);
void tcp_state_syn_sent(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet);
void tcp_state_syn_recv(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet);
void tcp_state_closed(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet);
void tcp_state_established(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet);
void tcp_state_fin_wait_1(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet);
void tcp_state_fin_wait_2(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet);
void tcp_state_last_ack(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet);
void tcp_state_close_wait(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet);
void tcp_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	//fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	if(tsk==NULL){
		//sock not exist
		tcp_send_reset(cb);
		return ;
	}
    char cb_flags[32];
    tcp_copy_flags_to_str(cb->flags, cb_flags);
    //log(DEBUG, "Received TCP packet: %s", cb_flags);



switch (tsk->state)
	{
    case TCP_CLOSED:
        tcp_state_closed(tsk, cb, packet);
        break;
    case TCP_LISTEN:
        tcp_state_listen(tsk, cb, packet);
        break;
	case TCP_SYN_SENT:
        tcp_state_syn_sent(tsk, cb, packet);
		break;
	case TCP_SYN_RECV:
        tcp_state_syn_recv(tsk, cb, packet);
		break;
	case TCP_ESTABLISHED:
        tcp_state_established(tsk, cb, packet);
		break;
	case TCP_FIN_WAIT_1:
        tcp_state_fin_wait_1(tsk, cb, packet);
		break;
	case TCP_FIN_WAIT_2:
        tcp_state_fin_wait_2(tsk, cb, packet);
		break;
    case TCP_LAST_ACK:
        tcp_state_last_ack(tsk, cb, packet);
        break;
    case TCP_CLOSE_WAIT:
        tcp_state_close_wait(tsk, cb, packet);
        break;
    default:
        log(ERROR, "tcp_process: Unknown state %d", tsk->state);
        break;
    }
}
void tcp_state_listen(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
    if (cb->flags & TCP_SYN) {
        struct tcp_sock *child = alloc_tcp_sock();
        child->sk_sip = cb->daddr;    
        child->sk_dip = cb->saddr;     
        child->sk_sport = tsk->sk_sport;
        child->sk_dport = cb->sport;    
        child->parent = tsk;
        list_add_tail(&child->list, &tsk->listen_queue);
        tcp_set_state(child, TCP_SYN_RECV);
        tcp_hash(child);
        child->iss = tcp_new_iss();
        child->snd_una = child->iss;
        child->snd_nxt = child->iss;
        child->rcv_nxt = cb->seq_end;
        tcp_send_control_packet(child, TCP_SYN | TCP_ACK);
    }
    else {
        log(ERROR, "tcp_state_listen: received non-SYN packet, sending reset.");
        tcp_send_reset(cb);
    }
}

// 当tcp_sock处于TCP_SYN_SENT状态时，说明处于主动连接阶段，等待服务器回复SYN+ACK
// 如果收到SYN+ACK包，则更新序号、回复ACK并将状态设置为ESTABLISHED
void tcp_state_syn_sent(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
    if (cb->flags  == (TCP_SYN | TCP_ACK)) {
        tsk->rcv_nxt = cb->seq_end;  
        tcp_update_window_safe(tsk, cb);
        tcp_set_state(tsk, TCP_ESTABLISHED);
        tcp_send_control_packet(tsk, TCP_ACK);
        wake_up(tsk->wait_connect);
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
            tcp_set_state(tsk, TCP_CLOSED);
            tcp_send_reset(cb);
            list_delete_entry(&tsk->list);
            free_tcp_sock(tsk);
        } else {
            tcp_set_state(tsk, TCP_ESTABLISHED);
            tcp_sock_accept_enqueue(tsk);
            wake_up(tsk->parent->wait_accept);
        }
    }
    else {
        log(ERROR, "tcp_state_syn_recv: expected ACK packet.");
    }
}

void tcp_state_closed(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
    log(DEBUG, "tcp_state_closed: connection closed, sending reset.");
    //tcp_send_reset(cb);
}
// TCP_ESTABLISHED 状态处理
void tcp_state_established(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
    if (!is_tcp_seq_valid(tsk, cb))
        return;

    if (cb->flags & TCP_ACK) {
        int rlen = tcp_sock_recv(tsk, cb);
        if (rlen != 0 || (cb->flags & TCP_FIN)) {
            tsk->rcv_nxt = cb->seq_end;
        }
        tcp_update_window_safe(tsk, cb);
        if (cb->flags & TCP_FIN) {
            tcp_set_state(tsk, TCP_CLOSE_WAIT);
            wake_up(tsk->wait_recv);
        }
        if (rlen != 0 || (cb->flags & TCP_FIN)) {
            tcp_send_control_packet(tsk, TCP_ACK);
        }
    }
}

// TCP_FIN_WAIT_1 状态处理
void tcp_state_fin_wait_1(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
    if (!is_tcp_seq_valid(tsk, cb))
        return;
    
    if (cb->flags & TCP_ACK) {
        int rlen = tcp_sock_recv(tsk, cb);
        if (rlen != 0) {
            tsk->rcv_nxt = cb->seq_end;
        }
        tcp_update_window_safe(tsk, cb);
        tcp_set_state(tsk, TCP_FIN_WAIT_2);
        if (rlen != 0) {
            tcp_send_control_packet(tsk, TCP_ACK);
        }
    }
    if ((cb->flags & TCP_FIN) && (cb->flags & TCP_ACK)) {
        tsk->rcv_nxt = cb->seq_end;
        tcp_send_control_packet(tsk, TCP_ACK);
        tcp_set_state(tsk, TCP_TIME_WAIT);
        tcp_set_timewait_timer(tsk);
    }
}

// TCP_FIN_WAIT_2 状态处理
void tcp_state_fin_wait_2(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
    if (!is_tcp_seq_valid(tsk, cb))
        return;
    
    if (cb->flags & TCP_ACK) {
        int rlen = tcp_sock_recv(tsk, cb);
        if (rlen != 0) {
            tsk->rcv_nxt = cb->seq_end;
        }
        tcp_update_window_safe(tsk, cb);
        if (rlen != 0) {
            tcp_send_control_packet(tsk, TCP_ACK);
        }
    }
    if (cb->flags & TCP_FIN) {
        tsk->rcv_nxt = cb->seq_end;
        tcp_set_state(tsk, TCP_TIME_WAIT);
        tcp_send_control_packet(tsk, TCP_ACK);
        tcp_set_timewait_timer(tsk);
    }
}

// TCP_LAST_ACK 状态处理
void tcp_state_last_ack(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
    if (!is_tcp_seq_valid(tsk, cb))
        return;
    
    if (cb->flags & TCP_ACK) {
        tcp_update_window_safe(tsk, cb);
        tcp_set_state(tsk, TCP_CLOSED);
        tcp_unhash(tsk);
        tcp_bind_unhash(tsk);
    }
}

// TCP_CLOSE_WAIT 状态处理
void tcp_state_close_wait(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
    if (!is_tcp_seq_valid(tsk, cb))
        return;
    
    if (cb->flags & TCP_ACK) {
        tcp_update_window_safe(tsk, cb);
    }
}
