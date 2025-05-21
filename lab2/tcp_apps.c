#include "tcp_sock.h"
#include "log.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// tcp server application
// 监听指定端口，接收到数据后，在返回数据时加上前缀 "server echoes: "（冒号后有空格）
void *tcp_server(void *arg)
{
    u16 port = *(u16 *)arg;
    struct tcp_sock *tsk = alloc_tcp_sock();

    struct sock_addr addr;
    addr.ip = htonl(0);
    addr.port = port;
    if (tcp_sock_bind(tsk, &addr) < 0) {
        log(ERROR, "tcp_sock bind to port %hu failed", ntohs(port));
        exit(1);
    }

    if (tcp_sock_listen(tsk, 3) < 0) {
        log(ERROR, "tcp_sock listen failed");
        exit(1);
    }

    log(DEBUG, "Listening on port %hu.", ntohs(port));

    struct tcp_sock *csk = tcp_sock_accept(tsk);
    log(DEBUG, "Accepted a connection.");

    char recv_buf[1500];
    char send_buf[1600];
    int n;

    // 循环从接收缓存中读取数据，直至对端关闭连接或发生错误
    while (1) {
        n = tcp_sock_read(csk, recv_buf, sizeof(recv_buf) - 1);
        if (n > 0) {
            recv_buf[n] = '\0';
            // 构造返回字符串，注意前缀后冒号后有空格
            snprintf(send_buf, sizeof(send_buf), "server echoes: %s", recv_buf);
            tcp_sock_write(csk, send_buf, strlen(send_buf));
        } else {
            // 0 表示对端关闭连接；-1 表示出现错误
            break;
        }
    }

    tcp_sock_close(csk);
    tcp_sock_close(tsk);
    return NULL;
}

// tcp client application
// 客户端连接到服务器后，使用固定字符串进行旋转发送（不少于 5 次），每次发送后接收并打印服务器返回的字符串
void *tcp_client(void *arg)
{
    struct sock_addr *skaddr = arg;
    struct tcp_sock *tsk = alloc_tcp_sock();

    if (tcp_sock_connect(tsk, skaddr) < 0) {
        log(ERROR, "tcp_sock connect to server (" IP_FMT ":%hu) failed.",
            NET_IP_FMT_STR(skaddr->ip), ntohs(skaddr->port));
        exit(1);
    }

    sleep(1);

    // 待发送的固定字符串，包含数字、小写字母和大写字母
    const char *data = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    int data_len = strlen(data);
    char send_buf[128];
    char recv_buf[1600];

    // 至少发送 5 次循环旋转后的字符串
    for (int i = 0; i < 8; i++) {
        int pos = 0;
        // 将 data[i] 到 data[data_len-1] 的部分先复制到 send_buf 中
        for (int j = i; j < data_len; j++) {
            send_buf[pos++] = data[j];
        }
        // 再将 data[0] 到 data[i-1] 的部分复制到 send_buf 中
        for (int j = 0; j < i; j++) {
            send_buf[pos++] = data[j];
        }
        send_buf[pos] = '\0';

        tcp_sock_write(tsk, send_buf, strlen(send_buf));

        int n = tcp_sock_read(tsk, recv_buf, sizeof(recv_buf) - 1);
        if (n > 0) {
            recv_buf[n] = '\0';
            printf("%s\n", recv_buf);
        }
        sleep(1);
    }

    tcp_sock_close(tsk);
    return NULL;
}
