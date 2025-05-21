#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


void solverange(const char *r, off_t fs, off_t *s, off_t *e) {
    char *p;
    if (*r == '-') {
        *s = 0;
        long v = strtol(r+1, &p, 10);
        *e = (p > r+1) ? v : fs-1;
    } else {
        *s = strtol(r, &p, 10);
        *e = (*p++ == '-') ? (*p ? strtol(p, 0, 10) : fs-1) : fs-1;
    }
    
    if (*e >= fs) *e = fs - 1;
}

int srv(int cli, const char *path, const char *range) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        const char *nf = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        send(cli, nf, strlen(nf), 0);
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        const char *nf = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        send(cli, nf, strlen(nf), 0);
        return -1;
    }
    off_t flsz = st.st_size, start = 0, end = flsz - 1;
    int status = 200;
    if (range) {
        solverange(range, flsz, &start, &end);
        status = 206;
    }
    off_t clen = end - start + 1;
    char hdr[512];
    if (status == 206)
        snprintf(hdr, sizeof(hdr),
               "HTTP/1.1 206 Partial Content\r\n"
               "Content-Length: %ld\r\n"
               "Content-Range: bytes %ld-%ld/%ld\r\n\r\n",
              clen, start, end, flsz);
    else
        snprintf(hdr, sizeof(hdr),
                 "HTTP/1.1 200 OK\r\nContent-Length: %ld\r\n\r\n", flsz);
    send(cli, hdr, strlen(hdr), 0);
    long pgsz = sysconf(_SC_PAGE_SIZE);
    off_t align_off = (start / pgsz) * pgsz;
    off_t diff = start - align_off;
    size_t len = diff + clen;
    void *map = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, align_off);
    send(cli, (char*)map + diff, clen, 0);
    munmap(map, len);
    close(fd);
    return 0;
}

int solveps(SSL *ssl, const char *path, const char *range) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        const char *nf = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        SSL_write(ssl, nf, strlen(nf));
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        const char *nf = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        SSL_write(ssl, nf, strlen(nf));
        return -1;
    }
    off_t flsz = st.st_size, start = 0, end = flsz - 1;
    int status = 200;
    if (range) {
        solverange(range, flsz, &start, &end);
        status = 206;
    }
    off_t clen = end - start + 1;
    char hdr[512];
    if (status == 206)
        snprintf(hdr, sizeof(hdr),
                 "HTTP/1.1 206 Partial Content\r\nContent-Length: %ld\r\nContent-Range: bytes %ld-%ld/%ld\r\n\r\n",
                 clen, start, end, flsz);
    else
        snprintf(hdr, sizeof(hdr),
                 "HTTP/1.1 200 OK\r\nContent-Length: %ld\r\n\r\n", flsz);
    SSL_write(ssl, hdr, strlen(hdr));
    long pgsz = sysconf(_SC_PAGE_SIZE);
    off_t align_off = (start / pgsz) * pgsz;
    off_t diff = start - align_off;
    size_t len = diff + clen;
    void *map = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, align_off);
    SSL_write(ssl, (char*)map + diff, clen);
    munmap(map, len);
    close(fd);
    return 0;
}

SSL_CTX *ssl_ctx = NULL;

void initial() { 
    SSL_library_init(); 
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
	const SSL_METHOD *method = TLS_server_method();
	SSL_CTX *ctx = SSL_CTX_new(method);
    if (SSL_CTX_use_certificate_file(ctx, "./keys/cnlab.cert", SSL_FILETYPE_PEM) <= 0) {
		perror("load cert failed");
		exit(1);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, "./keys/cnlab.prikey", SSL_FILETYPE_PEM) <= 0) {
		perror("load prikey failed");
		exit(1);
	}
    ssl_ctx = ctx; 
}
void solvep(int cli, struct sockaddr_in *client_addr) {
    char req[4096] = {0};
    int br = read(cli, req, sizeof(req) - 1);
    if (br <= 0) { close(cli); return; }
    req[br] = '\0';
    char method[16], url[256];
    sscanf(req, "%15s %255s", method, url);
    char *rp = strstr(req, "Range: bytes=");
    char *rv = NULL;
    if (rp) {
        rv = rp + strlen("Range: bytes=");
        char *crlf = strstr(rv, "\r\n");
        if (crlf) *crlf = '\0';
    }
    char path[512];
    snprintf(path, sizeof(path), "%s%s", ".", url);
    struct stat st;
    if (stat(path, &st) != 0) {
        const char *nf = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        send(cli, nf, strlen(nf), 0);
        close(cli);
        return;
    }
    if (S_ISDIR(st.st_mode)) {
        char ip[1024];
        snprintf(ip, sizeof(ip), "%s/index.html", path);
        if (stat(ip, &st) == 0)
            strcpy(path, ip);
        else {
            const char *nf = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
            send(cli, nf, strlen(nf), 0);
            close(cli);
            return;
        }
    }
    if (!rv && strcmp(url, "/index.html") == 0) {
        char redir[512];
        snprintf(redir, sizeof(redir),
                 "HTTP/1.1 301 Moved Permanently\r\nLocation: https://10.0.0.1%s\r\nContent-Length: 0\r\n\r\n",
                 url);
        send(cli, redir, strlen(redir), 0);
        close(cli);
        return;
    }
    srv(cli, path, rv);
    close(cli);
}

void solveget(SSL *ssl, struct sockaddr_in *client_addr) {
    char req[4096] = {0};
    int br = SSL_read(ssl, req, sizeof(req) - 1);
    if (br <= 0) return;
    req[br] = '\0';
    char method[16], url[256];
    sscanf(req, "%15s %255s", method, url);
    char *rp = strstr(req, "Range: bytes=");
    char *rv = NULL;
    if (rp) {
        rv = rp + strlen("Range: bytes=");
        char *crlf = strstr(rv, "\r\n");
        if (crlf) *crlf = '\0';
    }
    char path[512];
    snprintf(path, sizeof(path), "%s%s", ".", url);
    struct stat st;
    if (stat(path, &st) != 0) {
        const char *nf = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        SSL_write(ssl, nf, strlen(nf));
        return;
    }
    if (S_ISDIR(st.st_mode)) {
        char ip[1024];
        snprintf(ip, sizeof(ip), "%s/index.html", path);
        if (stat(ip, &st) == 0)
            strcpy(path, ip);
        else {
            const char *nf = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
            SSL_write(ssl, nf, strlen(nf));
            return;
        }
    }
    solveps(ssl, path, rv);
}
int socket_cm(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("Opening socket failed");
		exit(1);
	}
    int enable = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
		perror("setsockopt(SO_REUSEADDR) failed");
		exit(1);
	}
	struct sockaddr_in addr;
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);

	if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		perror("Bind failed");
		exit(1);
	}
	listen(sock, 10);
    return sock;
}
void *runp(void *arg) {
    int sock = socket_cm(80);

    while (1) {
        struct sockaddr_in caddr;
		socklen_t len;
		int csock = accept(sock, (struct sockaddr*)&caddr, &len);
		if (csock < 0) {
			perror("Accept failed");
			exit(1);
		}
        solvep(csock, &caddr);
    }
    return NULL;
}

void *runps(void *arg) {
    int sock = socket_cm(443);
    while (1) {
        struct sockaddr_in caddr;
        socklen_t len ;
        int csock = accept(sock, (struct sockaddr*)&caddr, &len);
		if (csock < 0) {
			perror("Accept failed");
			exit(1);
		}
    
        SSL *ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, csock);
        if (SSL_accept(ssl) > 0)
            solveget(ssl, &caddr);

        SSL_free(ssl);
        close(csock);
        
    }
    return NULL;
}

int main() {
    pthread_t Http, Https;
    initial();
    pthread_create(&Http, NULL, runp, NULL);
    pthread_create(&Https, NULL, runps, NULL);
    pthread_join(Http, NULL);
    pthread_join(Https, NULL);
    SSL_CTX_free(ssl_ctx);
    return 0;
}
