#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <net/ethernet.h>

#include <pthread.h>

#include <openssl/ssl.h>
#include <openssl/aes.h>

#include <sys/epoll.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <fcntl.h>

#include "zlog.h"

#include "khash.h"

#define MAXEPOLLSIZE 10000

typedef struct _transF_hash_key_
{
    uint32_t sip;
    uint32_t dip;
    uint16_t sport;
    uint16_t dport;
}thash_key_t;

//tcp
KHASH_MAP_INIT_INT64(tcp, thash_key_t)

    //udp
KHASH_MAP_INIT_INT64(udp, thash_key_t)

#define PRE_MAGIC_NUM 0x11223344

#define MASGIC_NUM  0xF1F30204
#define MASGIC_NUMR 0x0204F1F3

//timeToGo
//74696d65546f476f
uint8_t snd_pass[32] = { 0x74,0x69,0x6d,0x65,0x54,0x6f,0x47,0x6f,0x00 };
//gotoTIME
//676f746f54494d45
uint8_t rcv_pass[32] = { 0x67,0x6f,0x74,0x6f,0x54,0x49,0x4d,0x45,0x00 };

typedef struct _transF_ghandle_
{
    zlog_category_t* zc;

    AES_KEY send_en_key;
    AES_KEY recv_de_key;

    //tcp hash
    khash_t(tcp) * tcp_phash; 

    //udp hash
    khash_t(udp) * udp_phash; 

    //epoll
    int efd;
    //tcp socket
    int tfd;



}tfghandle_t;


tfghandle_t ghandle;

int setnonblocking(int sockfd)
{
    if(fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFD, 0)|O_NONBLOCK) == -1) 
    {
        return -1;
    }
    return 0;
}

int socket_init(uint16_t listen_port)
{
    int opt = 1;
    //tcp socket init 
    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));

    servaddr.sin_family = AF_INET; 
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(listen_port);

    ghandle.tfd = socket(AF_INET, SOCK_STREAM, 0); 
    if(ghandle.tfd == -1)
    {
        zlog_error(ghandle.zc, "can't create socket file");
        return -1;
    }

    setsockopt(ghandle.tfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if(setnonblocking(ghandle.tfd) < 0) 
    {
        zlog_error(ghandle.zc, "setnonblock error");
    }

    if(bind(ghandle.tfd, (struct sockaddr *) &servaddr, sizeof(struct sockaddr)) == -1) 
    {
        zlog_error(ghandle.zc, "bind error");
        return -1;
    } 

    if(listen(ghandle.tfd, 8) == -1) 
    {
        zlog_error(ghandle.zc, "listen error");
        return -1;
    }

    return 0;
}

int init_tran(uint16_t listen_port)
{
    //zlog
    int rc;
    zlog_category_t *zc;

    rc = zlog_init("../etc/log.conf");
    if (rc) {
        printf("init failed\n");
        return -1;
    }

    zc = zlog_get_category("run_log");
    if (!zc) {
        printf("get cat fail\n");
        zlog_fini();
        return -2;
    }

    ghandle.zc = zc;


    zlog_info(ghandle.zc, "init zlog success!");

    //ssl
    SSL_library_init();

    OpenSSL_add_all_algorithms();

    SSL_load_error_strings();

    AES_set_encrypt_key((const unsigned char*)snd_pass, 256, &ghandle.send_en_key);
    AES_set_decrypt_key((const unsigned char*)rcv_pass, 256, &ghandle.recv_de_key);

    zlog_info(ghandle.zc, "init ssl success!");

    //hash
    ghandle.tcp_phash = kh_init(tcp);

    if(ghandle.tcp_phash == NULL)
    {
        zlog_error(ghandle.zc, "tcp phash create failed!");
        return -1;
    }

    ghandle.udp_phash = kh_init(udp);
    if(ghandle.udp_phash == NULL)
    {
        zlog_error(ghandle.zc, "udp phash create failed!");
        return -1;
    }

    zlog_error(ghandle.zc, "tcp phash and udp phash init success!");

    //set proc fd size 
    struct rlimit rt;
    rt.rlim_max = rt.rlim_cur = MAXEPOLLSIZE;
    if(setrlimit(RLIMIT_NOFILE, &rt) == -1) 
    {
        zlog_error(ghandle.zc, "setrlimit error");
        return -1;
    }

    socket_init(listen_port);

    return 0;
}

int add_tcpfd_epoll(int efd, int fd, int events)
{
    struct epoll_event ev;

    ev.events = events;
    ev.data.fd = fd;
    
    if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev) < 0) 
    {
        fprintf(stderr, "epoll set insertion error: fd=%d\n", fd);
        return -1;
    }

    return 0;
}

void* tcp_thread(__attribute__((unused))void* arg)
{
    int i = 0;
    int num = 0;
    int need_wait = 0;

    int transF_fd = 0;
    int client_fd = 0;
    struct sockaddr_in client_addr;
    socklen_t  client_addrlen = sizeof(struct sockaddr_in);

    struct epoll_event events[MAXEPOLLSIZE];

    memset(events, 0, sizeof(events));

    //epoll fd init
    ghandle.efd = epoll_create(MAXEPOLLSIZE);

    add_tcpfd_epoll(ghandle.efd, ghandle.tfd, EPOLLIN);

    need_wait = 1;

    while(1)
    {
        num = epoll_wait(ghandle.efd, events, need_wait, -1);

        for(i=0; i < num; i++)
        {
            transF_fd = events[i].data.fd;
            if((events[i].events & EPOLLIN) && transF_fd == ghandle.tfd) 
            {
                client_fd = accept(ghandle.tfd, (struct sockaddr*)&client_addr, &client_addrlen);
                if (client_fd == -1)
                    zlog_error(ghandle.zc, "accpet error:");
                else
                {
                    zlog_info(ghandle.zc, "accept a new client: [%s:%d]",inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
                    add_tcpfd_epoll(ghandle.efd, client_fd, EPOLLIN);
                    need_wait ++;
                }
            }
            else if (events[i].events & EPOLLIN)
            {
            }
            else if (events[i].events & EPOLLOUT)
            {
            }
        }
    }

    return NULL;
}

void* udp_thread(__attribute__((unused))void* arg)
{

    return NULL;
}

//tcp thread
void create_tcp_thread()
{
    pthread_t pid;
    pthread_create(&pid, NULL, tcp_thread, NULL);
    pthread_detach(pid);

    zlog_info(ghandle.zc, "tcp thread created!");
}

//udp thread
void create_udp_thread()
{

    pthread_t pid;
    pthread_create(&pid, NULL, udp_thread, NULL);
    pthread_detach(pid);

    zlog_info(ghandle.zc, "udp thread created!");
}

int main(int argc, char** argv)
{
    if(argc != 2)
    {
        printf("eg.\n\t./a.out listen_port\n");
        return -1;
    }
   
    int listen_port = atoi(argv[1]); 
    if(listen_port < 0 || listen_port > 65535)
    {
        printf("listen_port error!\n");
        return -1;
    }

    //初始化
    init_tran(listen_port);

    //tcp thread
    create_tcp_thread();

    //udp thread
    create_udp_thread();


    while(1)
    {
        sleep(1);
    }

    return 0;
}
