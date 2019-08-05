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

#include "zlog.h"

#include "khash.h"

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

}tfghandle_t;


tfghandle_t ghandle;

int init_tran()
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
    
    return 0;
}


void* tcp_thread(__attribute__((unused))void* arg)
{
     
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

int main()
{
    //初始化
    init_tran();

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
