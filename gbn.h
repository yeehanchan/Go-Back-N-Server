#ifndef _gbn_h
#define _gbn_h

#include<sys/types.h>
#include<sys/socket.h>
#include<sys/ioctl.h>
#include<signal.h>
#include<unistd.h>
#include<fcntl.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<time.h>


#define WINDOW_SIZE   2
#define BUFF_SIZE  1028


/*----- Error variables -----*/
extern int h_errno;
extern int errno;

/*----- Protocol parameters -----*/
<<<<<<< HEAD
#define LOSS_PROB 0.1
#define CORR_PROB 0.01
=======
<<<<<<< HEAD
#define LOSS_PROB 0.1
#define CORR_PROB 0.01
=======
#define LOSS_PROB 1e-2    /* loss probability                            */
#define CORR_PROB 1e-3    /* corruption probability                      */
>>>>>>> 8d07222ad3ff86adbf162fb90eab6ae697a3cfab
>>>>>>> 7f06d046379c97f77586de28bf6bc4d15ef6b00b
#define DATALEN   1024    /* length of the payload                       */
#define N         1024    /* Max number of packets a single call to gbn_send can process */
#define TIMEOUT      1    /* timeout to resend packets (1 second)        */
#define CONNECTION_RETRY_LIMIT   5

/*----- Packet types -----*/
#define SYN      0        /* Opens a connection                          */
#define SYNACK   1        /* Acknowledgement of the SYN packet           */
#define DATA     2        /* Data packets                                */
#define DATAACK  3        /* Acknowledgement of the DATA packet          */
#define FIN      4        /* Ends a connection                           */
#define FINACK   5        /* Acknowledgement of the FIN packet           */
#define RST      6        /* Reset packet used to reject new connections */

/*----- Go-Back-n packet format -----*/
typedef struct {
	uint8_t  type;            /* packet type (e.g. SYN, DATA, ACK, FIN)     */
	uint8_t  seqnum;          /* sequence number of the packet              */
    uint16_t checksum;        /* header and payload checksum                */
    uint8_t data[DATALEN];    /* pointer to the payload                     */
    /*(uint16_t last_len;*/
    /*uint8_t islast;*/  
} __attribute__((packed)) gbnhdr;



enum STATE{
	CLOSED=0,
	SYN_SENT,
	SYN_RCVD,
	ESTABLISHED,
	FIN_SENT,
	FIN_RCVD
};

enum MODE{
    SLOW=0,
    FAST
};


typedef struct state_t{
    
    /* TODO: Your state information could be encoded here. */
    struct sockaddr *client;
    struct sockaddr *server;
    socklen_t server_socklen;
    socklen_t client_socklen;
    int client_sockfd;
    int server_sockfd;
    enum STATE state_type;
    int base; 
    int last_acked; 
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 7f06d046379c97f77586de28bf6bc4d15ef6b00b
    int track;
    int num; 
    enum MODE mode; 
    /*char *data[N][DATALEN];*/
    uint8_t data[N][DATALEN];
    int len;
<<<<<<< HEAD
=======
=======
    int track; 
    enum MODE mode; 
    char *data[N][DATALEN];

    uint8_t curr_seqnum; 
    int WINDOWSIZE;
>>>>>>> 8d07222ad3ff86adbf162fb90eab6ae697a3cfab
>>>>>>> 7f06d046379c97f77586de28bf6bc4d15ef6b00b

} state_t;

state_t s;
int conn_retry_counts;

void gbn_init();
void set_gbn_state(enum STATE state);
int check_gbn_state();
int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen);
int gbn_listen(int sockfd, int backlog);
int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen);
int gbn_socket(int domain, int type, int protocol);
int gbn_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int gbn_close(int sockfd);
ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags);
ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags);

ssize_t  maybe_sendto(int  s, const void *buf, size_t len, int flags, \
                      const struct sockaddr *to, socklen_t tolen);

uint16_t checksum(uint16_t *buf, int nwords);


#include <stdio.h>


#endif
