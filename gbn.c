#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <stdbool.h>
#include "gbn.h"

#define TIMEOUT 1 //timeout seconds
int timeout;
void handle_sigalrm(int signo, siginfo_t *siginfo, void *context)
{
    //alert when timed out
    alarm(TIMEOUT);
    timeout = 1;
}

size_t min(size_t a, size_t b) {
    return a < b ? a : b;
}

void gbn_init(){

    s = *(state_t*)malloc(sizeof(s));
    s.state_type = CLOSED;
    s.socklen = sizeof(struct sockaddr);
//    s.base = 0;
//    s.nextseq = 0;
//    s.last_acked = -1;
//    s.seq = -1;
    s.windowSize = 1;
    s.curr_seqNum = (uint8_t)rand();
    s.mode = SLOW; // protocol will start in slow mode
}

//check interity
int checkPkt(int type, char *buf, gbnhdr * pkt){

    uint16_t cs;
    if(type == 0){
        //TODO: change value
        cs = checksum((uint16_t *)buf, 2);
    }
    else{
        cs = checksum((uint16_t *)buf, 1);
    }
    if(cs == pkt->checksum){
        return 0;
    }
    return 1;
}


// make packet based on type
int make_pkt(uint8_t type, gbnhdr * pkt){

    char *buf;
    switch(type) {
        case SYN :
            pkt->type = SYN;
            sprintf(buf,"%d\t",pkt->type);
            pkt->checksum = checksum((uint16_t*)buf,1);
            fprintf(stderr,"client side checksum %d\n",pkt->checksum);
            return EXIT_SUCCESS;

        case SYNACK :
            pkt->type = SYNACK;
            sprintf(buf,"%d\t",pkt->type);
            pkt->checksum = checksum((uint16_t*)buf,1);
            return EXIT_SUCCESS;


        case FIN :

            pkt->type = FIN;
            sprintf(buf,"%d\t",pkt->type);
            pkt->checksum = checksum((uint16_t*)buf,1);
            return EXIT_SUCCESS;

        case FINACK :

            pkt->type = FINACK;
            sprintf(buf,"%d\t",pkt->type);
            pkt->checksum = checksum((uint16_t*)buf,1);
            return EXIT_SUCCESS;
        case RST :

            pkt->type = RST;
            sprintf(buf,"%d\t",pkt->type);
            pkt->checksum = checksum((uint16_t*)buf,1);
            return EXIT_SUCCESS;
    }


    return(-1);
}

// parse packet
int parse_pkt(uint8_t type, char *buff, gbnhdr* pkt){

    char *token;
    int i, j;


    // only DATA pkt required four fields. Other pkt types only have type| checksum fields
    if(type == 0){
        for(i = 0; i < 4; i++){

            token = strsep(&buff, "\t");
            switch (i){
                case 0:
                    pkt->type = atoi(token);
                    break;
                case 1:
                    pkt->seqnum = atoi(token);
                    break;
                case 2:
                    pkt->checksum = atoi(token);
                    break;
                case 3:
                    break;
            }
        }
    }else{

        for(i = 0; i < 2; i++){

            token = strsep(&buff, "\t");
            switch (i){
                case 0:

                    pkt->type = atoi(token);
                    break;
                case 1:
                    pkt->checksum = atoi(token);
                    break;
            }
        }
    }

    return EXIT_SUCCESS;
}


// should align make_packet method with yeehan
gbnhdr make_packet(int packet_type, uint8_t packet_sequence, char * data, int data_length){
    gbnhdr packet;
    packet.type = packet_type;
    packet.seqnum = packet_sequence;
    packet.checksum = 0 ; // need to double checksum initalization value
    if (data_length > 0){ // meaning this is a packet with data
        if (data_length < BUFF_SIZE){
            memcpy(packet.data, data, data_length);
        }
        else{ // need to split data because data is too large . Just cut it now. TODO: split the bigdata peroperly
            memcpy(packet.data, data, BUFF_SIZE);
        }
    }
    else{ // this is a packet with symbol indication
        strcpy(packet.data, "");
    }
    return packet;
}



uint16_t checksum(uint16_t *buf, int nwords)
{
	uint32_t sum;

	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}



// need to be modified later
ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags){
	

	/* Hint: Check the data length field 'len'.
	 *       If it is > DATALEN, you will have to split the data
	 *       up into multiple packets - you don't have to worry
	 *       about getting more than N * DATALEN.
	 */

    if(s.state_type != ESTABLISHED){
        return(-1);
    }

//    char *token;
//    struct sockaddr *server = s.server;
//    socklen_t socklen = s.socklen;
//    struct gbnhdr* pkts[];
//
//
//    while(token = strsep(&buf,"\n") != NULL){
//        if(strlen(token) > DATALEN){
//            /*TODO: split */
//        }
//        else{
//            /*TODO: make pkt*/
//        }
//    }
//
//    /*TODO: sliding window*/
//
//	return EXIT_SUCCESS; // return 0

    //set state machine
    s.windowSize = 2;
    s.curr_seqNum = rand();
    s.mode = SLOW;


    size_t curr_size = 0;
    size_t occupied_size = 0;

    gbnhdr * data_packet = malloc(sizeof(*data_packet));

    while (1){
        if (occupied_size >= len){
            break;
        }
        else{
            if (occupied_size == 0){ // first data packet
                if (len >= BUFF_SIZE){
                    // TODO : split data packet Here just cut it down
                    curr_size = BUFF_SIZE;
                }
                curr_size = min(BUFF_SIZE, len);

                int attempts = 0;

                char tmp_buf[BUFF_SIZE];
                memset(tmp_buf, '\0', sizeof(tmp_buf)); // reset tmp_buf incase pre occupied
                memcpy(tmp_buf, buf + occupied_size, curr_size);
                strcpy(data_packet, tmp_buf);
                s.state_type = SYN_RCVD;

                while (s.state_type!= ACK_RCVD && attempts < 5){
                    // send the packet
                    gbnhdr this_packet = make_packet(DATA, s.curr_seqNum, data_packet, curr_size);
                    alarm(TIMEOUT);
                    s.state_type = DATA_SENDING;
                    if (sendto(sockfd, &this_packet, sizeof(this_packet), 0, s.client, s.socklen) == -1 || errno == EINTR){
                        attempts ++;
                        printf("Send data packet sending failed. Attemps++");
                    }
                    else{ // sended
                        // prepare dataAckPacket
                        gbnhdr * data_ack_packet = malloc(sizeof(*data_ack_packet));
                        if (recvfrom(sockfd, data_ack_packet, sizeof(*data_ack_packet), 0, s.server, s.socklen) == -1 || data_ack_packet->type!=DATAACK){
                            attempts ++;
                            printf("Send data packet out. But no proper data ACK back Attemps++");
                        }
                        else if (data_ack_packet->seqnum != s.curr_seqNum){
                            attempts++;
                            printf("need to resend due to error order packet ACK");
                        }
                        else{
                            s.state_type = ACK_RCVD;
                            s.mode = FAST ; // first packet received, switch to fast mode
                        }
                    }
                }

                // send and ack successfully, update rest buffer parameters
                occupied_size += curr_size;
                len -= curr_size;
                s.state_type = ESTABLISHED;

                if (attempts >= 5){ // not send correctly for 5 times, close connection
                    s.state_type = CLOSED;
                    return -1; //
                }

            }
            else{ // start to send the second packet
                if (s.mode = FAST) { // 万箭齐发

                }

            }
        }
    }


}


// need to be modified later
ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){

    return EXIT_SUCCESS;
}



// pangjac version done
int gbn_close(int sockfd){

//    // origin version, directly exit
//    close(sockfd);
//	return EXIT_SUCCESS;
    if (sockfd < 0){
        perror("Not a valid sockfd. Return now.");
        return -1;
    }


    while (s.state_type != CLOSED){
        if (s.state_type == ESTABLISHED){ // start to send fin
            gbnhdr fin_packet = make_packet(FIN, s.curr_seqNum, NULL,0);
            if (sendto(sockfd, &fin_packet, sizeof(fin_packet), 0, s.client, s.socklen -1)){
                return -1;
            }
            s.state_type = FIN_SENT;
        }

        if (s.state_type == FIN_SENT){

        }


    }



    if (s.state_type == CLOSED){
        return close(sockfd);
    }

    return EXIT_SUCCESS;
}



// need to be modified later
int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen){


    gbn_init(); // pangjac: ?? added at gbn_socket()
    s.server = (struct sockaddr *) server;
    s.socklen = socklen;

    // if sockfd iteslet not valid
    if (sockfd < 0){
        return -1;
    }

    int attempts = 5;

    ssize_t senlen, revlen;
    char syn_buf[BUFF_SIZE], rev_buf[BUFF_SIZE];
    gbnhdr syn_packet, syn_ack_pkt;

    syn_packet = make_packet(SYN, 0, NULL, 0);
    //start to set state
    s.state_type = SYN_SENT;
    s.windowSize = 1;
    // do not set sending mode until calling gbn_send()

    while(s.state_type == SYN_SENT && attempts < 5){
        //sending syn
        if(sendto(sockfd, &syn_packet, sizeof(syn_packet),0,server,socklen) == -1){
            perror("Couldn't send syn packet");
            s.state_type =CLOSED;
            return -1;
        }
        // syn send
        alarm(TIMEOUT); // start timer
        attempts ++;

        // start to check whehther SYNACK back
        if (errno == EINTR){
            printf("SYNACK NEVER BACK, TIMEOUT\n");
            attempts++;
        }
        else{ // wait a SYNACK back
            // buff from the ACK
            if (recvfrom(sockfd, &syn_ack_pkt, sizeof (syn_ack_pkt), 0, server, socklen) != -1 && syn_ack_pkt.type == SYNACK){
                s.state_type = ESTABLISHED;
                printf("GOT SYNACK from server, state ESTABLISHED");
                return 0;
            }
            else{
                printf("SYNACK NOT RECEIVED PROPERLY, TRY AGAIN\n");
                attempts++;
            }

        }
    }

    if (attempts >=5) {
        printf("attempts exceeds 5 times upper limit. Close");
        s.state_type = CLOSED;
        return -1;
    }

}

// pangjac version done
int gbn_listen(int sockfd, int backlog){
    printf( "Always gbn_listen returned true as we don't need a listening connection queue \n");
    return EXIT_SUCCESS;
}




// pangjac version done
int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen){

    if (sockfd < 0){
        // has been closed the connection. directly break up
        return -1;
    }

    if (bind(sockfd, server, socklen) == -1)
    {
        close(sockfd);
        fprintf(stderr, "Failed binding socket.\n");
        return (-1);
    }


    return EXIT_SUCCESS;
}	


// pangjac version done
int gbn_socket(int domain, int type, int protocol){
		
	/*----- Randomizing the seed. This is used by the rand() function -----*/
	srand((unsigned)time(0));

    int sock_fd;

    gbn_init();

    //sets timeout handler
    struct sigaction act;
    memset (&act, '\0', sizeof(act));
    act.sa_sigaction = &handle_sigalrm;
    act.sa_flags = 0;
    sigaction(SIGALRM, &act, NULL);

    /* all networked programs must create a socket */
    if ((sock_fd = socket(domain, type, protocol)) == -1)
    {
        fprintf(stderr, "Failed creating socket.\n");
        return (-1);
    }
    return sock_fd;

}




//pangjac version done
int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen){

    if (sockfd < 0){
        perror( " parameter sockfd invalid ");
        return -1;
    }

    ssize_t revlen, senlen;

    gbnhdr syn_pkt;
    gbnhdr rep_pkt;

    printf("listener: waiting for revfrom\n");


    if((revlen = recvfrom(sockfd, &rep_pkt, sizeof(rep_pkt), 0, client, socklen) == -1) || rep_pkt.type != SYN){
        perror( "Failed to waiting for SYN");
        return(-1);
    }

    s.state_type = SYN_RCVD;
    s.client = client;
    rep_pkt.type = SYNACK;

    if (senlen = sendto(sockfd, &rep_pkt, sizeof(rep_pkt), 0, client, socklen) == -1){
        perror( " Failed to send SYNACK");
        return -1;
    }

//    // yeehan originial version
//    parse_pkt(1, rev_buf, &syn_pkt);
//
//    if(syn_pkt.type == SYN && checkPkt(1,&syn_pkt) == 0){
//        make_pkt(SYNACK, &rep_pkt);
//        sprintf(sen_buf,"%d\t%d\n",rep_pkt.type,rep_pkt.checksum);
//
//        if((senlen = sendto(sockfd, sen_buf, BUFF_SIZE, 0, client, *socklen)) == -1){
//            close(sockfd);
//            return(-1);
//        }
//
//    }else{
//        make_pkt(RST, &rep_pkt);
//        sprintf(sen_buf,"%d\t%d\n",rep_pkt.type,rep_pkt.checksum);
//
//        if((senlen = sendto(sockfd, sen_buf, BUFF_SIZE, 0, client, *socklen)) == -1){
//            close(sockfd);
//            return(-1);
//        }
//        return(-1);
//    }

    return sockfd;

}


// not modified
ssize_t maybe_sendto(int  s, const void *buf, size_t len, int flags, \
                     const struct sockaddr *to, socklen_t tolen){

	char *buffer = malloc(len);
	memcpy(buffer, buf, len);
	
	
	/*----- Packet not lost -----*/
	if (rand() > LOSS_PROB*RAND_MAX){
		/*----- Packet corrupted -----*/
		if (rand() < CORR_PROB*RAND_MAX){
			
			/*----- Selecting a random byte inside the packet -----*/
			int index = (int)((len-1)*rand()/(RAND_MAX + 1.0));

			/*----- Inverting a bit -----*/
			char c = buffer[index];
			if (c & 0x01)
				c &= 0xFE;
			else
				c |= 0x01;
			buffer[index] = c;
		}

		/*----- Sending the packet -----*/
		int retval = sendto(s, buffer, len, flags, to, tolen);
		free(buffer);
		return retval;
	}
	/*----- Packet lost -----*/
	else
		return(len);  /* Simulate a success */
}
