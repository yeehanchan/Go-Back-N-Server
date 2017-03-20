#include "gbn.h"

uint16_t checksum(uint16_t *buf, int nwords) {
    uint32_t sum;

    for (sum = 0; nwords > 0; nwords--) {
        sum += *buf++;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return ~sum;
}




void gbn_init(){
    s.state_type = CLOSED;
    s.socklen = sizeof(struct sockaddr);
    s.base = 0;
    s.nextseq = 0;
    s.last_acked = -1;
    s.seq = -1;
    s.mode = 0;

}





//check interity
int checkPkt(gbnhdr * pkt){

    uint16_t cs;
    if(pkt->type == DATA){
        //TODO: change value
         cs = checksum((uint16_t *)pkt, 3);
    }
    else{
        cs = checksum((uint16_t *)pkt, 1);
    }
    if(cs == pkt->checksum){
        return 0;
    }
    return 1;
}


// make packet based on type
int make_pkt(uint8_t type, gbnhdr * pkt){

    switch(type) {
        case SYN :
            pkt->type = SYN;
            pkt->checksum = checksum((uint16_t*)pkt,1);
            return EXIT_SUCCESS;

        case SYNACK :
            pkt->type = SYNACK;
            pkt->checksum = checksum((uint16_t*)pkt,1);
            return EXIT_SUCCESS;


        case FIN :

            pkt->type = FIN;
            pkt->checksum = checksum((uint16_t*)pkt,1);
            return EXIT_SUCCESS;

        case FINACK :

            pkt->type = FINACK;
            pkt->checksum = checksum((uint16_t*)pkt,1);
            return EXIT_SUCCESS;
        case RST :

            pkt->type = RST;
            pkt->checksum = checksum((uint16_t*)pkt,1);
            return EXIT_SUCCESS;
    }


    return(-1);
}


void handle_timeout()
{
    //alert when timed out
    if(conn_retry_counts < CONNECTION_RETRY_LIMIT){

        gbnhdr syn_packet;
        make_pkt(SYN, &syn_packet);
        // send a syn pkt to server
        if((maybe_sendto(s.client_sockfd, &syn_packet, BUFF_SIZE, 0, s.server, s.socklen) == -1)){
            close(s.client_sockfd);
            exit(-1);
        }
        conn_retry_counts ++;
        fprintf(stderr,"retry %d: client sent struct %d %d\n",conn_retry_counts,syn_packet.type,syn_packet.checksum);
        alarm(TIMEOUT);
    }else{
        close(s.client_sockfd);
        fprintf(stderr,"reached connection try limit, close client socket \n");
        exit(0);
    }
}







// need to be modified later
ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags){
	

	/* Hint: Check the data length field 'len'.
	 *       If it is > DATALEN, you will have to split the data
	 *       up into multiple packets - you don't have to worry
	 *       about getting more than N * DATALEN.
	 */

//    if(s.state_type != ESTABLISHED){
//        return(-1);
//    }

    char *token;
    struct sockaddr *server = s.server;
    socklen_t socklen = s.socklen;
    struct gbnhdr *pkts = malloc(N* sizeof(struct gbnnhdr*));
    int i;


//    if(s.seq < N){
//        while((token = strsep(&buf,"\n")) != NULL){
//
//            char *p = token;
//            int len = strlen(token);
//            // split oversized packet
//            if(len > DATALEN){
//
//                while(len > 0){
//                    strncpy(pkts[s.seq].data,p,DATALEN);
//                    p = p + DATALEN;
//                    len -= DATALEN;
//                    s.seq++;
//
//                }
//
//            }
//            else{
//                strcpy(pkts[s.seq]->data,token);
//                s.seq++;
//            }
//        }
//
//    }else{
//        fprintf(stderr,"buffer too long\n");
//    }



    /*TODO: sliding window*/

	return EXIT_SUCCESS;
}




// need to be modified later
ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){

    return EXIT_SUCCESS;
}



// need to be modified later
int gbn_close(int sockfd){

    close(sockfd);
	return EXIT_SUCCESS;
}



// need to be modified later
int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen){


    gbn_init();

    ssize_t senlen, revlen;
    gbnhdr syn_packet, syn_ack_pkt;
    s.server = server;
    s.client_sockfd = sockfd;

    // make a syn pkt
    make_pkt(SYN, &syn_packet);
    if((senlen = maybe_sendto(sockfd, &syn_packet, BUFF_SIZE, 0, server, socklen) == -1)){
        close(sockfd);
        return(-1);
    }

    fprintf(stderr,"client sent struct  %d %d\n",syn_packet.type,syn_packet.checksum);
    s.state_type = SYN_SENT;

    signal(SIGALRM,&handle_timeout);
    alarm(TIMEOUT);

    if(conn_retry_counts == 4){
        fprintf(stderr,"done \n");
        return EXIT_SUCCESS;
    }


    while(conn_retry_counts < CONNECTION_RETRY_LIMIT){


        if((revlen = recvfrom(sockfd, &syn_ack_pkt, BUFF_SIZE, 0, server, &socklen) == -1)){
            close(sockfd);
            return(-1);
        }



        fprintf(stderr,"client received  %d %d\n",syn_ack_pkt.type,syn_ack_pkt.checksum);
        if(syn_ack_pkt.type == SYNACK && checkPkt(&syn_ack_pkt) == 0){
            s.state_type = ESTABLISHED;
            fprintf(stdout,"connection established\n");
        }

        if(syn_ack_pkt.type == RST){
            printf("connection rejected\n");
        }

        return EXIT_SUCCESS;

    }




}

// need to be modified later
int gbn_listen(int sockfd, int backlog){



    return EXIT_SUCCESS;
}





int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen){


    if (bind(sockfd, server, socklen) == -1)
    {
        close(sockfd);
        fprintf(stderr, "Failed binding socket.\n");
        return (-1);
    }


    return EXIT_SUCCESS;
}	




int gbn_socket(int domain, int type, int protocol){
		
	/*----- Randomizing the seed. This is used by the rand() function -----*/
	srand((unsigned)time(0));
	

    int sock_fd;


    /* all networked programs must create a socket */
    if ((sock_fd = socket(domain, type, protocol)) == -1)
    {
        fprintf(stderr, "Failed creating socket.\n");
        return (-1);
    }
    return sock_fd;

}




//need to be modified later
int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen){

    ssize_t revlen, senlen;
    gbnhdr syn_pkt, rep_pkt;

    printf("listener: waiting for revfrom\n");


    if((revlen = recvfrom(sockfd, &syn_pkt, BUFF_SIZE, 0, client, socklen) == -1)){
        close(sockfd);
        return(-1);
    }
    fprintf(stderr,"server received struct %d %d \n",syn_pkt.type,syn_pkt.checksum);
    fprintf(stderr,"server computes checksum %d \n",checksum((uint16_t *)&syn_pkt,1));
    s.state_type = SYN_RCVD;
    s.client = client;




    if(syn_pkt.type == SYN && checkPkt((uint16_t *)&syn_pkt) == 0){

        make_pkt(SYNACK, &rep_pkt);
        fprintf(stderr,"server sent struct %d %d \n",rep_pkt.type,rep_pkt.checksum);

        if((senlen = maybe_sendto(sockfd, &rep_pkt, BUFF_SIZE, 0, client, *socklen)) == -1){
            close(sockfd);
            return(-1);
        }



    }else{

        make_pkt(RST, &rep_pkt);
        fprintf(stderr,"server sent struct %d %d \n",rep_pkt.type,rep_pkt.checksum);
        if((senlen = maybe_sendto(sockfd, &rep_pkt, BUFF_SIZE, 0, client, *socklen)) == -1){
            close(sockfd);
            return(-1);
        }
        return(-1);
    }



    return sockfd;
}

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
