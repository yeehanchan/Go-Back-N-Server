#include "gbn.h"


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
int checkPkt(int type, gbnhdr *pkt){

    uint16_t cs;
    if(type == 0){
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
            pkt->checksum = checksum((uint16_t *)pkt, 1);
            return EXIT_SUCCESS;

        case SYNACK :
            pkt->type = SYNACK;
            pkt->checksum = checksum((uint16_t *)pkt, 1);
            return EXIT_SUCCESS;


        case DATA :

            pkt->type = DATA;
            pkt->seqnum = seq++;
            pkt->checksum = checksum((uint16_t *)pkt, 3);

            return EXIT_SUCCESS;


        case DATAACK :

            pkt->type = DATAACK;
            pkt->checksum = checksum((uint16_t *)pkt, 3);

            return EXIT_SUCCESS;


        case FIN :

            pkt->type = FIN;
            pkt->checksum = checksum((uint16_t *)pkt, 1);

            return EXIT_SUCCESS;

        case FINACK :

            pkt->type = FINACK;
            pkt->checksum = checksum((uint16_t *)pkt, 1);

            break;
        case RST :

            pkt->type = RST;
            pkt->checksum = checksum((uint16_t *)pkt, 1);

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
                    while((token = strsep(&buff, "\t") != NULL)){
                        pkt->data[j] = atoi(token);
                        j++;
                    }
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

    char *token;
    struct sockaddr *server = s.server;
    socklen_t socklen = s.socklen;
    struct gbnhdr* pkts[];


    while(token = strsep(&buf,"\n") != NULL){
        if(strlen(token) > DATALEN){
            /*TODO: split */
        }
        else{
            /*TODO: make pkt*/
        }
    }

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
    char syn_buf[BUFF_SIZE], rev_buf[BUFF_SIZE];
    gbnhdr syn_packet, syn_ack_pkt;




    // make a syn pkt
    make_pkt(SYN, &syn_packet);
    sprintf(syn_buf,"%d\t%d\n",syn_packet.type,syn_packet.checksum);

    // send a syn pkt to server
    if((senlen = sendto(sockfd, syn_buf, BUFF_SIZE, 0, server, socklen) == -1)){
        close(sockfd);
        return(-1);
    }
    s.state_type = SYN_SENT;
    s.server = server;

    /* TODO: SET TIMER here. */

    /* TODO: IF NOTHING BACK, SEND AGAIN */

    /* TODO: BREAK CONNECTION IF NO RESPONSE AFTER 5 TIMES */


    // receive pkt from server
    if((revlen = recvfrom(sockfd, rev_buf, BUFF_SIZE, 0, server, &socklen) == -1)){
        close(sockfd);
        return(-1);
    }

    parse_pkt(1, rev_buf, &syn_ack_pkt);


    // received a synack
    if(syn_ack_pkt.type == SYNACK && checkPkt(1, &syn_ack_pkt) == 0){
        s.state_type = ESTABLISHED;
        fprintf(stdout,"connection established\n");
        return EXIT_SUCCESS;
    }

    if(syn_ack_pkt.type == RST){
        printf("connection rejected");
        return (-1);
    }




    return(-1);

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
    gbnhdr syn_pkt;
    gbnhdr rep_pkt;
    char sen_buf[BUFF_SIZE];
    char rev_buf[BUFF_SIZE];

    printf("listener: waiting for revfrom\n");


    if((revlen = recvfrom(sockfd, rev_buf, BUFF_SIZE, 0, client, socklen) == -1)){
        close(sockfd);
        return(-1);
    }

    s.state_type = SYN_RCVD;
    s.client = client;

    parse_pkt(1, rev_buf, &syn_pkt);

    if(syn_pkt.type == SYN && checkPkt(1,&syn_pkt) == 0){
        make_pkt(SYNACK, &rep_pkt);
        sprintf(sen_buf,"%d\t%d\n",rep_pkt.type,rep_pkt.checksum);

        if((senlen = sendto(sockfd, sen_buf, BUFF_SIZE, 0, client, *socklen)) == -1){
            close(sockfd);
            return(-1);
        }

    }else{
        make_pkt(RST, &rep_pkt);
        sprintf(sen_buf,"%d\t%d\n",rep_pkt.type,rep_pkt.checksum);

        if((senlen = sendto(sockfd, sen_buf, BUFF_SIZE, 0, client, *socklen)) == -1){
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
