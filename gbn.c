#include "gbn.h"

uint16_t checksum(uint16_t *buf, int nwords)
{
    uint32_t sum;

    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}




void gbn_init(){
    s.state_type = CLOSED;
    s.server_socklen = sizeof(struct sockaddr);
    s.client_socklen = sizeof(struct sockaddr_in);
    s.base = 0;
    s.nextseq = 0;
    s.last_acked = -1;
    s.seq = 0;
    s.mode = 0;

}





//check interity
int checkPkt(gbnhdr * pkt){

    uint16_t cs;
    char data[DATALEN],buf[BUFF_SIZE];
    int i;

    if(pkt->type == DATA || pkt->type == DATAACK ){

        cs = checksum((uint16_t *)pkt, sizeof(pkt));
    }
    else{
        cs = checksum((uint16_t *)pkt, sizeof(pkt));
    }
    if(cs == 0){
        return 0;
    }
    return 1;
}


int make_data_pkt(gbnhdr * pkt,uint8_t type,uint8_t seq, char *data){

    pkt->type = type;
    pkt->seqnum = seq;
    int i;
    if(type == DATAACK){
        pkt->data[0] = atoi(data);
    }
    else{
        for(i = 0; i < strlen(data); i++) {
            pkt->data[i] = data[i] - '0';
        }
    }
    pkt->checksum = checksum((uint16_t*)pkt, sizeof(pkt));
    return 1;
}




// make packet based on type
int make_pkt(uint8_t type, gbnhdr * pkt){

    switch(type) {
        case SYN :
            pkt->type = SYN;
            pkt->checksum = checksum((uint16_t*)pkt, sizeof(pkt));
            return EXIT_SUCCESS;

        case SYNACK :
            pkt->type = SYNACK;
            pkt->checksum = checksum((uint16_t*)pkt, sizeof(pkt));
            return EXIT_SUCCESS;


        case FIN :

            pkt->type = FIN;
            pkt->checksum = checksum((uint16_t*)pkt, sizeof(pkt));
            return EXIT_SUCCESS;

        case FINACK :

            pkt->type = FINACK;
            pkt->checksum = checksum((uint16_t*)pkt,sizeof(pkt));
            return EXIT_SUCCESS;
        case RST :

            pkt->type = RST;
            pkt->checksum = checksum((uint16_t*)pkt,sizeof(pkt));
            return EXIT_SUCCESS;
    }


    return(-1);
}


void handle_timeout()
{
    //alert when timed out
    if(conn_retry_counts < CONNECTION_RETRY_LIMIT){

        // send a syn pkt to server
        gbnhdr *syn_packet;
        syn_packet = malloc(sizeof(struct gbnhdr*));
        make_pkt(SYN, syn_packet);
        if((maybe_sendto(s.client_sockfd, syn_packet, BUFF_SIZE, 0, s.server, s.server_socklen) == -1)){
            close(s.client_sockfd);
            exit(-1);
        }
        conn_retry_counts ++;
        fprintf(stderr,"retry %d: client sent syn\n",conn_retry_counts);
        free(syn_packet);
        alarm(TIMEOUT);

    }else{
        close(s.client_sockfd);
        fprintf(stderr,"Connection Limit Reached, Close Socket \n");
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

    if(s.state_type != ESTABLISHED){
        return(-1);
    }

    char *token;
    struct sockaddr *server = s.server;
    socklen_t socklen = s.server_socklen;
    int i;
//
//
    if(s.seq < N){
        while((token = strsep(&buf,"\n")) != NULL){

            char *p = token;
            int len = strlen(token);
            // split oversized packet
            if(len > DATALEN){

                while(len > 0){
                    strncpy(s.data[s.seq],p,DATALEN);
                    p = p + DATALEN;
                    len -= DATALEN;
                    s.seq++;

                }

            }
            else{
                strcpy(s.data[s.seq],token);
                s.seq++;
            }
        }

    }else{
        fprintf(stderr,"buffer too long\n");
    }


//    /*TODO: sliding window*/

    gbnhdr data_packet;
    make_pkt(FIN,&data_packet);
    if(sendto(sockfd, &data_packet, BUFF_SIZE, 0, server, socklen) == -1){
        return(-1);
    }
    fprintf(stderr,"client sent pkt %d \n",data_packet.type);
	return EXIT_SUCCESS;
}




// need to be modified later
ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){

    printf("listening to client ...\n");


    struct sockaddr *client = s.client;
    socklen_t socklen = s.client_socklen;
    gbnhdr *data_pkt,*data_ack;
    data_pkt = malloc(sizeof(struct gbnhdr *));
    data_ack = malloc(sizeof(struct gbnhdr *));
    ssize_t revlen;
    int i;


    if((revlen = recvfrom(sockfd, data_pkt, BUFF_SIZE, 0, client, &socklen) == -1)){
        close(sockfd);
        return(-1);
    }

    fprintf(stderr,"server received packet %d \n",data_pkt->seqnum);


    if(data_pkt->type == DATA && checkPkt(data_pkt) == 0){

        if(data_pkt->seqnum == s.last_acked + 1){

            //write to file
            char *tmp;
            tmp = malloc(DATALEN* sizeof(char));
            for(i=0; i < sizeof(data_pkt->data); i++){
                tmp[i] = data_pkt->data[i] + '0';
            }
            strcat(tmp,"\0\n");
            strcpy((char *) buf, tmp);

            //ack to client
            char *ack = data_pkt->seqnum+"0";
            make_data_pkt(data_ack,DATAACK,data_pkt->seqnum+1,ack);
            maybe_sendto(sockfd, data_ack, BUFF_SIZE, 0, s.client, s.client_socklen);
            s.last_acked++;
            fprintf(stderr,"1 server acked %d, expected %d\n",data_ack->data[0],data_ack->seqnum);

        }
        else{
            char *ack;
            if(s.last_acked < 0){
                ack = "255";
            }
            else{
                sprintf(ack,"%d",s.last_acked);
            }
            make_data_pkt(data_ack,DATAACK,s.last_acked+1,ack);
            maybe_sendto(sockfd, data_ack, BUFF_SIZE, 0, s.client, s.client_socklen);
            fprintf(stderr,"2 server acked %d, expected %d\n",data_ack->data[0],data_ack->seqnum);

        }



        return DATALEN;
    }
    else if(data_pkt->type = FIN && checkPkt(data_pkt) == 0){
        make_pkt(FINACK,data_ack);
        maybe_sendto(sockfd, data_ack, BUFF_SIZE, 0, s.client, s.client_socklen);
        fprintf(stderr,"Finish Acked \n");
        free(data_pkt);
        free(data_ack);
        return 0;
    }

    return 0;
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
    gbnhdr *syn_packet, *syn_ack_pkt;
    s.server = server;
    s.client_sockfd = sockfd;

    syn_packet = malloc(sizeof(struct gbnhdr *));
    syn_ack_pkt = malloc(sizeof(struct gbnhdr *));
    // make a syn pkt
    make_pkt(SYN, syn_packet);
    if((senlen = maybe_sendto(sockfd, syn_packet, BUFF_SIZE, 0, server, socklen) == -1)){
        close(sockfd);
        return(-1);
    }

    fprintf(stderr,"client sent struct  %d %d\n",syn_packet->type,syn_packet->checksum);
    s.state_type = SYN_SENT;

    signal(SIGALRM,&handle_timeout);
    alarm(TIMEOUT);





    if((revlen = recvfrom(sockfd, syn_ack_pkt, BUFF_SIZE, 0, server, &socklen) == -1)){
        close(sockfd);
        return(-1);
    }



    fprintf(stderr,"client received  %d %d\n",syn_ack_pkt->type,syn_ack_pkt->checksum);
    if(syn_ack_pkt->type == SYNACK && checkPkt(syn_ack_pkt) == 0){
        s.state_type = ESTABLISHED;
        fprintf(stdout,"connection established\n");
        return EXIT_SUCCESS;

    }

    if(syn_ack_pkt->type == RST){
        printf("connection rejected\n");
        return EXIT_SUCCESS;
    }

    free(syn_ack_pkt);
    free(syn_packet);

    return (-1);



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

    gbn_init();


    ssize_t revlen, senlen;
    gbnhdr *syn_pkt, *rep_pkt;
    s.client = client;
    s.server_sockfd = sockfd;
    syn_pkt = malloc(sizeof(struct gbnhdr *));
    rep_pkt = malloc(sizeof(struct gbnhdr *));



    printf("listener: waiting for revfrom\n");




    if((revlen = recvfrom(sockfd, syn_pkt, BUFF_SIZE, 0, client, socklen) == -1)){
        close(sockfd);
        return(-1);
    }
    fprintf(stderr,"server received struct %d %d \n",syn_pkt->type,syn_pkt->checksum);
    fprintf(stderr,"server computes checksum %d \n",checksum(syn_pkt, sizeof(syn_pkt)));
    s.state_type = SYN_RCVD;



    if(syn_pkt->type == SYN && checkPkt(syn_pkt) == 0){
        make_pkt(SYNACK, rep_pkt);
        fprintf(stderr,"server sent struct %d %d \n",rep_pkt->type,rep_pkt->checksum);

        if((senlen = maybe_sendto(sockfd, rep_pkt, BUFF_SIZE, 0, client, *socklen)) == -1){
            close(sockfd);
            return(-1);
        }


    }else{

        make_pkt(RST, rep_pkt);
        fprintf(stderr,"server sent struct %d %d \n",rep_pkt->type,rep_pkt->checksum);
        if((senlen = maybe_sendto(sockfd, rep_pkt, BUFF_SIZE, 0, client, *socklen)) == -1){
            close(sockfd);
            return(-1);
        }
        return(-1);
    }

    free(syn_pkt);
    free(rep_pkt);

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
