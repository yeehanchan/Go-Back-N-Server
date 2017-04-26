#define _XOPEN_SOURCE
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
    s.last_acked = -1;
    s.track = 0;
    s.mode = SLOW;

}


/*Define a new method to calculate checksum for a packet without packet filed checksum */
/*Thanks Kesden's help! */
uint16_t packet_checksum(gbnhdr *packet) {
	
	uint16_t header = ((uint16_t)packet->type << 8) + (uint16_t)packet->seqnum;

    int nwords = (sizeof(packet->type) + sizeof(packet->seqnum) + sizeof(packet->data)) / sizeof(uint16_t);
    uint16_t buf[nwords];
    buf[0] = header;

    int i;
    for (i = 1; i <= sizeof(packet->data); i++) {
        int index = (i+1)/2;
        if (i % 2 == 0) {
        	/*append data*/
        	index -=1;
            buf[index] += packet->data[i-1];
        } else {
        	/*new data*/
            buf[index] = packet->data[i-1];
        }
    }
    return checksum(buf, nwords);
}

int checkPkt(gbnhdr * pkt){

	/* 

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
    */

    if (pkt->checksum == packet_checksum(pkt)){
    	return 0;
    }
    else{
    	return 1;
    }
}


int make_data_pkt(gbnhdr * pkt,uint8_t type,int seq, char *data){

    pkt->type = type;
    pkt->seqnum = seq;
    int i;
    if(type == DATA){
        for(i = 0; i < strlen(data); i++) {
            pkt->data[i] = data[i] - '0';
        }
        /* pkt->checksum = checksum((uint16_t*)pkt, sizeof(pkt)); */
        pkt->checksum = packet_checksum(pkt);
    }

    return 1;
}




int make_pkt(uint8_t type, gbnhdr * pkt){

    switch(type) {
        case SYN :
            pkt->type = SYN;
            /* pkt->checksum = checksum((uint16_t*)pkt, sizeof(pkt)); */
            pkt->checksum = packet_checksum(pkt);
            return EXIT_SUCCESS;

        case SYNACK :
            pkt->type = SYNACK;
            /* pkt->checksum = checksum((uint16_t*)pkt, sizeof(pkt)); */
            pkt->checksum = packet_checksum(pkt);
            return EXIT_SUCCESS;


        case FIN :

            pkt->type = FIN;
            /* pkt->checksum = checksum((uint16_t*)pkt, sizeof(pkt)); */
            pkt->checksum = packet_checksum(pkt);
            return EXIT_SUCCESS;

        case FINACK :

            pkt->type = FINACK;
            /* pkt->checksum = checksum((uint16_t*)pkt, sizeof(pkt)); */
            pkt->checksum = packet_checksum(pkt);
            return EXIT_SUCCESS;
        case RST :

            pkt->type = RST;
            /* pkt->checksum = checksum((uint16_t*)pkt, sizeof(pkt)); */
            pkt->checksum = packet_checksum(pkt);
            return EXIT_SUCCESS;
    }


    return(-1);
}


void handle_timeout()
{
    if(conn_retry_counts < CONNECTION_RETRY_LIMIT){

        gbnhdr *syn_packet;
        syn_packet = malloc(sizeof(struct gbnhdr*));
        make_pkt(SYN, syn_packet);
        if((maybe_sendto(s.client_sockfd, syn_packet, BUFF_SIZE, 0, s.server, s.server_socklen) == -1)){
            close(s.client_sockfd);
            exit(-1);
        }
        conn_retry_counts ++;
        fprintf(stderr,"retry times %d: client sent syn\n",conn_retry_counts);
        free(syn_packet);
        fprintf(stderr, "syn_packet has been freed\n");
        alarm(TIMEOUT);

    }else{
        close(s.client_sockfd);
        fprintf(stderr,"Connection Limit Reached, Close Socket \n");
        exit(0);
    }
}



void gbn_send_timeout() {
    fprintf(stderr,"TIMEOUT.\n");
}





ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags){
	

	/* Hint: Check the data length field 'len'.
	 *       If it is > DATALEN, you will have to split the data
	 *       up into multiple packets - you don't have to worry
	 *       about getting more than N * DATALEN.
	 */

    if(s.state_type != ESTABLISHED){
        return(-1);
    }


    struct sigaction sact = {
            .sa_handler = &gbn_send_timeout,
            .sa_flags = 0,
    };
    sigaction(SIGALRM, &sact, NULL);

    char *token = buf, *end = buf;
    struct sockaddr *server = s.server;
    socklen_t socklen = s.server_socklen;
    int i,attempts = 0;
    ssize_t revlen,sendlen;
    int chunksize = 10;

    if(s.track < N){
        while(strlen(end) != NULL){

            char *p = end;
            int len = strlen(p);

            if(len > DATALEN){

                while(len > 0){
                    strncpy(s.data[s.track],p,DATALEN);
                    p = p + DATALEN;
                    len -= DATALEN;
                    s.track++;
                }

            }
            else{
                strcpy(s.data[s.track],p);
                s.track++;
            }
            strsep(&end,"\n");
            if(end == NULL || strlen(end) == 0){
                break;
            }
        }


    }else{
        fprintf(stderr,"buffer too long\n");
    }

    fprintf(stderr,"finish input \n");

    /*Sliding Window*/
    s.track = 0;

    gbnhdr *data_packet, *data_ack, *data_packet_1, *data_ack_1,*fin_packet;
    data_packet = malloc(sizeof(struct gbnhdr*)*N);
    data_packet_1 = malloc(sizeof(struct gbnhdr*)*N);
    data_ack = malloc(sizeof(struct gbnhdr*)*N);
    data_ack_1 = malloc(sizeof(struct gbnhdr*)*N);
    fin_packet =  malloc(sizeof(struct gbnhdr*)*N);

    make_pkt(FIN,fin_packet);



    while(s.track < N){

        if(s.mode == FAST){

            if(strlen(s.data[s.track]) == 0 || strlen(s.data[s.base]) == 0){
                break;
            }

            fprintf(stderr,"Mode: Fast Mode \n");

            if(s.track == s.base) {

                make_data_pkt(data_packet,DATA,s.track,s.data[s.track]);
                make_data_pkt(data_packet_1,DATA,s.track+1,s.data[s.track+1]);

            }
            else if(s.track > s.base && s.track < s.base + 2){

                make_data_pkt(data_packet,DATA,s.base,s.data[s.base]);
                make_data_pkt(data_packet_1,DATA,s.track,s.data[s.track]);

            }

            /*send packet 1*/
            if(maybe_sendto(sockfd,data_packet, BUFF_SIZE, 0, server, socklen) == -1){
                fprintf(stderr,"data packet sent error \n");
                s.mode = SLOW;
                continue;
            }

            fprintf(stderr,"client sent first pkt seq %d\n",data_packet->seqnum);

            /*send packet 2*/
            if(maybe_sendto(sockfd,data_packet_1, BUFF_SIZE, 0, server, socklen) == -1){
                fprintf(stderr,"data packet sent error \n");
                s.mode = SLOW;
                continue;
            }

            fprintf(stderr,"client sent second pkt seq %d\n",data_packet_1->seqnum);

            alarm(TIMEOUT);


            /*First ack */
            /*if packet lost, wait for ack of second packet*/
            if(recvfrom(sockfd, data_ack, BUFF_SIZE, 0, server, &socklen) == -1){
                fprintf(stderr,"first ack lost \n");
            }
            /*if time out, wait for ack of second packet*/
            if(errno == EINTR){
                fprintf(stderr,"first acked timeout \n");
            }
            else if(data_ack->data[0] != data_packet->seqnum){
                fprintf(stderr,"first acked is not expected \n");
                if(data_ack->data[0] > s.base - 1){
                    s.base = data_ack->data[0] + 1;
                    s.track = s.base;
                }

            }
            else if(data_ack->type == DATAACK && checkPkt(data_ack) == 0){
                s.base = s.track + 1;
                fprintf(stderr,"client received first ack %d \n",data_ack->data[0]);
            }

            alarm(TIMEOUT);
            /* if packet lost, break loop*/
            if(recvfrom(sockfd, data_ack_1, BUFF_SIZE, 0, server, &socklen) == -1){
                fprintf(stderr,"second ack lost \n");
                if(s.base == s.track + 1){
                    s.track++;
                }else{
                    s.mode = SLOW;
                }
                continue;
            }
            /*if timeout, break the loop*/
            if(errno == EINTR){
                fprintf(stderr,"second acked timeout \n");
                if(s.base == s.track + 1){
                    s.track++;
                }else{
                    s.mode = SLOW;
                }
                continue;
            }
            else if(data_ack_1->data[0] != data_packet_1->seqnum){
                fprintf(stderr,"second ack is not expected \n");
                if(s.base == s.track + 1){
                    s.track++;
                }else{
                    s.mode = SLOW;
                }

                if(data_ack->data[0] > s.base - 1){
                    s.base = data_ack->data[0] + 1;
                    s.track = s.base;
                }

                continue;
            }
            else if(data_ack->type == DATAACK && checkPkt(data_ack) == 0){
                s.base = s.track + 2;
                s.track += 2;
                fprintf(stderr,"client received second ack %d \n",data_ack_1->data[0]);
                continue;
            }

        }


        if(s.mode == SLOW){


            if(strlen(s.data[s.track]) == 0 || strlen(s.data[s.base]) == 0){
                break;
            }
            fprintf(stderr,"Mode: Slow Mode \n");

            if(s.track == s.base){


                attempts = 0;

                while(attempts < 5){


                    make_data_pkt(data_packet,DATA,s.track,s.data[s.track]);


                    if(maybe_sendto(sockfd,data_packet, BUFF_SIZE, 0, server, socklen) == -1){
                        fprintf(stderr,"data packet sent error \n");
                        attempts++;
                        continue;
                    }

                    fprintf(stderr,"1 attempts %d: client sent new pkt seq %d \n",attempts,data_packet->seqnum);
                    alarm(TIMEOUT);



                    if(recvfrom(sockfd, data_ack, BUFF_SIZE, 0, server, &socklen) == -1){
                        fprintf(stderr,"acked packet lost \n");
                        attempts++;
                        continue;
                    }

                    if(errno == EINTR){
                        fprintf(stderr,"slow mode acked timeout \n");
                        attempts++;
                        continue;
                    }
                    else if(data_ack->data[0] != data_packet->seqnum){
                        fprintf(stderr,"acked packet is not expected one \n");
                        if(data_ack->data[0] > s.base - 1){
                            s.base = data_ack->data[0] + 1;
                            s.track = s.base;
                            s.mode = FAST;
                            break;
                        }else{
                            attempts++;
                            continue;
                        }
                    }
                    else if(data_ack->type == DATAACK && checkPkt(data_ack) == 0){
                        s.base = s.track +1;
                        s.track++;
                        fprintf(stderr,"client received ack %d \n",data_ack->data[0]);
                        s.mode = FAST;
                        break;
                    }

                }

                if(attempts == 5){/*Send fin to server*/
                    fprintf(stderr,"5 Attempts! Quit!\n");
                    if(maybe_sendto(sockfd,fin_packet, BUFF_SIZE, 0, server, socklen) == -1){
                        fprintf(stderr,"SEND FIN LOST\n");
                    }
                    gbn_close(sockfd);


                    return DATALEN;
                }


            }


            if(s.base < s.track){


                attempts = 0;

                while(attempts < 5){


                    make_data_pkt(data_packet,DATA,s.base,s.data[s.base]);

                    if(maybe_sendto(sockfd,data_packet, BUFF_SIZE, 0, server, socklen) == -1){
                        fprintf(stderr,"data packet sent error \n");
                        attempts++;
                    }

                    fprintf(stderr,"2 attempts %d: client sent unacked pkt seq %d \n",attempts,data_packet->seqnum);
                    alarm(TIMEOUT);


                    if((revlen = recvfrom(sockfd, data_ack, BUFF_SIZE, 0, server, &socklen) == -1)){
                        fprintf(stderr,"acked packet received error \n");
                        attempts++;
                        continue;
                    }

                    if(errno == EINTR){
                        attempts++;
                        continue;
                    }
                    else if(data_ack->data[0] != data_packet->seqnum){
                        fprintf(stderr,"acked packet is not sent packet \n");
                        attempts++;
                        continue;
                    }
                    else if(data_ack->type == DATAACK && checkPkt(data_ack) == 0){
                        s.base++;
                        fprintf(stderr,"client received ack %d \n",data_ack->data[0]);
                        s.mode = FAST;
                        break;
                    }
                }

                if(attempts == 5){/*Send fin to server*/
                    fprintf(stderr,"5 Attempts! Quit!\n");
                    if(maybe_sendto(sockfd,fin_packet, BUFF_SIZE, 0, server, socklen) == -1){
                        fprintf(stderr,"SEND FIN LOST\n");
                    }
                    gbn_close(sockfd);

                    return(-1);
                }

            }


        }


    }

    if(sendto(sockfd,fin_packet, BUFF_SIZE, 0, server, socklen) == -1){
        fprintf(stderr,"FIN LOST\n");
    }
    gbn_close(sockfd);



    free(data_packet);
    free(data_ack);
    free(data_ack_1);
    free(data_packet_1);
    free(fin_packet);

    return EXIT_SUCCESS;

}




ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){


    struct sockaddr *client = s.client;
    socklen_t socklen = s.client_socklen;
    gbnhdr *data_pkt,*data_ack;
    data_pkt = malloc(sizeof(struct gbnhdr*)*N);
    data_ack = malloc(sizeof(struct gbnhdr*)*N);
    ssize_t revlen;
    int i,j;


    if((revlen = recvfrom(sockfd, data_pkt, BUFF_SIZE, 0, client, &socklen) == -1)){
        close(sockfd);
        return(-1);
    }

    fprintf(stderr,"server received packet %d\n",data_pkt->seqnum);


    if(data_pkt->type == DATA ){

        if(data_pkt->seqnum == s.last_acked+1){

            data_ack->type = DATAACK;
            data_ack->seqnum = data_pkt->seqnum+1;
            data_ack->data[0] = data_pkt->seqnum;
            /*data_ack->checksum = checksum((uint16_t*)data_ack, sizeof(data_ack)); */
            data_ack->checksum = packet_checksum(data_ack);
            fprintf(stderr,"1 server acked %d, expected %d\n",data_ack->data[0],data_ack->seqnum);
            s.last_acked = data_ack->data[0];
            maybe_sendto(sockfd, data_ack, BUFF_SIZE, 0, s.client, s.client_socklen);



            
            for(i=0; i < sizeof(data_pkt->data); i++){
                if(data_pkt->data[i] == NULL){
                    break;
                }
            }
            char *tmp = malloc(sizeof(char)*i);
            if(i > 0){
                for(j = 0; j < i; j++){
                    tmp[j] = data_pkt->data[j] + '0';  
                }
                strcpy((char *) buf, "");
                strcpy((char *) buf, tmp);
                fprintf(stderr,"server output content %d %s\n",i-1,buf);
            }

        }
        else{

            data_ack->type = DATAACK;
            data_ack->seqnum = s.last_acked+1;
            data_ack->data[0] = s.last_acked;
            /* data_ack->checksum = checksum((uint16_t*)data_ack, sizeof(data_ack)); */
            data_ack->checksum = packet_checksum(data_ack);
            fprintf(stderr,"2 server acked %d, expected %d\n",data_ack->data[0],data_ack->seqnum);
            maybe_sendto(sockfd, data_ack, BUFF_SIZE, 0, s.client, s.client_socklen);
        }
        return i;
    }
    else if(data_pkt->type == FIN && checkPkt(data_pkt) == 0){
        make_pkt(FINACK,data_ack);
        fprintf(stderr,"Finish Acked \n");
        maybe_sendto(sockfd, data_ack, BUFF_SIZE, 0, s.client, s.client_socklen);
        gbn_close(sockfd);
        
        free(data_ack);
        free(data_pkt);
        return 0;
    }
    
}



int gbn_close(int sockfd){

    close(sockfd);
	return EXIT_SUCCESS;
}



int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen){


    gbn_init();

    ssize_t senlen, revlen;
    gbnhdr *syn_packet, *syn_ack_pkt;
    s.server = server;
    s.client_sockfd = sockfd;

    syn_packet = malloc(sizeof(struct gbnhdr *)*N);
    syn_ack_pkt = malloc(sizeof(struct gbnhdr *)*N);
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




int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen){

    gbn_init();


    ssize_t revlen, senlen;
    gbnhdr *syn_pkt, *rep_pkt;
    s.client = client;
    s.server_sockfd = sockfd;
    syn_pkt = malloc(sizeof(struct gbnhdr *)*N);
    rep_pkt = malloc(sizeof(struct gbnhdr *)*N);



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
