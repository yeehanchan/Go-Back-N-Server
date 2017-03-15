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



// need to be modified later
ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags){
	

	/* Hint: Check the data length field 'len'.
	 *       If it is > DATALEN, you will have to split the data
	 *       up into multiple packets - you don't have to worry
	 *       about getting more than N * DATALEN.
	 */




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


    ssize_t senlen;
    char buf[100];

    sprintf(buf, "request connection");
    if((senlen = sendto(sockfd, buf, 100, 0, server, socklen) == -1)){
        close(sockfd);
        return(-1);
    }

	return EXIT_SUCCESS;
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

    ssize_t revlen;
    printf("listener: waiting for revfrom\n");
    char buf[100];

    if((revlen = recvfrom(sockfd, buf, 100, 0, client, socklen) == -1)){
        close(sockfd);
        return (-1);
    }else{
        printf("received %s\n", buf);
        printf("accepted \n");
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
