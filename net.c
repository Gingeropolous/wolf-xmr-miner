#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "minerlog.h"

#define INVALID_SOCKET	-1

int ConnectToPool(char *URL, char *Port)
{
	int ret, sockfd;
	struct addrinfo filter, *poolinfo, *tmp;
	
	memset(&filter, 0, sizeof(struct addrinfo));
	filter.ai_family = AF_INET;
	filter.ai_socktype = SOCK_STREAM;
	filter.ai_flags = AI_PASSIVE;
	filter.ai_protocol = IPPROTO_TCP;
	
	ret = getaddrinfo(URL, Port, &filter, &poolinfo);
	
	if(ret)
	{
		Log(LOG_CRITICAL, "The attempt to get the address for the pool failed with code %d.", ret);
		return(INVALID_SOCKET);
	}
	
	sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(sockfd == INVALID_SOCKET)
	{
		Log(LOG_CRITICAL, "The attempt to create a socket failed.");
		freeaddrinfo(poolinfo);
		return(INVALID_SOCKET);
	}
	
	for(tmp = poolinfo; tmp; tmp = tmp->ai_next)
	{
		ret = connect(sockfd, tmp->ai_addr, tmp->ai_addrlen);
		if(ret != INVALID_SOCKET) break;
		
		Log(LOG_ADVINFO, "The attempt to connect to the pool failed.");
	}
	
	// Did we run out of addresses before successfully connecting?
	if(!tmp)
	{
		Log(LOG_CRITICAL, "Failed to connect to any of the pool's addresses.");
		freeaddrinfo(poolinfo);
		return(INVALID_SOCKET);
	}
	
	freeaddrinfo(poolinfo);
	return(sockfd);
}
