/* Test program for kbfd NetBSD */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <netinet/in.h>

#include "kbfd.h"

#define DEVICE "/dev/kbfd1"

int
main(int argc, char **argv)
{
	struct bfd_nl_peerinfo peer;
	int fd;
	int ret;
	u_int32_t num;
	char abuf[INET6_ADDRSTRLEN];
	int i;
	struct bfd_nl_peerinfo *p1, *p2;
	fd_set rfds;

	if(argc != 2)
		err(2, "no args");

	if ((fd = open(DEVICE, O_RDWR)) < 0)
		err(1, "unable to open " DEVICE);

	memset((void *)&peer, 0, sizeof(struct bfd_nl_peerinfo));
//	inet_pton(AF_INET6, "::1", &peer.dst.sin6.sin6_addr);

	/* vmnet1 on mac */
//	inet_pton(AF_INET6, "fe80::250:56ff:fec0:1", &peer.dst.sin6.sin6_addr);
	/* eth2 on sarge */
	inet_pton(AF_INET6, "fe80::20c:29ff:fe94:82b4", &peer.dst.sin6.sin6_addr);

	peer.dst.sin6.sin6_family = AF_INET6;
	peer.ifindex = 2;

	if(strcmp(argv[1], "-a") == 0){
		ret = ioctl(fd, BFD_NEWPEER, &peer);
	}
	else if(strcmp(argv[1], "-d") == 0){
		ret = ioctl(fd, BFD_DELPEER, &peer);
	}
	else if(strcmp(argv[1], "-s") == 0){
		ret = ioctl(fd, BFD_GETPEER_NUM, &num);
		if(ret == -1)
			perror("ioctl(GET_NUM)");
		printf("The Number of Peer is %u\n", num);

		p2 = malloc(num * sizeof(struct bfd_nl_peerinfo));
		if(!p2)
			perror("malloc");
		memset(p2, 0, sizeof(*p2));

		ret = ioctl(fd, BFD_GETPEER, p2);
		if(ret == -1)
			perror("ioctl(GET_PEER)");
		for(i=0; i<num; i++){
			printf("Peer: addr=%s\n", 
			    inet_ntop(AF_INET6, &p2->dst.sin6.sin6_addr, abuf, sizeof(abuf)));
			p2++;
		}
	}
	if (ret < 0)
		err(2, "ioctl(" DEVICE ")");

	/* waiting status change from kernel */
	if(strcmp(argv[1], "-w") == 0){
		while(1){
			while(1) {
				struct timeval to;
				memset(&to, 0, sizeof(to));
				to.tv_sec = 1;
				to.tv_usec = 0;
				FD_ZERO(&rfds);
				FD_SET(fd, &rfds);

				ret = select(fd+1, &rfds, NULL, NULL, NULL);
				if(ret == 0){
//					printf("timeout\n");
					continue;
				}
				if(ret < 0)
					perror("select");
				break;
			}
			p1 = malloc(sizeof(*p1));
			ret = read(fd, p1, sizeof(*p1));
			if(ret < 0)
				perror("read notify");
			printf("Change Status Peer: addr=%s, ret=%d\n ===> %d\n", 
			    inet_ntop(AF_INET6, &p1->dst.sin6.sin6_addr, abuf, sizeof(abuf)),
			    ret,
			    p1->state);
			free(p1);
		}
	}


	close(fd);

	return 0;
}

