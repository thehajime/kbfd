/* Test program for kbfd NetBSD */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <netinet/in.h>

#include "kbfd_netlink.h"

#define DEVICE "/dev/kbfd0"

int
main(int argc, char **argv)
{
	struct bfd_nl_peerinfo peer;
	int fd;
	int ret;

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
	else
		err(2, "no such option");
	if (ret < 0)
		err(2, "ioctl(" DEVICE ")");

	close(fd);

	return 0;
}

