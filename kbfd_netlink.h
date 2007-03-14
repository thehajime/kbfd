/* 
 *  BFD Netlink Interface
 *
 * base from draft-ietf-bfd-base-05.txt
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) Hajime TAZAKI, 2007
 */

#ifndef __KBFD_NETLNIK_H_
#define __KBFD_NETLNIK_H_


/* Protocol Name Define FIXME */
#define NETLINK_BFD (NETLINK_GENERIC + 1)

/*
 * netlink message type
 */
#define  BFD_NEWPEER                         1 /* Add BFD Session */
#define  BFD_DELPEER                         2 /* Delete BFD Session */
#define  BFD_GETPEER                         3 /* Get Peer Summary */
#define  BFD_GETPEERSTAT                     4 /* Get Peer Full Information */
#define  BFD_ADMINDOWN                       5 /* Set Session to AdminDown */
#define  BFD_SETLINK                         6 /* Set Interface Parameter */
#define  BFD_SETFLAG                         7 /*  */
#define  BFD_CLEAR_COUNTER                   8 /* Clear Counter */
#define  BFD_CLEAR_SESSION                   9 /* Re-Initialize Session */

/* 
 * BFD State
 */
#define    BSM_AdminDown		             0
#define    BSM_Down		                     1
#define    BSM_Init		                     2
#define    BSM_Up		                     3
#define    BFD_BSM_STATE_MAX                 4

/* Peer Information */
struct bfd_nl_peerinfo
{
	__u8 is1hop;
	__u8 state;
	__u16 pad2;
	union{
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	}dst;
	union{
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	}src;
	int ifindex;
	u_int32_t my_disc;
	u_int32_t your_disc;
};

struct bfd_nl_linkinfo
{
	int ifindex;
	u_int32_t mintx;
	u_int32_t minrx;
	u_int32_t mult;
};

#ifdef __KERNEL__
int bfd_netlink_init(void);
void bfd_netlink_finish(void);
void bfd_nl_send(struct bfd_session *);
#endif /* __KERNEL__ */


#endif /* __KBFD_NETLNIK_H_ */
