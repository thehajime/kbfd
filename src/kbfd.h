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

#define KBFD_VERSION "0.2"

/* Protocol Name Define FIXME */
#ifdef linux
#define NETLINK_BFD (NETLINK_GENERIC + 1)
#endif /* linux */

/*
 * netlink message type
 */
#ifdef linux
#define  BFD_NEWPEER                         1 /* Add BFD Session */
#define  BFD_DELPEER                         2 /* Delete BFD Session */
#define  BFD_GETPEER                         3 /* Get Peer Information */
#define  BFD_ADMINDOWN                       4 /* Set Session to AdminDown */
#define  BFD_SETLINK                         5 /* Set Interface Parameter */
#define  BFD_SETFLAG                         6 /* Set Debug Flag Parameter */
#define  BFD_CLEAR_COUNTER                   7 /* Clear Counter */
#define  BFD_CLEAR_SESSION                   8 /* Re-Initialize Session */
#elif defined __NetBSD__
#define  BFD_NEWPEER         _IOW('B', 1, struct bfd_nl_peerinfo) 
#define  BFD_DELPEER         _IOW('B', 2, struct bfd_nl_peerinfo) 
#define  BFD_GETPEER         _IOWR('B', 3, struct bfd_nl_peerinfo) 
#define  BFD_GETPEER_NUM     _IOR('B', 4, int) 
#define  BFD_ADMINDOWN       _IOW('B', 5, int) 
#define  BFD_SETLINK         _IOW('B', 6, struct bfd_nl_linkinfo) 
#define  BFD_SETFLAG         _IOW('B', 7, int) 
#define  BFD_CLEAR_COUNTER   _IOW('B', 8, int) 
#define  BFD_CLEAR_SESSION   _IOW('B', 9, int) 
#endif	/* __NetBSD__ */

/* 
 * BFD State
 */
#define    BSM_AdminDown		             0
#define    BSM_Down		                     1
#define    BSM_Init		                     2
#define    BSM_Up		                     3
#define    BFD_BSM_STATE_MAX                 4

/* 
 * BFD Flags
 */
#define  BFD_DEBUG_BSM             (1 << 0)
#define  BFD_DEBUG_CTRL_PACKET     (1 << 1)
#define  BFD_DEBUG_UIO             (1 << 2)
#define  BFD_DEBUG_DEBUG           (1 << 3)

/* Peer Information */
struct bfd_nl_peerinfo
{
#if defined (__NetBSD__)
	SIMPLEQ_ENTRY(bfd_nl_peerinfo) sendq;
#endif
	u_int8_t is1hop;
	u_int8_t state;
	u_int16_t pad2;
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

    /* counters */
	u_int64_t pkt_in;
	u_int64_t pkt_out;
	u_int32_t last_up;
	u_int32_t last_down;
	u_int32_t last_diag;
	u_int32_t up_cnt;
	u_int32_t last_discont;		/* FIXME(not implemented) */
};

struct bfd_nl_linkinfo
{
	int ifindex;
	u_int32_t mintx;
	u_int32_t minrx;
	u_int32_t mult;
};

#if defined (__KERNEL__) || (_KERNEL)
int bfd_uio_init(void);
void bfd_uio_finish(void);
void bfd_user_notify(struct bfd_session *);
#endif /* __KERNEL__ */

#endif /* __KBFD_NETLNIK_H_ */
