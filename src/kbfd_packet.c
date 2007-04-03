/* 
 *  BFD packet handling routine
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

#include <linux/workqueue.h>
#include <linux/in.h>
#include <net/sock.h>

#include "kbfd_packet.h"
#include "kbfd_session.h"
#include "kbfd_log.h"
#include "kbfd_netlink.h"
#include "kbfd.h"

extern struct bfd_master *master;

int
bfd_send_ctrl_packet(struct bfd_session *bfd)
{
	int len, err = 0;
	struct msghdr msg;
	struct iovec iov;
	mm_segment_t oldfs;
	struct bfd_ctrl_packet pkt;
	char buf[256];
	struct sched_param param;
	static int init = 0;

	/* Set scheduler(FIXME) */
	if (init == 0){
		param.sched_priority = MAX_RT_PRIO - 1;
		sched_setscheduler(current, SCHED_FIFO, &param);
		init++;
	}

	memcpy(&pkt, &bfd->cpkt, sizeof(struct bfd_ctrl_packet));

	memset(&msg, 0, sizeof(struct msghdr));
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_iov	 = &iov;
	msg.msg_iovlen = 1;
	msg.msg_name = bfd->dst;
	msg.msg_namelen = bfd->proto->namelen(bfd->dst);

	iov.iov_base = &pkt;
	iov.iov_len  = sizeof(struct bfd_ctrl_packet);

	oldfs = get_fs(); 
	set_fs(KERNEL_DS);
	if (IS_DEBUG_CTRL_PACKET)
		blog_info("SEND=>: Ctrl Pkt to %s",
				  bfd->proto->addr_print(bfd->dst, buf));
	len = sock_sendmsg(bfd->tx_ctrl_sock, &msg, iov.iov_len);
	if (len < 0)
		blog_err("sock_sendmsg returned: %d", len);
	set_fs(oldfs);

	/* Packet Count */
	bfd->pkt_out++;
	/* force final bit set to 0 */
	bfd->cpkt.final = 0;

	return err;
}

int
bfd_recv_ctrl_packet(struct bfd_proto *proto, struct sockaddr *src, 
					 struct sockaddr *dst,
					 int ifindex, char *buffer, int len)
{
	struct bfd_ctrl_packet *cpkt;
	struct bfd_session *bfd;
	char buf[256];
	int poll_seq_end = 0;

	if (IS_DEBUG_CTRL_PACKET)
		blog_info("RECV<=: Ctrl Pkt from %s, iif=%d", 
				  proto->addr_print(src, buf), ifindex);

	cpkt = (struct bfd_ctrl_packet *)buffer;

	/* Section 6.7.6 check */

	/* If the version number is not correct (1), the packet MUST be */
	/* discarded. */
	if (cpkt->version != BFD_VERSION_1){
		if (IS_DEBUG_CTRL_PACKET){
			blog_info("version isn't 1. Discarded");
		}
		return -1;
	}

	/* If the Length field is less than the minimum correct value (24 if */
	/* the A bit is clear, or 26 if the A bit is set), the packet MUST be */
	/* discarded. */
	if ((!cpkt->auth && cpkt->length < BFD_CTRL_LEN) ||
		(cpkt->auth && cpkt->length < BFD_CTRL_AUTH_LEN)){
		blog_warn("length is short. Discarded");
		return -1;
	}

	/* If the Length field is greater than the payload of the */
	/* encapsulating protocol, the packet MUST be discarded. */
	if (cpkt->length > len){
		blog_warn("length is too long. Discarded. %d>%d", 
                  cpkt->length, len);
		return -1;
	}

	/* If the Detect Mult field is zero, the packet MUST be discarded. */
	if (cpkt->detect_mult == 0){
		blog_warn("Detect Multi field is zero. Discarded");
		return -1;
	}

	/* If the My Discriminator field is zero, the packet MUST be discarded. */
	if (cpkt->my_disc == 0){
		blog_warn("My Discriminator field is zero. Discarded");
		return -1;
	}

	/* If the Your Discriminator field is nonzero, it MUST be used to */
	/* select the session with which this BFD packet is associated.  If */
	/* no session is found, the packet MUST be discarded. */
	if (cpkt->your_disc){
		if ((bfd = bfd_session_lookup(NULL, cpkt->your_disc, NULL, 0)) == NULL){
			if (IS_DEBUG_CTRL_PACKET){
				blog_info("couldn't find session with Discriminator field. Discarded");
			}
			return -1;
		}
	}
	else{
		/* If the Your Discriminator field is zero and the State field is not
		   Down or AdminDown, the packet MUST be discarded. */
		if (cpkt->state != BSM_AdminDown && cpkt->state != BSM_Down){
			blog_warn("Received state is not Down or AdminDown. Discarded");
			return -1;
		}

		/* If the Your Discriminator field is zero, the session MUST be
		   selected based on some combination of other fields, possibly
		   including source addressing information, the My Discriminator
		   field, and the interface over which the packet was received.  The
		   exact method of selection is application-specific and is thus
		   outside the scope of this specification.  If a matching session is
		   not found, a new session may be created, or the packet may be
		   discarded.  This choice is outside the scope of this
		   specification. */
		if ((bfd = bfd_session_lookup(proto, cpkt->your_disc, src, 0)) == NULL){
			if (IS_DEBUG_CTRL_PACKET){
				blog_info("couldn't find session without Discriminator field. Discarded");
				blog_info("src %s",proto->addr_print(src, buf));
			}
			return -1;
		}
	}

	/* mark our address */
	memcpy(bfd->src, dst, bfd->proto->namelen(dst));
	/* Packet Count */
	bfd->pkt_in++;

	/* If the A bit is set and no authentication is in use (bfd.AuthType
	   is zero), the packet MUST be discarded.
	   If the A bit is clear and authentication is in use (bfd.AuthType
	   is nonzero), the packet MUST be discarded. */
	if (cpkt->auth != bfd->cpkt.auth){
		if (IS_DEBUG_CTRL_PACKET){
			blog_info("Auth type isn't same. Discarded");
		}
		return -1;
	}

	/* If the A bit is set, the packet MUST be authenticated under the
	   rules of section 6.6, based on the authentication type in use
	   (bfd.AuthType.)  This may cause the packet to be discarded. */
	if (cpkt->auth){
		if (IS_DEBUG_CTRL_PACKET){
			blog_info("Packet has Authentication");
		}
		/* FIXME authentication process */
	}

	/* Set bfd.RemoteDiscr to the value of My Discriminator. */
	bfd->cpkt.your_disc = cpkt->my_disc;

	/* If the Required Min Echo RX Interval field is zero, the
	   transmission of Echo packets, if any, MUST cease. */
	/* FIXME */

	/* If Demand mode is active, a Poll Sequence is being transmitted by
	   the local system, and the Final (F) bit in the received packet is
	   set, the Poll Sequence MUST be terminated. */
	/* FIXME */

	/* If Demand mode is not active, the Final (F) bit in the received
	   packet is set, and the local system has been transmitting packets
	   with the Poll (P) bit set, the Poll (P) bit MUST be set to zero in
	   subsequent transmitted packets. */
	/* permit session from loopback interface */
	if (!bfd->cpkt.demand && cpkt->final
		&& (bfd->cpkt.poll || (ifindex == 1))){
		bfd->cpkt.poll = 0;
		poll_seq_end = 1;
		if (IS_DEBUG_CTRL_PACKET)
			blog_info("BFD Poll Sequence is done.");

		bfd->act_tx_intv = 
			ntohl(bfd->cpkt.des_min_tx_intv) < ntohl(cpkt->req_min_rx_intv) ?
			ntohl(cpkt->req_min_rx_intv) : ntohl(bfd->cpkt.des_min_tx_intv);
		bfd->act_rx_intv = ntohl(bfd->cpkt.req_min_rx_intv);
	}

	/* Update the Detection Time as described in section 6.7.4. */
	bfd->detect_time = cpkt->detect_mult *
		(bfd->act_rx_intv > ntohl(cpkt->des_min_tx_intv) ?
		 bfd->act_rx_intv : ntohl(cpkt->des_min_tx_intv));

	/* Update the transmit interval as described in section 6.7.2. */
	if (poll_seq_end){
		bfd_reset_tx_timer(bfd);
	}
	bfd->last_rcv_req_rx = cpkt->req_min_rx_intv;

	/* If bfd.SessionState is AdminDown */
	if (bfd->cpkt.state == BSM_AdminDown){
		if (IS_DEBUG_CTRL_PACKET)
			blog_info("BFD State is AdminDown. Discarded");
		return -1;
	}


	/* If received state is AdminDown
	    If bfd.SessionState is not Down
         Set bfd.LocalDiag to 3 (Neighbor signaled session down)
         Set bfd.SessionState to Down */
	if (cpkt->state == BSM_AdminDown){
		if (bfd->cpkt.state != BSM_Down){
			bfd->cpkt.diag = BFD_DIAG_NBR_SESSION_DOWN;
		}
	}

	if (cpkt->state == BSM_Down){
		bfd_bsm_event(bfd, BSM_Recived_Down);
	}
	else if (cpkt->state == BSM_Init){
		bfd_bsm_event(bfd, BSM_Recived_Init);
	}
	else if (cpkt->state == BSM_Up){
		bfd_bsm_event(bfd, BSM_Recived_Up);
	}

	/* If the Demand (D) bit is set and bfd.DemandModeDesired is 1,
	   and bfd.SessionState is Up, Demand mode is active. */
	if (cpkt->demand &&	bfd->cpkt.demand &&
		bfd->cpkt.state == BSM_Up){
		bfd->demand = 1;
	}
	/* If the Demand (D) bit is clear or bfd.DemandModeDesired is 0,
	   or bfd.SessionState is not Up, Demand mode is not
	   active. */
	else{
		bfd->demand = 0;
	}

	/* If the Poll (P) bit is set, send a BFD Control packet to the
	   remote system with the Poll (P) bit clear, and the Final (F) bit
	   set. */
	if (cpkt->poll){
		/* Store old p-bit */
		u_char old_poll_bit = bfd->cpkt.poll;

		if (IS_DEBUG_CTRL_PACKET)
			blog_info("BFD: Poll Sequence inprogress");

		bfd->cpkt.poll = 0;
		bfd->cpkt.final = 1;
		bfd_start_xmit_timer(bfd);
		bfd_send_ctrl_packet(bfd);
		bfd->cpkt.poll = old_poll_bit;
	}

	/* If the packet was not discarded, it has been received for purposes
	   of the Detection Time expiration rules in section 6.7.4. */
	if (IS_DEBUG_CTRL_PACKET)
		blog_info("BFD: Detect Time is %d(usec)", bfd->detect_time);

	if (bfd->cpkt.state == BSM_Up ||
		bfd->cpkt.state == BSM_Init){
		bfd_reset_expire_timer(bfd);
	}

	return 0;
}



