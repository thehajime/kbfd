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

#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/in.h>

#include "kbfd_packet.h"
#include "kbfd_session.h"
#include "kbfd_netlink.h"
#include "kbfd_interface.h"
#include "kbfd_log.h"
#include "kbfd.h"

static struct sock *bfd_nls = NULL;
static unsigned long bfd_nl_seq = 0;

/* FIXME */
extern struct bfd_proto v4v6_proto;

static int
bfd_peer_fill_info(struct sk_buff *skb, struct bfd_session *bfd,
				   u32 pid, u32 seq, int event, unsigned int flags)
{
	struct bfd_nl_peerinfo *peer;
	struct nlmsghdr *nlh;
	u_char *b = skb->tail;

	nlh = NLMSG_NEW(skb, pid, seq, event, sizeof(*peer), flags);
	peer = NLMSG_DATA(nlh);

	memset(peer, 0, sizeof(struct bfd_nl_peerinfo));
	peer->is1hop = 1;
	peer->state = bfd->cpkt.state;
	memcpy(&peer->dst, bfd->dst, bfd->proto->namelen(bfd->dst));
	memcpy(&peer->src, bfd->src, bfd->proto->namelen(bfd->src));
	peer->ifindex = bfd->bif->ifindex;
	peer->my_disc = bfd->cpkt.my_disc;
	peer->your_disc = bfd->cpkt.your_disc;

    /* counter */
	peer->pkt_in = bfd->pkt_in;
	peer->pkt_out = bfd->pkt_out;
	peer->last_up = bfd->last_up;
	peer->last_down = bfd->last_down;
	peer->up_cnt = bfd->up_cnt;
	peer->last_discont = bfd->last_discont;

	nlh->nlmsg_len = skb->tail - b;
	return skb->len;

nlmsg_failure:
blog_info("nlmsg_failure");
	skb_trim(skb, b - skb->data);
	return -1;
}

static int
bfd_peer_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct bfd_session *bfd;
	struct bfd_nl_peerinfo *peer = NLMSG_DATA(cb->nlh);
	int i = 0;
	int s_idx = cb->args[0];

	/* Query by Peer Address */
	if (peer->dst.sa.sa_family){
		bfd = bfd_session_lookup(&v4v6_proto, 0, &peer->dst.sa, 0);
		if (!bfd){
			return skb->len;
		}
		if (bfd_peer_fill_info(skb, bfd, NETLINK_CB(cb->skb).pid,
							   cb->nlh->nlmsg_seq, BFD_NEWPEER, 0) <= 0){
			return skb->len;
		}
	}
	/* Then All Info dump */
	else{
		for (i = 0; i<BFD_SESSION_HASH_SIZE; i++){
			if (i < s_idx)
				continue;
			bfd = v4v6_proto.nbr_tbl[i];
			while (bfd){
				if (bfd_peer_fill_info(skb, bfd, NETLINK_CB(cb->skb).pid,
									   cb->nlh->nlmsg_seq,
									   BFD_NEWPEER, NLM_F_MULTI) <= 0){
					s_idx = i;
					return skb->len;
				}

				bfd = bfd->nbr_next;
			}
		}
	}

	cb->args[0] = i;
	return skb->len;
}


#if 0
static int test_done(struct netlink_callback *cb)
{
	blog_info("entered %s", __FUNCTION__);
	return 0;
}
#endif

static int
bfd_nl_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	struct bfd_nl_peerinfo *peer;
	struct bfd_nl_linkinfo *link;
	int err = 0;

	if (IS_DEBUG_NETLINK){
		blog_debug("bfd_nl_rcv: type=%d, len=%d, ack=%d",
				   nlh->nlmsg_type,
				   nlh->nlmsg_len,
				   nlh->nlmsg_flags & NLM_F_ACK);
	}

	if (!(nlh->nlmsg_flags&NLM_F_REQUEST))
		return 0;

	switch (nlh->nlmsg_type){
	case BFD_NEWPEER:
		peer = NLMSG_DATA(nlh);

		if (peer)
			err = bfd_session_add(&v4v6_proto, &peer->dst.sa, peer->ifindex);
		else
			err = EINVAL;
		break;
	case BFD_DELPEER:
		peer = NLMSG_DATA(nlh);

		if (peer)
			err = bfd_session_delete(&v4v6_proto, &peer->dst.sa, peer->ifindex);
		else
			err = EINVAL;
		break;
	case BFD_GETPEER:
		if (!nlh->nlmsg_flags&NLM_F_DUMP) {
			err =  EINVAL;
			break;
		}
		return netlink_dump_start(bfd_nls, skb, nlh,
								  bfd_peer_dump, NULL);
		break;
	case BFD_ADMINDOWN:
		break;
	case BFD_SETLINK:
		link = NLMSG_DATA(nlh);

		if (link){
			struct bfd_interface *bif = bfd_interface_get(link->ifindex);
			if (bif){
                blog_debug("BFD_SETLINK: if=%s mintx=%d, minrx=%d, mult=%d",
                           bif->name,
                           link->mintx,
                           link->minrx,
                           link->mult);
				bif->v_mintx = link->mintx;
				bif->v_minrx = link->minrx;
				bif->v_mult = link->mult;
				bfd_interface_change_timer(bif);
			}
			else
				err = ENOMEM;
		}
		else
			err = EINVAL;
		break;
	case BFD_SETFLAG:
		break;
	case BFD_CLEAR_COUNTER:
		break;
	case BFD_CLEAR_SESSION:
		break;
	default:
		err = EINVAL;
		break;
	}
	return err;
}

static inline void
bfd_nl_rcv_skb(struct sk_buff *skb)
{
	if (skb->len >= NLMSG_SPACE(0)) {
		int err;
		struct nlmsghdr *nlh = (struct nlmsghdr *)skb->data;

		if (nlh->nlmsg_len < sizeof(*nlh) ||
		    skb->len < nlh->nlmsg_len)
			return;

		/* parse client message */
		err = bfd_nl_rcv_msg(skb, nlh);

		if (err || nlh->nlmsg_flags & NLM_F_ACK){
			if (IS_DEBUG_NETLINK)
				blog_debug("bfd_nl: send ack");
			netlink_ack(skb, nlh, err);
		}
	}
	return;
}

/* Recieve Handler */
static void 
bfd_nl_rcv(struct sock *sk, int len)
{
	struct sk_buff *skb;
	unsigned int qlen = skb_queue_len(&sk->sk_receive_queue);

	while (qlen-- && (skb = skb_dequeue(&sk->sk_receive_queue))) {
		bfd_nl_rcv_skb(skb);
		kfree_skb(skb);
	}
	return;
}

/* Notify function */
void
bfd_nl_send(struct bfd_session *bfd)
{
	unsigned int size;
	struct sk_buff *skb;
	struct bfd_nl_peerinfo *data;
	struct nlmsghdr *nlh;

	if (!bfd_nls)
		return;

	size = NLMSG_SPACE(sizeof(struct bfd_nl_peerinfo));

	skb = alloc_skb(size, GFP_ATOMIC);
	if (!skb) {
		blog_err("skb_alloc() failed.");
		return;
	}

	nlh = NLMSG_PUT(skb, 0, bfd_nl_seq++, NLMSG_DONE, size - sizeof(*nlh));
	nlh->nlmsg_type = BFD_NEWPEER;

	data = (struct bfd_nl_peerinfo *)NLMSG_DATA(nlh);

	memcpy(&data->dst.sa, bfd->dst, bfd->proto->namelen(bfd->dst));
	data->ifindex = bfd->bif->ifindex;
	data->state = bfd->cpkt.state;

	NETLINK_CB(skb).dst_group = 1;
	netlink_broadcast(bfd_nls, skb, 0, 1, GFP_ATOMIC);

nlmsg_failure:
	return;
}


int
bfd_netlink_init(void)
{
	bfd_nls = netlink_kernel_create(NETLINK_BFD, 1, bfd_nl_rcv, THIS_MODULE);
	if (!bfd_nls) {
		blog_err("Failed to create new netlink socket(%u) for bfd",
				 NETLINK_BFD);
	}
	return 0;
}

void
bfd_netlink_finish(void)
{
	if (bfd_nls && bfd_nls->sk_socket)
		sock_release(bfd_nls->sk_socket);
	return;
}

