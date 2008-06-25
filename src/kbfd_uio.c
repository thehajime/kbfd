/* 
 *  BFD User-land interface for NetBSD
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
 * Copyright (C) Hajime TAZAKI, 2008
 */

#include "kbfd_sys.h"

#include "kbfd_uio.h"
#include "kbfd_netlink.h"
#include "kbfd_queue.h"
#include "kbfd_session.h"
#include "kbfd_v4v6.h"
#include "kbfd_log.h"

/* minor devices */
static struct kbfd_softc kbfd_scs[MAXKBFDDEVS];
/* module reference counter */
static int kbfd_refcnt = 0;

/* FIXME */
extern struct bfd_proto v4v6_proto;

int
bfd_open(dev_t dev, int flag, int mode, struct lwp *p)
{
	struct kbfd_softc *kbfdsc = (kbfd_scs + minor(dev));

	if(minor(dev) >= MAXKBFDDEVS)
		return (ENODEV);

	/* check if device already open */
	if(kbfdsc->sc_refcnt > 0)
		return (EBUSY);

	/* increase device reference counter */
	kbfdsc->sc_refcnt++;

	/* increase module reference counter */
	kbfd_refcnt++;

	return (0);
}

int
bfd_close(dev_t dev, int flag, int mode, struct lwp *p)
{
	struct kbfd_softc *kbfdsc = (kbfd_scs + minor(dev));

	/* decrease device reference counter */
	kbfdsc->sc_refcnt--;

	/* decrease module reference counter */
	kbfd_refcnt--;

	return 0;
}


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

int
bfd_read(dev_t dev, struct uio *uio, int flag)
{
#if 0
	struct kbfd_softc *kbfdsc = (kbfd_scs + minor(dev));
	if (uio->uio_resid < sizeof(u_int32_t))
		return (EINVAL);

	while (uio->uio_resid >= sizeof(u_int32_t)) {
		int error;

		/* copy to user space */
		if ((error = uiomove(&(fibosc->sc_current),
		    sizeof(fibosc->sc_current), uio))) {
			return (error);
		}

		/* prevent overflow */
		if (fibosc->sc_current > (MAXFIBONUM - 1)) {
			fibosc->sc_current = 1;
			fibosc->sc_previous = 0;
			continue;
		}

		/* calculate */ {
			u_int32_t tmp;

			tmp = fibosc->sc_current;
			fibosc->sc_current += fibosc->sc_previous;
			fibosc->sc_previous = tmp;
		}
	}
#endif
	return 0;
}

int
bfd_ioctl(dev_t dev, u_long cmd, void *addr, int flags, struct lwp *l)
{
	int err = 0;
	struct bfd_nl_peerinfo peer;

	switch (cmd){
	case BFD_NEWPEER:
		peer = *(struct bfd_nl_peerinfo *)addr;
		err = bfd_session_add(&v4v6_proto, &peer.dst.sa, peer.ifindex);
		break;
	case BFD_DELPEER:
		peer = *(struct bfd_nl_peerinfo *)addr;
		err = bfd_session_delete(&v4v6_proto, &peer.dst.sa, peer.ifindex);
		break;
	case BFD_GETPEER:
			struct ifreq *ifr = (struct ifreq *)data;
			struct ifnet *ifp = &sc->sc_ec.ec_if;

			strlcpy(ifr->ifr_name, ifp->if_xname, IFNAMSIZ);

		err =  netlink_dump_start(bfd_nls, skb, nlh,
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
