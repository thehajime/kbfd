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

#include "kbfd_queue.h"
#include "kbfd_session.h"
#include "kbfd.h"
#include "kbfd_interface.h"
#include "kbfd_v4v6.h"
#include "kbfd_log.h"
#include "kbfd_lock.h"
#include "kbfd_memory.h"
#include "kbfd_ioctl.h"

/* minor devices */
static struct kbfd_softc kbfd_scs[MAXKBFDDEVS];
/* module reference counter */
int kbfd_refcnt = 0;

/* FIXME */
extern struct bfd_proto v4v6_proto;

static int
bfd_peer_fill_info(void *data, struct bfd_session *bfd)
{
	struct bfd_nl_peerinfo *peer;

	peer = data;
	if(!peer)
		goto failure;

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

	return sizeof(struct bfd_nl_peerinfo);

failure:
	blog_info("ioctl_failure");
	return -1;
}

static int
bfd_peer_dump(void *data, struct bfd_nl_peerinfo *peer)
{
	struct bfd_session *bfd;
	int i = 0;
	int len = 0;
	int ret;

	/* Query by Peer Address */
	if (peer && peer->dst.sa.sa_family){
		bfd = bfd_session_lookup(&v4v6_proto, 0, &peer->dst.sa, 0);
		if (!bfd){
			return -1;
		}
		if ((ret = bfd_peer_fill_info(data, bfd)) <= 0){
			return -1;
		}
		len += ret;
		data = (char *)data + ret;
	}
	/* Then All Info dump */
	else{
		for (i = 0; i<BFD_SESSION_HASH_SIZE; i++){
			bfd = v4v6_proto.nbr_tbl[i];
			while (bfd){
				if ((ret = bfd_peer_fill_info(data, bfd)) <= 0){
					return -1;
				}
				len += ret;
				data = (char *)data + ret;
				bfd = bfd->nbr_next;
			}
		}
	}

	return len;
}

/* Notify function */
void
bfd_user_notify(struct bfd_session *bfd)
{
	unsigned int size;
	struct bfd_nl_peerinfo *peer;
	int i;

	size = sizeof(struct bfd_nl_peerinfo);

	for(i = 0; i < MAXKBFDDEVS; i++){
		if(kbfd_scs[i].sc_refcnt <= 0)
			continue;

		peer = bfd_malloc(size);
		if (!peer) {
			blog_err("alloc() failed.");
			return;
		}

		memcpy(&peer->dst.sa, bfd->dst, bfd->proto->namelen(bfd->dst));
		peer->ifindex = bfd->bif->ifindex;
		peer->state = bfd->cpkt.state;

		bfd_lock(&kbfd_scs[i].sendq_lock);
		SIMPLEQ_INSERT_TAIL(&kbfd_scs[i].kbfd_sendq, peer, sendq);
		bfd_unlock(&kbfd_scs[i].sendq_lock);

		selnotify(&kbfd_scs[i].r_sel, 0);
	}

	if(IS_DEBUG_UIO)
		blog_debug("%s return", __func__);

	return;
}


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

	/* init queue */
	SIMPLEQ_INIT(&kbfdsc->kbfd_sendq);
	selinit(&kbfdsc->r_sel);

	return (0);
}

int
bfd_close(dev_t dev, int flag, int mode, struct lwp *p)
{
	struct kbfd_softc *kbfdsc = (kbfd_scs + minor(dev));

	seldestroy(&kbfdsc->r_sel);

	/* decrease device reference counter */
	kbfdsc->sc_refcnt--;

	/* decrease module reference counter */
	kbfd_refcnt--;

	return 0;
}

int
bfd_read(dev_t dev, struct uio *uio, int flag)
{
	struct kbfd_softc *kbfdsc = (kbfd_scs + minor(dev));
	struct bfd_nl_peerinfo *peer;
	char buf[256];

	if(IS_DEBUG_UIO)
		blog_debug("%s: call", __func__);

	bfd_lock(&kbfdsc->sendq_lock);
	peer = SIMPLEQ_FIRST(&kbfdsc->kbfd_sendq);
	if (!peer) {
		bfd_unlock(&kbfdsc->sendq_lock);
		return ENOENT;
	}
	SIMPLEQ_REMOVE_HEAD(&kbfdsc->kbfd_sendq, sendq);
	bfd_unlock(&kbfdsc->sendq_lock);

	if (uio->uio_resid < sizeof(struct bfd_nl_peerinfo)){
		blog_debug("size less %d", uio->uio_resid);
		return EINVAL;
	}

	while (uio->uio_resid >= sizeof(struct bfd_nl_peerinfo)) {
		int error;

		if(IS_DEBUG_UIO)
			blog_debug("%s: peer %s status %d", __func__,
			    v4v6_proto.addr_print(&peer->dst.sa, buf),
			    peer->state);

		/* copy to user space */
		if ((error = uiomove(peer, sizeof(*peer), uio))) {
			return error;
		}
	}

	bfd_free(peer);
	return 0;
}

int
bfd_ioctl(dev_t dev, u_long cmd, void *addr, int flags, struct lwp *l)
{
	int err = 0;
	struct bfd_nl_peerinfo *peer;
	struct bfd_nl_linkinfo *link;

	switch (cmd){
	case BFD_NEWPEER:
		peer = (struct bfd_nl_peerinfo *)addr;
		err = bfd_session_add(&v4v6_proto, &peer->dst.sa, peer->ifindex);
		break;
	case BFD_DELPEER:
		peer = (struct bfd_nl_peerinfo *)addr;
		err = bfd_session_delete(&v4v6_proto, &peer->dst.sa, peer->ifindex);
		break;
	case BFD_GETPEER_NUM:
		*(u_int32_t *)addr = v4v6_proto.nbr_num;
		break;
	case BFD_GETPEER:
		peer = (struct bfd_nl_peerinfo *)addr;
		err = bfd_peer_dump(addr, peer);
		if(err < 0){
			blog_warn("ioctl err %d", err);
		}
		else
			err = 0;
		break;
	case BFD_ADMINDOWN:
		break;
	case BFD_SETLINK:
		link = (struct bfd_nl_linkinfo *)addr;

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
		debug_flag = *(u_int32_t *)addr;
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


int
bfd_poll(dev_t dev, int events, struct lwp *l)
{
	struct kbfd_softc *kbfdsc = (kbfd_scs + minor(dev));
	int revents = 0;

	if(IS_DEBUG_UIO)
		blog_debug("bfd_poll");

	if (events & (POLLIN | POLLRDNORM)) {
		if (!SIMPLEQ_EMPTY(&kbfdsc->kbfd_sendq)) {
			if(IS_DEBUG_UIO)
				blog_debug("%s: can read", __func__);
			revents |= events & (POLLIN | POLLRDNORM);
		} 
		else {
			if(IS_DEBUG_UIO)
				blog_debug("%s: no data. waiting", __func__);
			selrecord(l, &kbfdsc->r_sel);
		}
	}

	if (events & (POLLOUT | POLLWRNORM))
		revents |= events & (POLLOUT | POLLWRNORM);

	return (revents);
}

int
bfd_uio_init(void)
{
	memset(kbfd_scs, 0, sizeof(kbfd_scs));
	return 0;
}

void
bfd_uio_finish(void)
{
	return;
}

