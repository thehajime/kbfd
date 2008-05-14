/* 
 *  BFD Interface Management
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

#include <linux/netdevice.h>

#include "kbfd_interface.h"
#include "kbfd_log.h"
#include "kbfd_session.h"
#include "kbfd.h"

static struct bfd_interface *biflist = NULL;
static DEFINE_SPINLOCK(bif_lock);
/* FIXME */
extern struct bfd_proto v4v6_proto;

inline static struct bfd_interface *
bfd_interface_new(int ifindex)
{
	struct bfd_interface *bif;

	bif = kmalloc(sizeof(struct bfd_interface), GFP_KERNEL);
	if (bif){
		struct net_device *dev;

		memset(bif, 0, sizeof(struct bfd_interface));
		bif->ifindex = ifindex;

		bif->v_mintx = BFD_MIN_TX_INTERVAL_DEFAULT;
		bif->v_minrx = BFD_MIN_RX_INTERVAL_DEFAULT;
		bif->v_mult = BFD_DETECT_MULT_DEFAULT;

		dev = dev_get_by_index(ifindex);
		if (dev){
			bif->name = dev->name;
		}
	}
	return bif;
}

struct bfd_interface *
bfd_interface_get(int ifindex)
{
	struct bfd_interface *bif = biflist;

	/* lookup same interface */
	rcu_read_lock();
	while (bif){
		if (bif->ifindex == ifindex)
			break;
		bif = bif->next;
	}
	rcu_read_unlock();

	/* found */
	if (bif)
		return bif;

	/* then alloc new interface */
	bif = bfd_interface_new(ifindex);
	if (!bif)
		return NULL;

	spin_lock(&bif_lock);
	bif->next = biflist;
	biflist = bif;
	spin_unlock(&bif_lock);

	return bif;
}

void
bfd_interface_free(struct bfd_interface *bif)
{
	synchronize_rcu();
	if (bif){
		kfree(bif);
	}
	return;
}

void
bfd_interface_change_timer(struct bfd_interface *bif)
{
	struct bfd_interface *tmpbif = biflist;
	struct bfd_session *bfd = NULL;
	int i;

	/* lookup same interface */
	rcu_read_lock();
	while (tmpbif){
		if (tmpbif == bif)
			break;
		tmpbif = tmpbif->next;
	}
	rcu_read_unlock();

	rcu_read_lock();
	for (i = 0; i<BFD_SESSION_HASH_SIZE; i++){
		bfd = v4v6_proto.nbr_tbl[i];
		while (bfd){
			if (bfd->bif == bif)
				bfd_change_interval_time(bfd, bif->v_mintx, bif->v_minrx);
			bfd = bfd->nbr_next;
		}
	}
	rcu_read_unlock();

	return;
}
