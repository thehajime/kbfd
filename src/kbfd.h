/* 
 * BFD Headers.
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


#ifndef __BFD_H_
#define __BFD_H_

#include <linux/kernel.h>
#include <linux/workqueue.h>

#define BFD_MIN_TX_INTERVAL_INIT   1000000 /* 1sec=1,000,000usec */
#define BFD_MIN_RX_INTERVAL_INIT   1000000 /* 1sec=1,000,000usec */
#define BFD_DETECT_MULT_DEFAULT          5

#define BFD_MIN_TX_INTERVAL_DEFAULT   100000 /* 100msec=100,000usec */
#define BFD_MIN_RX_INTERVAL_DEFAULT   100000 /* 100msec=100,000usec */

#define BFD_SESSION_HASH_SIZE      255

struct bfd_master
{
	struct bfd_session *session_tbl[BFD_SESSION_HASH_SIZE];
	spinlock_t ses_tbl_lock;
	struct workqueue_struct *tx_ctrl_wq;
	struct workqueue_struct *ctrl_expire_wq;
	u_int32_t discriminator;
};

struct bfd_proto
{
	struct bfd_session **nbr_tbl;
	spinlock_t nbr_tbl_lock;
	int (*create_ctrl_socket)(struct bfd_session *);
	u_int32_t (*hash)(struct sockaddr *);
	int (*cmp)(struct sockaddr *, struct sockaddr *);
	char *(*addr_print)(struct sockaddr *, char *);
	int (*namelen)(struct sockaddr *);
	int (*get_oif)(struct sockaddr *);
};


#endif /* __BFD_H_ */
