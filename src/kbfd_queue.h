/* 
 *  BFD Workqueue routine
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

#ifndef __BFD_QUEUE_H__
#define __BFD_QUEUE_H__

#if defined linux
#define BFD_INIT_WORK(W,F,A)						\
	INIT_WORK(&((W)->wk), (F), NULL);				\
	(W)->wk.data = (A);
#elif defined __NetBSD__
#define BFD_INIT_WORK(W,F,A)						\
	callout_init(&((W)->u.wk_ch), 0);				\
	callout_setfunc(&((W)->u.wk_ch), (F), (A));
#endif	/* __NetBSD__ */

struct bfd_workqueue
{
#if defined linux
	struct workqueue_struct *wkq;
#elif defined __NetBSD__
	struct workqueue *wkq;
#endif
};

struct bfd_work
{
#if defined linux
	struct work_struct wk;
#elif defined __NetBSD__
	union{
		struct work wk;
		struct callout wk_ch;
	}u;
	uint32_t timeout;
#endif
};


int bfd_workqueue_add(struct bfd_workqueue *, struct bfd_work *, uint32_t, int);
int bfd_workqueue_delete(struct bfd_workqueue *, struct bfd_work *);
struct bfd_workqueue *bfd_workqueue_init(const char *);
int bfd_workqueue_exit(struct bfd_workqueue *);

#endif /* __BFD_QUEUE_H__ */
