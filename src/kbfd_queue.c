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
#include "kbfd_memory.h"
#include "kbfd_queue.h"
#include "kbfd_session.h"
#include "kbfd.h"
#include "kbfd_log.h"

#ifdef __NetBSD__
static void
bfd_worker(struct work *wk, void *arg)
{
	struct bfd_work *bwk = (void *)wk;

	if(IS_DEBUG_DEBUG)
		blog_debug("%s: %p", __func__, bwk);

	(*bwk->func)(bwk->arg);

	return;
}

static void
callout_fire(void *arg)
{
	struct bfd_work *bwk = arg;

	if(IS_DEBUG_DEBUG)
		blog_debug("%s: %p", __func__, bwk);

	workqueue_enqueue(bwk->wkq, &bwk->u.wk, NULL);
	return;

}
#endif	/* __NetBSD__ */


int
bfd_workqueue_add(struct bfd_workqueue *wkq, struct bfd_work *wk,
    uint32_t usec, int jitter)
{
#ifdef linux
	queue_delayed_work(wkq->wkq, &wk->wk,
	    usecs_to_jiffies(usec) * jitter / 100 );
#elif defined __NetBSD__
	u_int32_t timeout = ((hz*usec)/1000000) * jitter / 100;
	wk->wkq = wkq->wkq;
	if(IS_DEBUG_DEBUG){
		blog_info("wq add. usec=%d, jitter=%d, to=%d",
		    usec, jitter, timeout);
	}

	if(IS_DEBUG_DEBUG)
		blog_debug("%s: %p", __func__, wk);

	callout_setfunc(&wk->u.wk_ch, callout_fire, wk);
	callout_schedule(&wk->u.wk_ch, timeout);
#endif	/* __NetBSD__ */
	return 0;
}

int
bfd_workqueue_delete(struct bfd_workqueue *wkq, struct bfd_work *wk)
{
#ifdef linux
	if (wk->wk.pending)
		cancel_rearming_delayed_workqueue(wkq->wkq, &wk->wk);
#elif defined __NetBSD__
	if(IS_DEBUG_DEBUG)
		blog_debug("%s: %p", __func__, wk);
	callout_stop(&wk->u.wk_ch);
#endif	/* __NetBSD__ */
  return 0;
}

struct bfd_workqueue *
bfd_workqueue_init(const char *name)
{
	struct bfd_workqueue *queue;

	queue = bfd_malloc(sizeof(struct bfd_workqueue));
	if(!queue)
		return NULL;
	
#ifdef linux
	queue->wkq = create_singlethread_workqueue(name);
#elif defined __NetBSD__
	workqueue_create(&queue->wkq, name,
	    bfd_worker, NULL, PUSER - 1, IPL_SOFTCLOCK, 0);
	
#endif	/* __NetBSD__ */
	return queue;
}

int
bfd_workqueue_exit(struct bfd_workqueue *queue)
{
#ifdef linux
	destroy_workqueue(queue->wkq);
#elif defined __NetBSD__
	workqueue_destroy(queue->wkq);
#endif	/* __NetBSD__ */

	bfd_free(queue);
	return 0;
}

