/* 
 *  BFD Main routine
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

#include "kbfd_sys.h"

#include "kbfd_packet.h"
#include "kbfd_queue.h"
#include "kbfd_session.h"
#include "kbfd.h"
#include "kbfd_v4v6.h"
#include "kbfd_log.h"
#include "kbfd_lock.h"
#include "kbfd_memory.h"
#include "kbfd_var.h"
#include "kbfd_ioctl.h"

struct bfd_master *master = NULL;
static
#if defined __linux__
int __init
#elif defined __NetBSD__
void
#endif /* linux */
bfd_init(void){
	master = bfd_malloc(sizeof(struct bfd_master));
	if (!master){
		blog_err("malloc error");
#if defined linux
		return ENOMEM;
#elif defined __NetBSD__
		return;
#endif
	}

	memset(master, 0, sizeof(struct bfd_master));

	bfd_uio_init();
	bfd_v4v6_init();
	bfd_session_init();

	blog_info("BFD: kbfd %s start. clock hz=%d", 
	    KBFD_VERSION, HZ);
#if defined linux
	return ENOMEM;
#elif defined __NetBSD__
	return;
#endif
}

static void
#ifdef linux
__exit
#endif /* linux */
bfd_exit(void)
{
	bfd_session_finish();
	bfd_v4v6_finish();
	bfd_uio_finish();

	if (master)
		bfd_free(master);

	blog_info("BFD: kbfd stop");
	return;
}

#ifdef linux
module_init(bfd_init);
module_exit(bfd_exit);
MODULE_LICENSE("GPL");
#endif /* linux */

#ifdef __NetBSD__
int kbfd_lkmentry(struct lkm_table *, int, int);

/* device struct */
static struct cdevsw kbfd_dev = {
	bfd_open, 
	bfd_close,
	bfd_read,
	(dev_type_write((*))) enodev,
	bfd_ioctl,
	(dev_type_stop((*))) enodev, 
	(dev_type_tty((*))) enodev,
	bfd_poll,
	(dev_type_mmap((*))) enodev,
	nokqfilter, 0
};

extern int kbfd_refcnt;
MOD_DEV("kbfd", "kbfd", NULL, -1, &kbfd_dev, -1);

static int
bfd_handle(struct lkm_table *lkmtp, int cmd)
{
	switch (cmd) {
	case LKM_E_LOAD:
		if (lkmexists(lkmtp))
			return (EEXIST);

		bfd_init();
		break;
	case LKM_E_UNLOAD:
		if (kbfd_refcnt > 0)
			return (EBUSY);
		bfd_exit();
		break;
	case LKM_E_STAT:
		break;
	default:
		return (EIO);
		break;
	}

	return (0);
}

int
kbfd_lkmentry(struct lkm_table *lkmtp, int cmd, int ver)
{
	DISPATCH(lkmtp, cmd, ver, bfd_handle, bfd_handle, bfd_handle);
}

#endif  /* __NetBSD__ */
