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

#include <linux/module.h>
#include <linux/init.h>
#include <linux/in.h>
#include <linux/inet.h>

#include "kbfd_packet.h"
#include "kbfd_session.h"
#include "kbfd_netlink.h"
#include "kbfd_v4v6.h"
#include "kbfd_log.h"
#include "kbfd.h"

struct bfd_master *master = NULL;

static int __init
bfd_init(void)
{
	master = kmalloc(sizeof(struct bfd_master), GFP_KERNEL);
	if (!master){
		blog_err("kmalloc error");
		return -1;
	}

	memset(master, 0, sizeof(struct bfd_master));

	bfd_netlink_init();
	bfd_v4v6_init();
	bfd_session_init();

	blog_info("BFD: kbfd start");
	return 0;
}

static void __exit
bfd_exit(void)
{
	bfd_session_finish();
	bfd_v4v6_finish();
	bfd_netlink_finish();

	if (master)
		kfree(master);

	blog_info("BFD: kbfd stop");
}

module_init(bfd_init);
module_exit(bfd_exit);
MODULE_LICENSE("GPL");

