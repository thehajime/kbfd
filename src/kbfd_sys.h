/* 
 * BFD System Headers.
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

#ifndef __BFD_SYS_H__
#define __BFD_SYS_H__

#if defined linux
#include <linux/module.h>
#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/workqueue.h>
#include <linux/socket.h>
#include <linux/random.h>
#include <linux/netdevice.h>
#include <linux/rcupdate.h>
#include <linux/ipv6.h>
#include <linux/netfilter.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/route.h>
#include <net/ipv6.h>
#include <net/addrconf.h>
#include <net/flow.h>
#include <net/ip6_route.h>
#include <stdarg.h>

#elif defined __NetBSD__
#include <sys/param.h>
#include <sys/conf.h>
#include <sys/device.h>
#include <sys/filedesc.h>
#include <sys/file.h>
#include <sys/filio.h>
#include <sys/select.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/exec.h>
#include <sys/lkm.h>
#include <sys/socket.h>
#include <sys/endian.h>
#include <sys/workqueue.h>
#include <sys/socketvar.h>
#include <sys/mbuf.h>
#include <sys/kthread.h>
#include <sys/simplelock.h>
#include <sys/timex.h>
#include <sys/rnd.h>
#include <sys/callout.h>
#include <sys/protosw.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/ip6_var.h>
#include <machine/stdarg.h>

#include "kbfd_uio.h"

/* FIXME */
#define __LITTLE_ENDIAN_BITFIELD

#define printk printf
#define jiffies (long unsigned int)hardclock_ticks

#define KERN_DEBUG   "DEBG "
#define KERN_INFO    "INFO "
#define KERN_NOTICE  "NOTI "
#define KERN_WARNING "WARN "
#define KERN_ERR     "ERR  "

#define NSEC_PER_SEC NANOSECOND
#endif /* __NetBSD__ */

#endif /* __BFD_SYS_H__ */
