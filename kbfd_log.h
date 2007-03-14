/* 
 *  BFD Logging Management
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


#ifndef __BFD_lOG_H_
#define __BFD_lOG_H_

extern void blog(const char *, ...);

#define IS_DEBUG_BSM           0
#define IS_DEBUG_CTRL_PACKET   0
#define IS_DEBUG_NETLINK       0

#define blog_debug(format, args...) \
	printk(KERN_DEBUG "BFD(%lu): " format "\n", jiffies, ##args);

#define blog_info(format, args...) \
	printk(KERN_INFO "BFD(%lu): " format "\n", jiffies, ##args);

#define blog_notice(format, args...) \
	printk(KERN_NOTICE "BFD(%lu): " format "\n", jiffies, ##args);

#define blog_warn(format, args...) \
	printk(KERN_WARNING "BFD(%lu): " format "\n", jiffies, ##args);

#define blog_err(format, args...) \
	printk(KERN_ERR "BFD(%lu): " format "\n", jiffies, ##args);

#endif /* __BFD_LOG_H_ */
