/* 
 *  BFD for IPv4 and IPv6 (1-hop)
 *
 * base from draft-ietf-bfd-v4v6-1hop-05.txt
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

#include <linux/ipv6.h>

#define  BFD_CONTROL_PORT           3784
#define  BFD_ECHO_PORT              3785
#define  BFD_MULTI_CONTROL_PORT     4784
#define  BFD_SRC_CONTROL_PORT_BEGIN 49152
#define  BFD_SRC_CONTROL_PORT_END   65535

union ip_pktinfo_union
{
    struct in_pktinfo pkti;
    struct in6_pktinfo pkti6;
};

int bfd_v4v6_init(void);
int bfd_v4v6_finish(void);
