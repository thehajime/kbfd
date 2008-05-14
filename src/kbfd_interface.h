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

struct bfd_interface
{
	struct bfd_interface *next;
	int ifindex;
	char *name;

	u_int32_t v_mintx;
	u_int32_t v_minrx;
	u_int32_t v_mult;
};

struct bfd_interface *bfd_interface_get(int);
void bfd_interface_free(struct bfd_interface *);
void bfd_interface_change_timer(struct bfd_interface *);

