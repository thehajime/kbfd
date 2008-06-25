/* 
 *  BFD User-land interface for NetBSD
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

#ifndef __BFD_UIO_H__
#define __BFD_UIO_H__

struct kbfd_softc{
	int sc_refcnt;
};

/* up to 8 minor devices */
#define MAXKBFDDEVS     8

int bfd_open(dev_t, int, int, struct lwp *);
int bfd_close(dev_t, int, int, struct lwp *);
int bfd_read(dev_t, struct uio *, int);
int bfd_ioctl(dev_t, u_long, void *, int, struct lwp *);

#endif /* __BFD_UIO_H__ */
