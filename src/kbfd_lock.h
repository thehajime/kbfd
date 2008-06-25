/* 
 *  BFD exclusive Management
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

#ifndef __BFD_LOCK_H__
#define __BFD_LOCK_H__

#ifdef linux
typedef spinlock_t bfd_lock_t;
#define DEFINE_LOCK(X)  DEFINE_SPINLOCK((X))
#elif __NetBSD__
typedef struct simplelock bfd_lock_t;
#define DEFINE_LOCK(X)							\
	bfd_lock_t (X) = SIMPLELOCK_INITIALIZER;
#endif	/* __NetBSD__ */

#ifdef __NetBSD__
#define rcu_read_lock() ;
#define rcu_read_unlock() ;
#define synchronize_rcu() ;
#endif	/* __NetBSD__ */

void bfd_lock(bfd_lock_t *);
void bfd_unlock(bfd_lock_t *);


#endif	/* __BFD_LOCK_H__ */
