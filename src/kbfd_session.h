/* 
 * BFD Session Defintion.
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

#ifndef _BFD_SESSION_H
#define _BFD_SESSION_H

#include "kbfd_packet.h"

/* 
 * BFD State Event
 */
#define    BSM_Start                         0
#define    BSM_Recived_Down                  1
#define    BSM_Recived_Init                  2
#define    BSM_Recived_Up                    3
#define    BSM_Timer_Expired                 4
#define    BSM_Toggle_Admin_Down             5
#define    BFD_BSM_EVENT_MAX                 6

#define  HASH_KEY(X)                ((X) % BFD_SESSION_HASH_SIZE)

struct bfd_session
{
	struct bfd_session *session_next;
	struct bfd_session *nbr_next;
	struct sockaddr *dst;
	struct sockaddr *src;
	struct bfd_interface *bif;
	struct socket *tx_ctrl_sock;
	struct work_struct t_rx_expire;
	struct work_struct t_tx_work;
	struct bfd_proto *proto;

	/* control packet */
	struct bfd_ctrl_packet cpkt;
	u_int32_t auth_seq;
	u_int32_t xmit_auth_seq;
	u_int32_t auth_seq_known;	
	u_int32_t detect_time;
	u_int32_t act_tx_intv;
	u_int32_t act_rx_intv;
	u_int32_t last_rcv_req_rx;

	u_char demand;
	u_char async;

	/* For MIB Information(draft-ietf-bfd-mib-03.txt) */
	u_int64_t pkt_in;
	u_int64_t pkt_out;
	u_int32_t last_up;
	u_int32_t last_down;
	u_int32_t last_diag;
	u_int32_t up_cnt;
	u_int32_t last_discont;		/* FIXME(not implemented) */
};

int bfd_session_init (void);
int bfd_session_finish (void);
struct bfd_session *bfd_session_lookup(struct bfd_proto *, u_int32_t, struct sockaddr *, int);
int bfd_session_add(struct bfd_proto *, struct sockaddr *, int);
int bfd_session_delete(struct bfd_proto *, struct sockaddr *, int);
int bfd_bsm_event(struct bfd_session *, int);
void bfd_reset_tx_timer(struct bfd_session *);
void bfd_reset_expire_timer(struct bfd_session *);
void bfd_start_xmit_timer(struct bfd_session *);
void bfd_change_interval_time(struct bfd_session *, u_int32_t, u_int32_t);

#endif /* _BFD_SESSION_H */
