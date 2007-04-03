/* 
 * BFD Packets.
 *
 * base from draft-ietf-bfd-base-05.txt
 *           draft-ietf-bfd-mib-03.txt
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

#ifndef _BFD_PACKET_H
#define _BFD_PACKET_H

#include <linux/workqueue.h>
#include <net/sock.h>

#include "kbfd.h"

/* Versions */
#define    BFD_VERSION_0    0
#define    BFD_VERSION_1    1

#define    BFD_CTRL_LEN          24
#define    BFD_CTRL_AUTH_LEN     26

/*    Diagnostic (Diag)
 *
 *      A diagnostic code specifying the local system's reason for the
 *      last session state change.  Values are:
 */

/*   
 *   0 -- No Diagnostic 
 *   1 -- Control Detection Time Expired
 *   2 -- Echo Function Failed
 *   3 -- Neighbor Signaled Session Down
 *   4 -- Forwarding Plane Reset
 *   5 -- Path Down
 *   6 -- Concatenated Path Down
 *   7 -- Administratively Down
 *   8 -- Reverse Concatenated Path Down
 *   9-31 -- Reserved for future use
 */

#define    BFD_DIAG_NO_DIAG                     0
#define    BFD_DIAG_CTRL_TIME_EXPIRED           1
#define    BFD_DIAG_ECHO_FAILED                 2
#define    BFD_DIAG_NBR_SESSION_DOWN            3
#define    BFD_DIAG_FWD_PLANE_RST               4
#define    BFD_DIAG_PATH_DOWN                   5
#define    BFD_DIAG_CONCATENATED_PATH_DOWN      6
#define    BFD_DIAG_ADMIN_DOWN                  7
#define    BFD_DIAG_REV_CONCATENATED_PATH_DOWN  8

/* 
 * BFD Authentication Type
 *
 *        0 - Reserved
 *        1 - Simple Password
 *        2 - Keyed MD5
 *        3 - Meticulous Keyed MD5
 *        4 - Keyed SHA1
 *        5 - Meticulous Keyed SHA1
 *        6-255 - Reserved for future use
 */
#define    BGF_AUTH_RESERVED                  0
#define    BGF_AUTH_SIMPLE_PASSWD             1
#define    BGF_AUTH_KEYED_MD5                 2
#define    BGF_AUTH_METICULOUS_MD5            3
#define    BGF_AUTH_KEYED_SHA1                4
#define    BGF_AUTH_METICULOUS_SHA1           5

/* 
   The Mandatory Section of a BFD Control packet has the following
   format:

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Vers |  Diag   |Sta|P|F|C|A|D|R|  Detect Mult  |    Length     |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       My Discriminator                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Your Discriminator                       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Desired Min TX Interval                    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                   Required Min RX Interval                    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                 Required Min Echo RX Interval                 |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 */
struct bfd_ctrl_packet
{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u_char diag:5;
	u_char version:3;

	/* flags */
	u_char rsrv:1;
	u_char demand:1;
	u_char auth:1;
	u_char cplane:1;
	u_char final:1;
	u_char poll:1;
	u_char state:2;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u_char version:3;
	u_char diag:5;

	/* flags */
	u_char state:2;
	u_char poll:1;
	u_char final:1;
	u_char cplane:1;
	u_char auth:1;
	u_char demand:1;
	u_char rsrv:1;
#else
#error "Adjust your <asm/byteorder.h> defines"
#endif

	u_char detect_mult;
	u_char length;

	u_int32_t my_disc;
	u_int32_t your_disc;
	u_int32_t des_min_tx_intv;
	u_int32_t req_min_rx_intv;
	u_int32_t req_min_echo_rx_intv;

};

struct bfd_auth_packet
{
	u_char auth_type;
	u_char auth_len;
	u_int16_t auth_data; 
};

struct bfd_session;

int bfd_sock_init(void);
int bfd_sock_exit(void);
int bfd_send_ctrl_packet(struct bfd_session *);
int bfd_recv_ctrl_packet(struct bfd_proto *, struct sockaddr *, 
						 struct sockaddr *, int, char *, int);

#endif /* _BFD_PACKET_H */
