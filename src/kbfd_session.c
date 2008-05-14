/* 
 *  BFD Session Management
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

#include <net/sock.h>

#include <linux/config.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/random.h>
#include <linux/netdevice.h>
#include <linux/rcupdate.h>
#include <net/sock.h>

#include "kbfd_session.h"
#include "kbfd_packet.h"
#include "kbfd_netlink.h"
#include "kbfd_log.h"
#include "kbfd_interface.h"
#include "kbfd.h"


static struct proc_dir_entry *kbfd_root_dir = NULL;
static struct proc_dir_entry *session_proc = NULL;
extern struct bfd_master *master;
static DEFINE_SPINLOCK(tbl_lock);

char *bfd_state_string[] = {
	"AdminDown",
	"Down",
	"Init",
	"Up",		
};

char *bfd_event_string[] = {
	"Start",
	"Received_Down",
	"Received_Init",
	"Received_Up",
	"TimerExpired",
	"Toggle_AdminDown",
};

void bfd_start_xmit_timer(struct bfd_session *);
void bfd_xmit_timeout(void *);
int bfd_bsm_event(struct bfd_session *, int);
void bfd_detect_timeout(void *);
void bfd_stop_xmit_timer(struct bfd_session *);
void bfd_stop_expire_timer(struct bfd_session *);


static u32
get_sys_uptime(void)
{
	struct timespec ts;

	ktime_get_ts(&ts);

	return ((ts.tv_sec * 100L) +
			(ts.tv_nsec / (NSEC_PER_SEC / 100L)));

}

inline struct bfd_session *
bfd_session_new(struct bfd_proto *proto, struct sockaddr *dst, int ifindex)
{
	struct bfd_session *bfd;

	bfd = kmalloc(sizeof(struct bfd_session), GFP_KERNEL);
	if (bfd){
		memset(bfd, 0, sizeof(struct bfd_session));
		bfd->proto = proto;

		bfd->cpkt.state = BSM_Down;
		bfd->act_tx_intv = BFD_MIN_TX_INTERVAL_INIT;
		bfd->cpkt.des_min_tx_intv = htonl(BFD_MIN_TX_INTERVAL_INIT);
		bfd->act_rx_intv = BFD_MIN_RX_INTERVAL_INIT;
		bfd->cpkt.req_min_rx_intv = htonl(BFD_MIN_RX_INTERVAL_INIT);
		bfd->cpkt.detect_mult = BFD_DETECT_MULT_DEFAULT;
		bfd->cpkt.version = BFD_VERSION_1;
		bfd->cpkt.length = sizeof(struct bfd_ctrl_packet);
		bfd->cpkt.my_disc = htonl(++master->discriminator);
		while (bfd_session_lookup(bfd->proto, bfd->cpkt.my_disc, NULL, 0)){
			bfd->cpkt.my_disc++;
		}


		INIT_WORK(&bfd->t_tx_work, bfd_xmit_timeout, NULL);
		bfd->t_tx_work.data = bfd;

		INIT_WORK(&bfd->t_rx_expire, bfd_detect_timeout, NULL);
		bfd->t_rx_expire.data = bfd;

		bfd->dst = kmalloc(bfd->proto->namelen(dst), GFP_KERNEL);
		if (!bfd->dst){
			kfree(bfd);
			return NULL;
		}
		memcpy(bfd->dst, dst, bfd->proto->namelen(dst));

		bfd->src = kmalloc(bfd->proto->namelen(dst), GFP_KERNEL);
		if (!bfd->src){
			kfree(bfd->dst);
			kfree(bfd);
			return NULL;
		}

		bfd->proto->create_ctrl_socket(bfd);
		/* set output interface */
		bfd->tx_ctrl_sock->sk->sk_bound_dev_if = ifindex;

        if (ifindex == 0)
            ifindex = bfd->proto->get_oif(dst);

		/* bind interface */
		bfd->bif = bfd_interface_get(ifindex);
	}

	return bfd;
}

void
bfd_session_free(struct bfd_session *bfd)
{
	if (bfd){
		if (bfd->src){
			kfree(bfd->src);
		}
		if (bfd->dst){
			kfree(bfd->dst);
		}
		kfree(bfd);
	}
	return;
}

struct bfd_session *
bfd_session_lookup(struct bfd_proto *proto, u_int32_t my_disc,
				   struct sockaddr *dst, int ifindex)
{
	u_int32_t key;
	struct bfd_session *bfd;

	rcu_read_lock();
	if (my_disc){
		key = HASH_KEY(my_disc);
		bfd = master->session_tbl[key];
		while (bfd){
			if (bfd->cpkt.my_disc == my_disc)
				break;
			bfd = bfd->session_next;
		}
	}
	else {
		key = proto->hash(dst);

		bfd = proto->nbr_tbl[key];
		while (bfd){
			if (proto->cmp(bfd->dst, dst) == 0)
				if (!ifindex || bfd->bif->ifindex == ifindex)
					break;
			bfd = bfd->nbr_next;
		}
	}
	rcu_read_unlock();
	
	return bfd;
}

int
bfd_session_add(struct bfd_proto *proto, struct sockaddr *dst, int ifindex)
{
	struct bfd_session *bfd;
	u_int32_t key;
	int err = 0;

	bfd = bfd_session_lookup(proto, 0, dst, ifindex);
	if (bfd){
		blog_warn("Already registered. ignore.");
		err = -EEXIST;
		return err;
	}

	bfd = bfd_session_new(proto, dst, ifindex);
	if (!bfd)
		return -ENOMEM;

	/* register hash */
	spin_lock(&tbl_lock);
	key = proto->hash(dst);
	bfd->nbr_next = proto->nbr_tbl[key];
	proto->nbr_tbl[key] = bfd;

	key = HASH_KEY(bfd->cpkt.my_disc);
	bfd->session_next = master->session_tbl[key];
	master->session_tbl[key] = bfd;
	spin_unlock(&tbl_lock);

	bfd_bsm_event(bfd, BSM_Start);

	return err;
}


int
bfd_session_delete(struct bfd_proto *proto, struct sockaddr *dst, int ifindex)
{
	struct bfd_session *bfd1, *bfd2, *prev = NULL;
	u_int32_t key;
	char buf[256];

	/* unregister hash */
	spin_lock(&tbl_lock);
	key = proto->hash(dst);
	bfd1 = proto->nbr_tbl[key];
	while (bfd1){
		if (proto->cmp(bfd1->dst, dst) == 0){
			if (prev)
				prev->nbr_next = bfd1->nbr_next;
			else
				proto->nbr_tbl[key] = bfd1->nbr_next;
			break;
		}
		prev = bfd1;
		bfd1 = bfd1->nbr_next;
	}

	if (!bfd1){
		blog_err("not found. ignore");
		spin_unlock(&tbl_lock);
		return -1;
	}

	key = HASH_KEY(bfd1->cpkt.my_disc);
	bfd2 = master->session_tbl[key];
	while (bfd2){
		if (bfd2->cpkt.my_disc == bfd1->cpkt.my_disc){
			if (prev)
				prev->session_next = bfd2->session_next;
			else
				master->session_tbl[key] = bfd2->session_next;
			break;
		}
		prev = bfd2;
		bfd2 = bfd2->session_next;
	}
	spin_unlock(&tbl_lock);

	if (!bfd2){
		blog_err("Session %d(local disc) not found. ignore", bfd1->cpkt.my_disc);
	}

	if (bfd1 != bfd2){
		blog_err("Session deletion isn't invalid %d", bfd1->cpkt.my_disc);
	}


	if (IS_DEBUG_BSM){
		blog_info("session %s, disc=%d deleted",
				  proto->addr_print(bfd1->dst, buf),
				  bfd1->cpkt.my_disc);
	}

	bfd_stop_xmit_timer(bfd1);
	bfd_stop_expire_timer(bfd1);

	sock_release(bfd1->tx_ctrl_sock);

	synchronize_rcu();
	bfd_session_free(bfd1);

	return 0;
}


void
bfd_xmit_timeout(void *data)
{
	struct bfd_session *bfd = (struct bfd_session *)data;

	/* reset timer before send processing(avoid self synchronization) */
	bfd_start_xmit_timer(bfd);

	bfd_send_ctrl_packet(bfd);
	return;
}

void
bfd_start_xmit_timer(struct bfd_session *bfd)
{
	int jitter;

	/* jitter is 0% -> 25%. if detectmult == 1, max 90% */
	get_random_bytes(&jitter, 4);
	jitter = 75 + jitter % ((bfd->cpkt.detect_mult == 1 ? 15 : 25) + 1);

	queue_delayed_work(master->tx_ctrl_wq, &bfd->t_tx_work,
					   usecs_to_jiffies(bfd->act_tx_intv) * jitter / 100 );
	return;
}

void
bfd_stop_xmit_timer(struct bfd_session *bfd)
{
	if (bfd->t_tx_work.pending)
		cancel_rearming_delayed_workqueue(master->tx_ctrl_wq, &bfd->t_tx_work);

	return;
}

void
bfd_reset_tx_timer(struct bfd_session *bfd)
{
	bfd_stop_xmit_timer(bfd);
	bfd_start_xmit_timer(bfd);
	return;
}

void
bfd_detect_timeout(void *data)
{
	struct bfd_session *bfd = (struct bfd_session *)data;

	bfd_bsm_event(bfd, BSM_Timer_Expired);
	return;
}

void
bfd_stop_expire_timer(struct bfd_session *bfd)
{
	if (bfd->t_rx_expire.pending)
		cancel_rearming_delayed_workqueue(master->ctrl_expire_wq, 
										  &bfd->t_rx_expire);
	return;
}

void
bfd_reset_expire_timer(struct bfd_session *bfd)
{
	bfd_stop_expire_timer(bfd);
	queue_delayed_work(master->ctrl_expire_wq, &bfd->t_rx_expire,
					   usecs_to_jiffies(bfd->detect_time));
	return;
}


void
bfd_change_interval_time(struct bfd_session *bfd,
						  u_int32_t tx, u_int32_t rx)
{
	if (IS_DEBUG_BSM)
		blog_info("Try to change intv TX=%d(usec), RX=%d(usec)", 
			tx, rx);

	/* Section 6.7.3 Description */
	if (bfd->cpkt.state == BSM_Up &&
		tx > ntohl(bfd->cpkt.des_min_tx_intv)){
		bfd->cpkt.poll = 1;
		blog_info("BFD Poll Sequence is started(tx_intv change)");
	}
	else{
		bfd->act_tx_intv = tx < ntohl(bfd->last_rcv_req_rx) ?
			ntohl(bfd->last_rcv_req_rx) : tx;
		bfd_reset_tx_timer(bfd);
		if (IS_DEBUG_BSM)
			blog_info("New TX %d(usec)(tx_intv change)", 
				bfd->act_tx_intv);
	}

	if (bfd->cpkt.state == BSM_Up &&
		rx < ntohl(bfd->cpkt.req_min_rx_intv)){
		bfd->cpkt.poll = 1;
		if (IS_DEBUG_BSM)
			blog_info("BFD Poll Sequence is started(rx_intv change).");
	}
	else{
		bfd->act_rx_intv = rx;
		if (IS_DEBUG_BSM)
			blog_info("New RX %d(usec)(rx_intv change)", rx);
	}

	bfd->cpkt.des_min_tx_intv = htonl(tx);
	bfd->cpkt.req_min_rx_intv = htonl(rx);
	bfd->cpkt.detect_mult = bfd->bif->v_mult;

	if (IS_DEBUG_BSM)
		blog_info("Change intv TX=%d(usec), RX=%d(usec)", 
			tx, rx);
	return;
}



int
bsm_ignore(struct bfd_session *bfd)
{
	if (IS_DEBUG_BSM)
		blog_info("BSM: ignored.");

	return 0;
}

int
bsm_toggle_admin_down(struct bfd_session *bfd)
{
	if (bfd->cpkt.state != BSM_AdminDown){
		/* goes to administratively down */
		bfd->cpkt.diag = BFD_DIAG_ADMIN_DOWN;
		bfd_stop_xmit_timer(bfd);
		bfd_stop_expire_timer(bfd);
	}
	else{
		/* wake up session */
		bfd->cpkt.diag = BFD_DIAG_NO_DIAG;
		bfd_bsm_event(bfd, BSM_Start);
	}

	return 0;
}

int
bsm_start(struct bfd_session *bfd)
{
	bfd_start_xmit_timer(bfd);
	return 0;
}

int
bsm_rcvd_down(struct bfd_session *bfd)
{
	if (bfd->cpkt.state == BSM_Up){
		bfd->cpkt.diag = BFD_DIAG_NBR_SESSION_DOWN;
	}
	return 0;
}

int
bsm_rcvd_init(struct bfd_session *bfd)
{
	return 0;
}

int
bsm_rcvd_up(struct bfd_session *bfd)
{
	return 0;
}

int
bsm_timer_expire(struct bfd_session *bfd)
{
	blog_info("BSM:Timeout. to = %uusec", 
			  bfd->detect_time);
	bfd->cpkt.diag = BFD_DIAG_CTRL_TIME_EXPIRED;

	/* reset timer */
	bfd->cpkt.des_min_tx_intv = htonl(BFD_MIN_TX_INTERVAL_INIT);
	bfd->cpkt.req_min_rx_intv = htonl(BFD_MIN_RX_INTERVAL_INIT);
	return 0;
}

struct
{
	int (*func)(struct bfd_session *);
	int next_state;
} BSM[BFD_BSM_STATE_MAX][BFD_BSM_EVENT_MAX]
={
	{
		/* AdminDown */
		{bsm_ignore, BSM_AdminDown},				/* Start */
		{bsm_ignore, BSM_AdminDown},				/* Received_Down */
		{bsm_ignore, BSM_AdminDown},				/* Received_Init */
		{bsm_ignore, BSM_AdminDown},				/* Received_Up */
		{bsm_ignore, BSM_AdminDown},				/* TimerExpired */
		{bsm_toggle_admin_down, BSM_Down},			/* Toggle_AdminDown */
	},
	{
		/* Down */
		{bsm_start, BSM_Down},						/* Start */
		{bsm_rcvd_down, BSM_Init},					/* Received_Down */
		{bsm_rcvd_init, BSM_Up},					/* Received_Init */
		{bsm_ignore, BSM_Down},						/* Received_Up */
		{bsm_ignore, BSM_Down},						/* TimerExpired */
		{bsm_toggle_admin_down, BSM_AdminDown},		/* Toggle_AdminDown */
	},
	{
		/* Init */
		{bsm_ignore, BSM_Init},						/* Start */
		{bsm_ignore, BSM_Init},						/* Received_Down */
		{bsm_rcvd_down, BSM_Up},					/* Received_Init */
		{bsm_rcvd_up, BSM_Up},						/* Received_Up */
		{bsm_timer_expire, BSM_Down},				/* TimerExpired */
		{bsm_toggle_admin_down, BSM_AdminDown},		/* Toggle_AdminDown */
	},
	{
		/* Up */
		{bsm_ignore, BSM_Up},						/* Start */
		{bsm_rcvd_down, BSM_Down},					/* Received_Down */
		{bsm_ignore, BSM_Up},						/* Received_Init */
		{bsm_ignore, BSM_Up},						/* Received_Up */
		{bsm_timer_expire, BSM_Down},				/* TimerExpired */
		{bsm_toggle_admin_down, BSM_AdminDown},		/* Toggle_AdminDown */
	},
};

int
bfd_bsm_event(struct bfd_session *bfd, int bsm_event)
{
	int next_state, old_state;
	char buf[256];

	old_state = bfd->cpkt.state;
	next_state = (*(BSM[bfd->cpkt.state][bsm_event].func))(bfd);

	if (!next_state)
		bfd->cpkt.state = BSM[bfd->cpkt.state][bsm_event].next_state;
	else
		bfd->cpkt.state = next_state;

	if (IS_DEBUG_BSM)
		blog_info("BSM:Event (%s)", bfd_event_string[bsm_event]);

	if (bfd->cpkt.state != old_state){
		if (bfd->cpkt.state == BSM_Up || old_state == BSM_Up){
			blog_info("%s Sta Chg %s=>%s(%s)", 
					  bfd->proto->addr_print(bfd->dst, buf),
					  bfd_state_string[old_state], 
					  bfd_state_string[bfd->cpkt.state],
					  bfd_event_string[bsm_event]);

			/* notify netlink user */
			bfd_nl_send(bfd);
		}
		else if (IS_DEBUG_BSM){
			blog_info("%s Sta Chg %s=>%s(%s)", 
					  bfd->proto->addr_print(bfd->dst, buf),
					  bfd_state_string[old_state], 
					  bfd_state_string[bfd->cpkt.state],
					  bfd_event_string[bsm_event]);
		}

		/* if state changed from !Up to Up, Set Tx/Rx Interval */
		if (old_state != BSM_Up && bfd->cpkt.state == BSM_Up){
			bfd_change_interval_time(bfd, bfd->bif->v_mintx,
									  bfd->bif->v_minrx);
			/* set uptime */
			bfd->last_up = get_sys_uptime();
			bfd->up_cnt++;
		}

		/* Reset Tx Timer */
		if (bfd->cpkt.state != BSM_Up){
			bfd_change_interval_time(bfd, BFD_MIN_TX_INTERVAL_INIT,
									  BFD_MIN_RX_INTERVAL_INIT);

			/* Cancel Expire timer */
			bfd_stop_expire_timer(bfd);
		}
		/* set downtime */
		if (bfd->cpkt.state == BSM_Down){
			bfd->last_down = get_sys_uptime();
			bfd->last_diag = bfd->cpkt.diag;
		}

		/* Reset Diagnostic Code */
		if (old_state == BSM_Down){
			bfd->cpkt.diag = BFD_DIAG_NO_DIAG;
		}
	}

	return 0;
}



static int
proc_session_read(char *page, char **start, off_t off, 
				  int count, int *eof, void *data)
{
	size_t len=0;
	int i=0;
	char buf[256];

	/* Header */
	len += sprintf (page+len, "DstAddr         MyDisc YoDisc If             LUp      LDown LDiag State \n");

	for (i = 0; i < BFD_SESSION_HASH_SIZE; i++){
		struct bfd_session *bfd;

		bfd = master->session_tbl[i];
		while (bfd){
			len += sprintf (page+len,
							"%15s %6u %6u %4s(%1d) %10u %10u %5d %s\n", 
							bfd->proto->addr_print(bfd->dst, buf),
							ntohl(bfd->cpkt.my_disc),
							ntohl(bfd->cpkt.your_disc),
							bfd->bif->ifindex ? bfd->bif->name : "none",
							bfd->bif->ifindex,
							bfd->last_up,
							bfd->last_down,
							bfd->last_diag,
							bfd_state_string[bfd->cpkt.state]);
			bfd = bfd->session_next;
		}
	}

	*eof = 1;
	return len;
}

#define MK_IP(a,b,c,d) ((a << 24) | (b << 16) | (c << 8) | d)

static int
proc_session_write(struct file *file, const char __user *buffer,
               unsigned long count, void *data)
{
	char c, sw;
	unsigned int d1, d2, d3, d4;
	int ifindex;
	int rc;
	struct sockaddr_in dst;
	extern struct bfd_proto v4v6_proto;

	rc = get_user(c, buffer);
	if (rc)
		return rc;

	/* FIXME */
	memset (&dst, 0, sizeof (struct sockaddr_in));

	if (sscanf(buffer, "%c %u.%u.%u.%u %u\n", &sw, &d1, &d2, &d3, &d4, &ifindex) == 6){
		dst.sin_family = AF_INET;
        dst.sin_addr.s_addr = htonl(MK_IP(d1,d2,d3,d4));
		switch (sw){
		case '+':
			bfd_session_add(&v4v6_proto, (struct sockaddr *)&dst, ifindex);
			break;
		case '-':
			bfd_session_delete(&v4v6_proto, (struct sockaddr *)&dst, ifindex);
			break;
		default:
			break;
		}
	}
	else{
		blog_err("input format is invalid...:");
	}

	return count;
}


int
bfd_session_init(void)
{
	/* initialize hash */
	memset(master->session_tbl, 0,
			sizeof(struct bfd_session *) * BFD_SESSION_HASH_SIZE);

	/* Workqueue for send process */
	master->tx_ctrl_wq = create_singlethread_workqueue("kbfd_tx");
	if (!master->tx_ctrl_wq){
		blog_err("failed create workqueue");
	}

	/* Workqueue for receive expire */
	master->ctrl_expire_wq = create_singlethread_workqueue("kbfd_rx_expire");
	if (!master->ctrl_expire_wq){
		blog_err("failed create workqueue");
	}

	/* proc fs */
	kbfd_root_dir = proc_mkdir("kbfd", &proc_root);
	if (!kbfd_root_dir){
		blog_err("kbfd init fail(proc)...:");
		return 0;
	}

	session_proc = create_proc_entry("session", S_IFREG|S_IRWXUGO,
									 kbfd_root_dir);
	if (!session_proc)
 		return 0;

	session_proc->read_proc = proc_session_read;
	session_proc->write_proc = proc_session_write;

	return 0;
}


int
bfd_session_finish(void)
{
	int i = 0;

	if(kbfd_root_dir){
		if(session_proc)
			remove_proc_entry("session", kbfd_root_dir);
		remove_proc_entry("kbfd", 0);
	}

	for (i = 0; i < BFD_SESSION_HASH_SIZE; i++){
		struct bfd_session *bfd;

		bfd = master->session_tbl[i];
		while (bfd){
			bfd_session_delete(bfd->proto, bfd->dst, bfd->bif->ifindex);

			bfd_stop_xmit_timer(bfd);
			bfd_stop_expire_timer(bfd);
			bfd = bfd->session_next;
		}
	}

	if (master->ctrl_expire_wq){
		destroy_workqueue(master->ctrl_expire_wq);
		master->ctrl_expire_wq = NULL;
	}

	if (master->tx_ctrl_wq){
		destroy_workqueue(master->tx_ctrl_wq);
		master->tx_ctrl_wq = NULL;
	}

	return 0;
}
