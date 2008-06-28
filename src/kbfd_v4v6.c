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

#include "kbfd_sys.h"

#include "kbfd.h"
#include "kbfd_queue.h"
#include "kbfd_session.h"
#include "kbfd_packet.h"
#include "kbfd_v4v6.h"
#include "kbfd_memory.h"
#include "kbfd_log.h"
#include "kbfd_netlink.h"

struct bfd_session *v4v6_nbr_tbl[BFD_SESSION_HASH_SIZE];
#ifdef linux
static DECLARE_COMPLETION(threadcomplete);
static int recv_thread_pid;
#elif defined __NetBSD__
static struct lwp *recv_thread;
static kcondvar_t kbfd_th_cv;
static kmutex_t kbfd_th_lock;
#endif /* __NetBSD__ */


static struct socket *rx_ctrl_sock = NULL;
static struct socket *echo_sock = NULL;
struct bfd_proto v4v6_proto;

extern struct bfd_master *master;

static int bfd_create_ctrl_sock(void);
static int bfd_create_echo_sock(void);
static volatile int running = 0;

#define IN6ADDR_HASH(addr)                              \
  ((addr)->s6_addr32[0] ^ (addr)->s6_addr32[1] ^        \
   (addr)->s6_addr32[2] ^ (addr)->s6_addr32[3])

static u_int32_t
bfd_v4v6_hash(struct sockaddr *key)
{
	switch (key->sa_family){
	case AF_INET:
		return (((struct sockaddr_in *)key)->sin_addr.s_addr
				% BFD_SESSION_HASH_SIZE);
		break;
	case AF_INET6:
		return IN6ADDR_HASH(&((struct sockaddr_in6 *)key)->sin6_addr)
			% BFD_SESSION_HASH_SIZE;
		break;
	default:
		break;
	}
	return 0;
}

static int
bfd_v4v6_cmp(struct sockaddr *val1, struct sockaddr *val2)
{
	if (val1->sa_family != val2->sa_family)
		return (val1->sa_family - val2->sa_family);

	switch (val1->sa_family){
	case AF_INET:
		return memcmp(&(((struct sockaddr_in *)val1)->sin_addr),
                              &(((struct sockaddr_in *)val2)->sin_addr), sizeof(struct in_addr));
		break;
	case AF_INET6:
		return memcmp(&((struct sockaddr_in6 *)val1)->sin6_addr,
                              &((struct sockaddr_in6 *)val2)->sin6_addr, sizeof(struct in6_addr));
		break;
	default:
		break;
	}
	return 1;
}

static char *
bfd_v4v6_print(struct sockaddr *addr, char *buf)
{

	if (addr->sa_family == AF_INET){
#ifdef linux
		sprintf(buf, NIPQUAD_FMT,
				NIPQUAD(((struct sockaddr_in *)addr)->sin_addr.s_addr));
#elif defined __NetBSD__
                sprintf(buf, in_fmtaddr(((struct sockaddr_in *)addr)->sin_addr));
#endif
	}
	else if (addr->sa_family == AF_INET6){
#ifdef linux
		if (ipv6_addr_type(&((struct sockaddr_in6 *)addr)->sin6_addr)
			== IPV6_ADDR_MAPPED)
#elif defined __NetBSD__
		if (IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6 *)addr)->sin6_addr))
#endif  /* __NetBSD__ */
                  {
			struct in_addr in;

			memcpy (&in, (char *)&(((struct sockaddr_in6 *)addr)->sin6_addr) + 12, 4);
#ifdef linux
			sprintf(buf, "V6MAP " NIPQUAD_FMT, NIPQUAD(in.s_addr));
#elif defined __NetBSD__
			sprintf(buf, "V6MAP %s", in_fmtaddr(in));
#endif /* __NetBSD__ */
		}
		else{
#ifdef linux
			sprintf(buf, NIP6_FMT,
					NIP6(((struct sockaddr_in6 *)addr)->sin6_addr));
#elif defined __NetBSD__
			sprintf(buf, ip6_sprintf(&((struct sockaddr_in6 *)addr)->sin6_addr));
#endif
		}
	}
	else{
		sprintf(buf, "unknown family(%d)", addr->sa_family);
	}


	return buf;
}

static int
bfd_v4v6_namelen(struct sockaddr *addr)
{
	switch (addr->sa_family){
	case AF_INET:
		return sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		return sizeof(struct sockaddr_in6);
		break;
	default:
		break;
	}
	return 0;
}

#ifdef linux
static int
bfd_v4v6_get_oif(struct sockaddr *addr)
{
	struct flowi fl;
	struct dst_entry *dst;

	switch (addr->sa_family){
	case AF_INET:
        memset(&fl, 0, sizeof(fl));
        memcpy(&fl.fl4_dst, &(((struct sockaddr_in *)addr)->sin_addr),
               sizeof(struct in_addr));
		ip_route_output_key((struct rtable **)&dst, &fl);
		return dst ? dst->dev->ifindex : 0;
		break;
	case AF_INET6:
        memset(&fl, 0, sizeof(fl));
		ipv6_addr_copy(&fl.fl6_dst,
                       &((struct sockaddr_in6 *)addr)->sin6_addr);
        dst = ip6_route_output(NULL, &fl);
		return dst ? dst->dev->ifindex : 0;
		break;
	default:
		break;
	}
	return 0;
}
#elif defined __NetBSD__
static int
bfd_v4v6_get_oif(struct sockaddr *addr)
{
	struct ifnet *ifp;
	int err;

	switch (addr->sa_family){
	case AF_INET:
		/* Not supported yet */
		return 0;
		break;
	case AF_INET6:
		err = in6_selectroute((struct sockaddr_in6 *)addr,
		    NULL, NULL, NULL, &ifp, NULL, 0);
		return err ? 0 : ifp->if_index;
		break;
	default:
		break;
	}
	return 0;
}
#endif /* __NetBSD__ */


static int
bfd_v4v6_create_ctrl_socket(struct bfd_session *bfd)
{
	struct socket *sock = NULL;
	int err = 0;
	int sport;
	struct sockaddr_in6 *sin6;
#ifdef __NetBSD__
	struct mbuf *m;
#endif  /* __NetBSD__ */

#ifdef linux
	err = sock_create(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, &sock);
	if(err < 0)
#elif defined __NetBSD__
	err = socreate(AF_INET6, &sock, SOCK_DGRAM, IPPROTO_UDP, 
	    recv_thread);
	if(err != 0)
#endif  /* __NetBSD__ */
        {
		blog_err("Error creating control socket.");
	}

	/* bind port */
	sport = BFD_SRC_CONTROL_PORT_BEGIN;
#ifdef linux
        sin6 = bfd_malloc(sizeof(struct sockaddr_in6));
#elif defined __NetBSD__
	m = m_get(M_WAIT, MT_SONAME);
	MCLAIM(m, sock->so_mowner);
	sin6 = mtod(m, struct sockaddr_in6 *);
	m->m_len = sizeof (struct sockaddr_in6);
#endif  /* __NetBSD__ */

	sin6->sin6_family = AF_INET6;
	memset(&sin6->sin6_addr, 0, sizeof(struct in6_addr));
	sin6->sin6_port = htons((unsigned short)BFD_SRC_CONTROL_PORT_BEGIN);

#ifdef linux
	while ((err = sock->ops->bind(sock, (struct sockaddr *)sin6, 
                                      sizeof(struct sockaddr_in6))) != 0)
#elif defined __NetBSD__
	while ((err = sobind(sock, m, recv_thread)) != 0)
#endif  /* __NetBSD */
        {
		sin6->sin6_port = htons((unsigned short)++sport);
		if (sport > BFD_SRC_CONTROL_PORT_END){
			blog_err("Error bind control tx_socket. %d", err);
#ifdef linux
			bfd_free(sin6);
#elif defined __NetBSD__
			m_freem(m);
#endif  /* __NetBSD__ */
			return -1;
		}
	}

#ifdef linux
	bfd_free(sin6);
#elif defined __NetBSD__
	m_freem(m);
#endif  /* __NetBSD__ */

	/* ttl is 255 */
#ifdef linux
	inet_sk(sock->sk)->uc_ttl = 255;
	inet_sk(sock->sk)->pinet6->hop_limit = 255;
#elif defined __NetBSD__
	/* We set hoplimit at sending time NetBSD */
#endif  /* __NetBSD__ */

	((struct sockaddr_in *)bfd->dst)->sin_port = 
		htons((unsigned short)BFD_CONTROL_PORT);
	bfd->tx_ctrl_sock = sock;

	return 0;
}

#if defined __NetBSD__
static void
bfd_rcv_v4v6(struct socket *so, void *arg, int waitflag)
{
	struct sockaddr_in6 *client = NULL, our_addr; /* FIXME */
	struct bfd_ctrl_packet *bpkt = NULL;
	char buffer[128];
	int len;
	int ifindex = 0;
	int rcvttl = 0;
	/* For IP_PKTINFO */
	struct cmsghdr *cmh;
	union ip_pktinfo_union *pkti_u;
	struct mbuf *from = NULL, *control = NULL, *m = NULL, *tmp_from, *tmp_mp, *ctrl;
	int err;
	struct uio auio;
	int rcvflg;
	struct mbuf *mp = NULL;

        if(!so)
		return;

	/* not need to setup uio_vmspace */
	do {
		auio.uio_resid = len = 1000000;
		rcvflg = MSG_DONTWAIT;
		err = (*so->so_receive)(so, 
		    &tmp_from, &auio, &tmp_mp, &ctrl, &rcvflg);

		if (err == EWOULDBLOCK) {
			break;
		}
		else if (err){
			break;
		}

		if(tmp_mp)
			mp = tmp_mp;
		if(tmp_from)
			from = tmp_from;
		if(ctrl){
			control = ctrl;
		}

#ifdef DEBUG
		blog_info("%s: so_receive ok, len=%d from=%p, mp=%p, ctrl=%p",
		    __func__, len, from, mp, control);
#endif

		if(control)
			break;
	} while (1);
	len -= auio.uio_resid;

#ifdef DEBUG
	blog_info("%s: after loop, len=%d from=%p, mp=%p, ctrl=%p",
	    __func__, len, from, mp, control);
	blog_info("<<rtrn recvmsg");
#endif

	if(err && err != EWOULDBLOCK) {
		if(from){
			m_freem(from);
			from = NULL;
		}
		if(control) {
			free_control_mbuf(curlwp, control, control);
			control = NULL;
		}
		if(mp){
			m_freem(mp);
			mp = (struct mbuf *)0;
		}

		blog_info("recvmsg len <= 0, err=%d", err);
		return;
	}


	/* control */
	for (m = control; m != NULL; m = m->m_next) {
		cmh = mtod(m, struct cmsghdr *);
		if (cmh->cmsg_level == IPPROTO_IP){
		}
		else if (cmh->cmsg_level == IPPROTO_IPV6){
			if (cmh->cmsg_type == IPV6_PKTINFO){
				pkti_u = (union ip_pktinfo_union *)CMSG_DATA(cmh);
				ifindex = pkti_u->pkti6.ipi6_ifindex;
				our_addr.sin6_family = AF_INET6;
				memcpy(&our_addr.sin6_addr,
				    &pkti_u->pkti6.ipi6_addr,
				    sizeof(pkti_u->pkti6.ipi6_addr));
			}
			else if(cmh->cmsg_type == IPV6_HOPLIMIT){
				rcvttl = *(int *)CMSG_DATA(cmh);
			}
		}
	}
	free_control_mbuf(curlwp, control, m);

#ifdef DEBUG
	blog_info("%s ctrl parse done. ifindex=%d, rcvttl==%d",
	    __func__, ifindex, rcvttl);

	blog_info("ouraddr = %s ttl=%d iif=%d", 
	    bfd_v4v6_print((struct sockaddr *)&our_addr, buffer),
	    rcvttl, ifindex);
#endif

	/* Peer address */
	client = mtod(from, struct sockaddr_in6 *);
	if (IN6_IS_ADDR_V4MAPPED(&(client->sin6_addr))){
		struct sockaddr_in sin;

		memset (&sin, 0, sizeof (struct sockaddr_in));
		sin.sin_family = AF_INET;
		memcpy (&sin.sin_addr,
		    (char *)&(client->sin6_addr) + 12, 4);
		memcpy (client, &sin, sizeof (struct sockaddr_in));
	}
	if(from){
		m_freem(from);
		from = NULL;
	}

	/* GTSM check */
	if (rcvttl != 255){
		blog_warn("%s: GTSM check failure. TTL=%d", 
		    bfd_v4v6_print((struct sockaddr *)client, buffer),
		    rcvttl);
		goto end;
	}

	if (mp->m_len < sizeof(*bpkt) &&
	    (mp = m_pullup(m, sizeof(*bpkt))) == NULL) {
		blog_warn("%s: m_pullup failed", __func__);
		return;
	}
	bpkt = mtod(mp, struct bfd_ctrl_packet *);
	bfd_recv_ctrl_packet(&v4v6_proto, (struct sockaddr *)client,
	    (struct sockaddr *)&our_addr,
	    ifindex, (char *)bpkt, mp->m_len);

end:
	if(mp){
		m_freem(mp);
		mp = (struct mbuf *)0;
	}

	return;
}

static void 
bfd_v4v6_main_thread(void *data)
{
	int event_queue_count;
	/* Socket Creation */
	bfd_create_ctrl_sock();
	bfd_create_echo_sock();

	running = 1;

	while(running)
	{
		/* FIXME */
		tsleep(&event_queue_count, PSOCK,
			"bfd_main", 1);
	}

	rx_ctrl_sock->so_upcall = NULL;
	rx_ctrl_sock->so_upcallarg = NULL;
	rx_ctrl_sock->so_rcv.sb_flags &= ~SB_UPCALL;
	soshutdown(rx_ctrl_sock, SHUT_RDWR);
	soclose(rx_ctrl_sock);
	soclose(echo_sock);

	mutex_enter(&kbfd_th_lock);
	cv_signal(&kbfd_th_cv);
	mutex_exit(&kbfd_th_lock);

	kthread_exit(0);

	return;
}
#endif	/* __NetBSD__ */

#ifdef linux
static int
bfd_v4v6_recv_thread(void *data)
{
	struct sockaddr_in6 client, our_addr; /* FIXME */
	char buffer[sizeof (struct bfd_ctrl_packet)];
	int len, addr_size;
	struct msghdr msg;
	struct iovec iov;
	mm_segment_t oldfs;
	int ifindex = 0;
	int rcvttl = 0;
	struct sched_param param;
	static int init = 0;
	/* For IP_PKTINFO */
	char cbuffer[CMSG_SPACE(sizeof(union ip_pktinfo_union)) +
	    CMSG_SPACE(sizeof(rcvttl))];
	struct cmsghdr *cmh = (struct cmsghdr *)cbuffer;
	struct cmsghdr *cmhp;
	union ip_pktinfo_union *pkti_u;

	daemonize("kbfd_v4v6_rx");
	allow_signal(SIGTERM);

	if (init == 0){
		param.sched_priority = MAX_RT_PRIO - 1;
		sched_setscheduler(current, SCHED_FIFO, &param);
		init++;
	}

	if (rx_ctrl_sock->sk==NULL) 
		return 0;

	msg.msg_iov	 = &iov;
	msg.msg_iovlen = 1;
	msg.msg_namelen = sizeof(struct sockaddr_in6);
	msg.msg_name = &client;
	msg.msg_flags = 0;

	while (!signal_pending(current))
	{
		msg.msg_control = cmh;
		msg.msg_controllen = sizeof(cbuffer);
		iov.iov_base = buffer;
		iov.iov_len  = sizeof(buffer);
		oldfs = get_fs(); 
		set_fs(KERNEL_DS);
		len = sock_recvmsg(rx_ctrl_sock, &msg, sizeof(buffer), 0);
		set_fs(oldfs);
		if (len <= 0)
		{
			blog_info("recvmsg len <= 0, %d", len);
			continue;
		}

		msg.msg_control = cmh;
		msg.msg_controllen = sizeof(cbuffer);
		for (cmhp = CMSG_FIRSTHDR(&msg); cmhp; cmhp = CMSG_NXTHDR(&msg, cmhp)){
			if (cmhp->cmsg_level == IPPROTO_IP){
				if (cmhp->cmsg_type == IP_PKTINFO){
					pkti_u = (union ip_pktinfo_union *)CMSG_DATA(cmhp);
					ifindex = pkti_u->pkti.ipi_ifindex;
					our_addr.sin6_family = AF_INET;
					((struct sockaddr_in *)&our_addr)->sin_addr
					    = pkti_u->pkti.ipi_addr;
				}
				else if(cmhp->cmsg_type == IP_TTL){
					rcvttl = *(int *)CMSG_DATA(cmhp);
				}
			}
			else if (cmhp->cmsg_level == IPPROTO_IPV6){
				if (cmhp->cmsg_type == IPV6_PKTINFO){
					pkti_u = (union ip_pktinfo_union *)CMSG_DATA(cmhp);
					ifindex = pkti_u->pkti6.ipi6_ifindex;
					our_addr.sin6_family = AF_INET6;
					memcpy(&our_addr.sin6_addr,
					    &pkti_u->pkti6.ipi6_addr,
					    sizeof(pkti_u->pkti6.ipi6_addr));
				}
				else if(cmhp->cmsg_type == IPV6_HOPLIMIT){
					rcvttl = *(int *)CMSG_DATA(cmhp);
				}
			}
		}

#ifdef DEBUG
		blog_info("ouraddr = %s ttl=%d iif=%d", 
		    bfd_v4v6_print((struct sockaddr *)&our_addr, buffer),
		    rcvttl, ifindex);
#endif

		/* Peer address */
		rx_ctrl_sock->ops->getname(rx_ctrl_sock,
		    (struct sockaddr *)&client, &addr_size, 1);
		if (ipv6_addr_type(&(client.sin6_addr)) == IPV6_ADDR_MAPPED)
		{
			struct sockaddr_in sin;

			memset (&sin, 0, sizeof (struct sockaddr_in));
			sin.sin_family = AF_INET;
			memcpy (&sin.sin_addr,
			    (char *)&(client.sin6_addr) + 12, 4);
			memcpy (&client, &sin, sizeof (struct sockaddr_in));
		}

		/* GTSM check */
		if (rcvttl != 255){
			blog_warn("%s: GTSM check failure. TTL=%d", 
			    bfd_v4v6_print((struct sockaddr *)&client, buffer),
			    rcvttl);
			continue;
		}

		bfd_recv_ctrl_packet(&v4v6_proto, (struct sockaddr *)&client,
		    (struct sockaddr *)&our_addr,
		    ifindex, buffer, len);

	}

	complete(&threadcomplete);
	return 0;
}
#endif	/* linux */

static int
bfd_create_ctrl_sock(void)
{
	int err;
	struct sockaddr_in6 *sin6;
#ifdef linux
	mm_segment_t oldfs;
	int val = 1;
#endif /* linux */
#ifdef __NetBSD__
	struct mbuf *m;
#endif	/* __NetBSD__ */

#ifdef linux
	if ((err = sock_create(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, &rx_ctrl_sock)) < 0)
#elif defined __NetBSD__
	if ((err = socreate(AF_INET6, &rx_ctrl_sock, SOCK_DGRAM, IPPROTO_UDP
		    ,curlwp)) != 0)
#endif	/* __NetBSD__ */
	{
		blog_err("Error creating control socket. err=%d", err);
		err = -EIO;
		goto err;
	}

	/* bind port */
#ifdef linux
	rx_ctrl_sock->sk->sk_reuse = 1;
#elif defined __NetBSD__
	rx_ctrl_sock->so_options |= SO_REUSEADDR|SO_REUSEPORT;
#endif	/* __NetBSD__ */

#ifdef linux
        sin6 = bfd_malloc(sizeof(struct sockaddr_in6));
#elif defined __NetBSD__
	m = m_get(M_WAIT, MT_SONAME);
	MCLAIM(m, rx_ctrl_sock->so_mowner);
	sin6 = mtod(m, struct sockaddr_in6 *);
	m->m_len = sizeof (struct sockaddr_in6);
#endif  /* __NetBSD__ */

	sin6->sin6_family = AF_INET6;
	memset(&sin6->sin6_addr, 0, sizeof(struct in6_addr));
	sin6->sin6_port = htons((unsigned short)BFD_CONTROL_PORT);

#ifdef linux
	err = rx_ctrl_sock->ops->bind(rx_ctrl_sock,
	    (struct sockaddr *)sin6, sizeof(struct sockaddr_in6));
	if (err){
		blog_err("Error bind control rx_socket. %d", err);
		err = EIO;
		goto err;
	}
#elif defined __NetBSD__
	err = sobind(rx_ctrl_sock, m, &lwp0);
	if (err != 0){
		blog_err("Error bind control rx_socket. %d", err);
		err = EIO;
		m_freem(m);
		goto err;
	}
	m_freem(m);
#endif  /* __NetBSD */

	/* IP_PKTINFO */
#ifdef linux
	oldfs = get_fs(); set_fs(KERNEL_DS);
	err = rx_ctrl_sock->ops->setsockopt(rx_ctrl_sock, IPPROTO_IP, 
	    IP_PKTINFO, (char __user *)&val, sizeof(val));
	if (err){
		blog_warn("setsockopt failure (%d)", err);
	}
	
	err = rx_ctrl_sock->ops->setsockopt(rx_ctrl_sock, IPPROTO_IP, 
	    IP_RECVTTL, (char __user *)&val, sizeof(val));
	if (err){
		blog_warn("setsockopt failure (%d)", err);
	}
	err = rx_ctrl_sock->ops->setsockopt(rx_ctrl_sock, IPPROTO_IPV6, 
	    IPV6_RECVPKTINFO, (char __user *)&val, sizeof(val));
	if (err){
		blog_warn("setsockopt failure (%d)", err);
	}
	
	err = rx_ctrl_sock->ops->setsockopt(rx_ctrl_sock, IPPROTO_IPV6,
	    IPV6_RECVHOPLIMIT, (char __user *)&val, sizeof(val));
	if (err){
		blog_warn("setsockopt failure (%d)", err);
	}
	set_fs(oldfs);
#elif defined __NetBSD__
	m = m_get(M_WAIT, MT_SOOPTS);
	MCLAIM(m, rx_ctrl_sock->so_mowner);
	*mtod(m, int *) = 1;
	m->m_len = sizeof(int);
	err = sosetopt(rx_ctrl_sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, m);
	if(err)
		blog_err("sosetopt err = %d", err);

	m = m_get(M_WAIT, MT_SOOPTS);
	MCLAIM(m, rx_ctrl_sock->so_mowner);
	*mtod(m, int *) = 1;
	m->m_len = sizeof(int);
	err = sosetopt(rx_ctrl_sock, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, m);
	if(err)
		blog_err("sosetopt err = %d", err);

	rx_ctrl_sock->so_upcallarg = (void *)NULL;
	rx_ctrl_sock->so_upcall = bfd_rcv_v4v6;
	rx_ctrl_sock->so_rcv.sb_flags |= SB_UPCALL;
#endif	/* __NetBSD__ */

	return err;

err:
	if (rx_ctrl_sock)
#ifdef linux
		sock_release(rx_ctrl_sock);
#elif defined __NetBSD__
		soclose(rx_ctrl_sock);
#endif	/* __NetBSD__ */
	return err;
}

static int
bfd_create_echo_sock(void)
{
	int err;
	struct sockaddr_in6 *sin6;
#ifdef __NetBSD__
	struct mbuf *m;
#endif	/* __NetBSD__ */

#ifdef linux
	if (sock_create(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, &echo_sock) < 0)
#elif defined __NetBSD__
	if (socreate(AF_INET6, &echo_sock, SOCK_DGRAM, IPPROTO_UDP
		, curlwp) != 0)
#endif	/* __NetBSD__ */
	{
		blog_err("Error creating echo socket.");
		err = EIO;
		goto err;
	}

#ifdef linux
	echo_sock->sk->sk_reuse = 1;
#elif defined __NetBSD__
	m = m_get(M_WAIT, MT_SOOPTS);
	MCLAIM(m, echo_sock->so_mowner);
	*mtod(m, u_char *) = 1;
	m->m_len = sizeof(u_char);
	sosetopt(echo_sock, SOL_SOCKET, SO_REUSEADDR|SO_REUSEPORT, m);
#endif	/* __NetBSD__ */

#ifdef linux
        sin6 = bfd_malloc(sizeof(struct sockaddr_in6));
#elif defined __NetBSD__
	m = m_get(M_WAIT, MT_SONAME);
	MCLAIM(m, rx_ctrl_sock->so_mowner);
	sin6 = mtod(m, struct sockaddr_in6 *);
	m->m_len = sizeof (struct sockaddr_in6);
#endif  /* __NetBSD__ */

	sin6->sin6_family = AF_INET6;
	memset(&sin6->sin6_addr, 0, sizeof(struct in6_addr));
	sin6->sin6_port = htons((unsigned short)BFD_ECHO_PORT);

#ifdef linux
	err = echo_sock->ops->bind(echo_sock,
	    (struct sockaddr *)sin6, sizeof(struct sockaddr_in6));
	if (err){
		blog_err("Error bind echo socket. %d", err);
		err = EIO;
		goto err;
	}
#elif defined __NetBSD__
	err = sobind(echo_sock, m, &lwp0);
	if (err != 0){
		blog_err("Error bind echo socket. %d", err);
		err = EIO;
		m_freem(m);
		goto err;
	}
	m_freem(m);
#endif  /* __NetBSD */
	
	return err;

err:
	if (echo_sock){
#ifdef linux
		sock_release(echo_sock);
#elif defined __NetBSD__
		soclose(echo_sock);
#endif	/* __NetBSD__ */
	}

	return err;
}

int
bfd_v4v6_init(void)
{
	int err = 0;

	/* Start Thread */
#ifdef linux
	recv_thread_pid = kernel_thread(bfd_v4v6_recv_thread, NULL, CLONE_KERNEL);
	if (recv_thread_pid < 0)
#elif defined __NetBSD__
	err = kthread_create(MAXPRI, 0, NULL, bfd_v4v6_main_thread,
	    NULL, &recv_thread, "kbfd_v4v6_rx");
	if (err != 0)
#endif	/* __NetBSD__ */
	{
		blog_err("failed create recv thread");
		err = EIO;
		goto err;
	}

#ifdef linux
	/* Control Packet Socket */
	bfd_create_ctrl_sock();
	if(IS_DEBUG_DEBUG)
		blog_info("create ctrl socket succeed");

	/* Echo Packet Socket */
	bfd_create_echo_sock();
	if(IS_DEBUG_DEBUG)
		blog_info("create echo socket succeed");
#elif defined (__NetBSD__)
	mutex_init(&kbfd_th_lock, MUTEX_DRIVER, IPL_NONE);
	cv_init(&kbfd_th_cv, "kbfd_v4v6_rx");
#endif	/* linux */

	/* initialize neighbor table */
	memset(v4v6_nbr_tbl, 0,
	    sizeof(struct bfd_session *) * BFD_SESSION_HASH_SIZE);

err:
	return err;
}

int
bfd_v4v6_finish(void)
{

#ifdef linux
	if (recv_thread_pid) {
		kill_proc(recv_thread_pid, SIGTERM, 0);
		wait_for_completion(&threadcomplete);
	}
#elif defined __NetBSD__
	if(recv_thread){
		mutex_enter(&kbfd_th_lock);
		running = 0;
		cv_wait(&kbfd_th_cv, &kbfd_th_lock);
		mutex_exit(&kbfd_th_lock);
		recv_thread = NULL;
	}
	cv_destroy(&kbfd_th_cv);
	mutex_destroy(&kbfd_th_lock);
#endif /* __NetBSD__ */

	if(IS_DEBUG_DEBUG)
		blog_info("bfd_v4v6_finish thread is done");

#ifdef linux
	if (rx_ctrl_sock)
		sock_release(rx_ctrl_sock);
	if (echo_sock)
		sock_release(echo_sock);
#endif	/* linux */
	if(IS_DEBUG_DEBUG)
		blog_info("bfd_v4v6_finish is done");

	return 0;
}

struct bfd_proto v4v6_proto = {
	.create_ctrl_socket = bfd_v4v6_create_ctrl_socket,
	.nbr_tbl = v4v6_nbr_tbl,
	.nbr_num = 0,
	.hash = bfd_v4v6_hash,
	.cmp = bfd_v4v6_cmp,
	.addr_print = bfd_v4v6_print,
	.namelen = bfd_v4v6_namelen,
	.get_oif = bfd_v4v6_get_oif,
};

