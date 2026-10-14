// SPDX-License-Identifier: GPL-2.0
/*
 * Two xfrm states can share destination address, SPI and protocol only when
 * both have a direction and the directions differ. Check the duplicate
 * detection, the requests that select a state by direction and the data path
 * of such a pair, over loopback in a private network namespace.
 */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <linux/netlink.h>
#include <linux/xfrm.h>

#include "kselftest_harness.h"

#define SPI		0x1000
#define UDP_PORT	50000
#define ADDR1		INADDR_LOOPBACK
#define ADDR2		(INADDR_LOOPBACK + 1)

#define DIR_NONE	0
#define DIR_IN		XFRM_SA_DIR_IN
#define DIR_OUT		XFRM_SA_DIR_OUT

struct nlreq {
	struct nlmsghdr nh;
	char buf[2048];
};

static void *nlreq_put(struct nlreq *r, size_t len)
{
	size_t off = NLMSG_ALIGN(r->nh.nlmsg_len);

	r->nh.nlmsg_len = off + NLMSG_ALIGN(len);
	memset((char *)r + off, 0, NLMSG_ALIGN(len));
	return (char *)r + off;
}

static void nlreq_attr(struct nlreq *r, uint16_t type, const void *data,
		       size_t len)
{
	struct nlattr *nla = nlreq_put(r, NLA_HDRLEN + len);

	nla->nla_type = type;
	nla->nla_len = NLA_HDRLEN + len;
	memcpy((char *)nla + NLA_HDRLEN, data, len);
}

static void nlreq_init(struct nlreq *r, uint16_t type)
{
	memset(r, 0, sizeof(*r));
	r->nh.nlmsg_type = type;
	r->nh.nlmsg_len = NLMSG_HDRLEN;
}

static void nlreq_dir(struct nlreq *r, uint8_t dir)
{
	if (dir)
		nlreq_attr(r, XFRMA_SA_DIR, &dir, sizeof(dir));
}

/* Returns 0 or a negative errno. A data reply is copied to @reply. */
static int nl_talk(int fd, struct nlreq *r, void *reply, size_t reply_sz)
{
	struct nlmsghdr *nh;
	char buf[4096];
	ssize_t n;

	r->nh.nlmsg_flags |= NLM_F_REQUEST | NLM_F_ACK;
	if (send(fd, r, r->nh.nlmsg_len, 0) < 0)
		return -errno;

	for (;;) {
		n = recv(fd, buf, sizeof(buf), 0);
		if (n < 0)
			return -errno;

		for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, n);
		     nh = NLMSG_NEXT(nh, n)) {
			if (nh->nlmsg_type == NLMSG_ERROR)
				return ((struct nlmsgerr *)NLMSG_DATA(nh))->error;
			if (reply && nh->nlmsg_len <= reply_sz)
				memcpy(reply, nh, nh->nlmsg_len);
		}
	}
}

static const struct nlattr *nl_find_attr(const struct nlmsghdr *nh,
					 size_t hdrlen, uint16_t type)
{
	const char *p = (const char *)NLMSG_DATA(nh) + NLMSG_ALIGN(hdrlen);
	const char *end = (const char *)nh + nh->nlmsg_len;

	while (p + NLA_HDRLEN <= end) {
		const struct nlattr *nla = (const struct nlattr *)p;

		if (nla->nla_len < NLA_HDRLEN || p + nla->nla_len > end)
			break;
		if ((nla->nla_type & NLA_TYPE_MASK) == type)
			return nla;
		p += NLA_ALIGN(nla->nla_len);
	}
	return NULL;
}

static void xid_fill(struct xfrm_id *id, uint32_t daddr)
{
	id->daddr.a4 = htonl(daddr);
	id->spi = htonl(SPI);
	id->proto = IPPROTO_ESP;
}

static void sa_id_fill(struct xfrm_usersa_id *id, uint32_t daddr)
{
	id->daddr.a4 = htonl(daddr);
	id->spi = htonl(SPI);
	id->family = AF_INET;
	id->proto = IPPROTO_ESP;
}

/* Add or update (@type) a transport mode ESP state. */
static int sa_add_saddr(int fd, uint16_t type, uint32_t daddr, uint32_t saddr,
			uint8_t dir, uint32_t reqid, uint64_t soft_pkts)
{
	char aead_buf[sizeof(struct xfrm_algo_aead) + 20] = {};
	struct xfrm_algo_aead *aead = (struct xfrm_algo_aead *)aead_buf;
	struct xfrm_usersa_info *p;
	struct nlreq r;

	nlreq_init(&r, type);
	p = nlreq_put(&r, sizeof(*p));
	xid_fill(&p->id, daddr);
	p->saddr.a4 = htonl(saddr);
	p->sel.family = AF_INET;
	p->lft.soft_byte_limit = XFRM_INF;
	p->lft.hard_byte_limit = XFRM_INF;
	p->lft.soft_packet_limit = soft_pkts;
	p->lft.hard_packet_limit = XFRM_INF;
	p->family = AF_INET;
	p->mode = XFRM_MODE_TRANSPORT;
	p->reqid = reqid;

	strcpy(aead->alg_name, "rfc4106(gcm(aes))");
	aead->alg_key_len = 160;
	aead->alg_icv_len = 128;
	memset(aead->alg_key, 0x5a, 20);
	nlreq_attr(&r, XFRMA_ALG_AEAD, aead, sizeof(aead_buf));
	nlreq_dir(&r, dir);

	return nl_talk(fd, &r, NULL, 0);
}

static int sa_add(int fd, uint16_t type, uint32_t daddr, uint8_t dir,
		  uint32_t reqid, uint64_t soft_pkts)
{
	return sa_add_saddr(fd, type, daddr, INADDR_LOOPBACK, dir, reqid,
			    soft_pkts);
}

struct sa_info {
	int dir;
	int reqid;
	long long soft_pkts;
	long long packets;
};

static int sa_get(int fd, uint32_t daddr, uint8_t dir, struct sa_info *info)
{
	struct nlmsghdr *nh;
	char reply[4096] = {};
	struct xfrm_usersa_info *p;
	const struct nlattr *nla;
	struct xfrm_usersa_id *id;
	struct nlreq r;
	int ret;

	nlreq_init(&r, XFRM_MSG_GETSA);
	id = nlreq_put(&r, sizeof(*id));
	sa_id_fill(id, daddr);
	nlreq_dir(&r, dir);

	ret = nl_talk(fd, &r, reply, sizeof(reply));
	if (ret)
		return ret;

	nh = (struct nlmsghdr *)reply;
	if (nh->nlmsg_type != XFRM_MSG_NEWSA)
		return -EBADMSG;

	p = NLMSG_DATA(nh);
	nla = nl_find_attr(nh, sizeof(*p), XFRMA_SA_DIR);
	info->dir = nla ? *((const uint8_t *)nla + NLA_HDRLEN) : 0;
	info->reqid = p->reqid;
	info->soft_pkts = p->lft.soft_packet_limit;
	info->packets = p->curlft.packets;
	return 0;
}

static int sa_del(int fd, uint32_t daddr, uint8_t dir)
{
	struct xfrm_usersa_id *id;
	struct nlreq r;

	nlreq_init(&r, XFRM_MSG_DELSA);
	id = nlreq_put(&r, sizeof(*id));
	sa_id_fill(id, daddr);
	nlreq_dir(&r, dir);

	return nl_talk(fd, &r, NULL, 0);
}

static int sa_flush(int fd)
{
	struct xfrm_usersa_flush *f;
	struct nlreq r;

	nlreq_init(&r, XFRM_MSG_FLUSHSA);
	f = nlreq_put(&r, sizeof(*f));
	f->proto = IPPROTO_ESP;

	return nl_talk(fd, &r, NULL, 0);
}

static int ae_get_reqid(int fd, uint8_t dir, int *reqid)
{
	char reply[4096] = {};
	struct xfrm_aevent_id *ae;
	struct nlreq r;
	int ret;

	nlreq_init(&r, XFRM_MSG_GETAE);
	ae = nlreq_put(&r, sizeof(*ae));
	sa_id_fill(&ae->sa_id, ADDR1);
	nlreq_dir(&r, dir);

	ret = nl_talk(fd, &r, reply, sizeof(reply));
	if (ret)
		return ret;

	ae = NLMSG_DATA((struct nlmsghdr *)reply);
	*reqid = ae->reqid;
	return 0;
}

static int ae_set_packets(int fd, uint8_t dir, uint64_t packets)
{
	struct xfrm_lifetime_cur lt = { .packets = packets };
	struct xfrm_aevent_id *ae;
	struct nlreq r;

	nlreq_init(&r, XFRM_MSG_NEWAE);
	r.nh.nlmsg_flags |= NLM_F_REPLACE;
	ae = nlreq_put(&r, sizeof(*ae));
	sa_id_fill(&ae->sa_id, ADDR1);
	nlreq_attr(&r, XFRMA_LTIME_VAL, &lt, sizeof(lt));
	nlreq_dir(&r, dir);

	return nl_talk(fd, &r, NULL, 0);
}

static int spi_alloc(int fd, uint8_t dir, uint32_t seq)
{
	struct xfrm_userspi_info *p;
	struct nlreq r;

	nlreq_init(&r, XFRM_MSG_ALLOCSPI);
	p = nlreq_put(&r, sizeof(*p));
	xid_fill(&p->info.id, ADDR1);
	p->info.saddr.a4 = htonl(INADDR_LOOPBACK);
	p->info.family = AF_INET;
	p->info.mode = XFRM_MODE_TRANSPORT;
	p->info.seq = seq;
	p->min = SPI;
	p->max = SPI;
	nlreq_dir(&r, dir);

	return nl_talk(fd, &r, NULL, 0);
}

static int sa_expire(int fd, uint8_t dir)
{
	struct xfrm_user_expire *ue;
	struct nlreq r;

	nlreq_init(&r, XFRM_MSG_EXPIRE);
	ue = nlreq_put(&r, sizeof(*ue));
	xid_fill(&ue->state.id, ADDR1);
	ue->state.family = AF_INET;
	ue->hard = 1;
	nlreq_dir(&r, dir);

	return nl_talk(fd, &r, NULL, 0);
}

static int sa_migrate(int fd, uint8_t dir, uint32_t new_daddr,
		      uint32_t reqid)
{
	struct xfrm_user_migrate_state *um;
	struct nlreq r;

	nlreq_init(&r, XFRM_MSG_MIGRATE_STATE);
	um = nlreq_put(&r, sizeof(*um));
	sa_id_fill(&um->id, ADDR1);
	um->new_daddr.a4 = htonl(new_daddr);
	um->new_saddr.a4 = htonl(INADDR_LOOPBACK);
	um->new_family = AF_INET;
	um->new_reqid = reqid;
	um->new_sel.family = AF_INET;
	nlreq_dir(&r, dir);

	return nl_talk(fd, &r, NULL, 0);
}

/* A transport mode ESP policy for the UDP test traffic. */
static int pol_add(int fd, uint8_t dir, uint32_t reqid)
{
	struct xfrm_user_tmpl tmpl = {};
	struct xfrm_userpolicy_info *p;
	struct nlreq r;

	nlreq_init(&r, XFRM_MSG_NEWPOLICY);
	p = nlreq_put(&r, sizeof(*p));
	p->sel.family = AF_INET;
	p->sel.daddr.a4 = htonl(INADDR_LOOPBACK);
	p->sel.saddr.a4 = htonl(INADDR_LOOPBACK);
	p->sel.prefixlen_d = 32;
	p->sel.prefixlen_s = 32;
	p->sel.proto = IPPROTO_UDP;
	p->sel.dport = htons(UDP_PORT);
	p->sel.dport_mask = 0xffff;
	p->lft.soft_byte_limit = XFRM_INF;
	p->lft.hard_byte_limit = XFRM_INF;
	p->lft.soft_packet_limit = XFRM_INF;
	p->lft.hard_packet_limit = XFRM_INF;
	p->dir = dir;
	p->action = XFRM_POLICY_ALLOW;
	p->share = XFRM_SHARE_ANY;

	tmpl.id.proto = IPPROTO_ESP;
	tmpl.family = AF_INET;
	tmpl.reqid = reqid;
	tmpl.mode = XFRM_MODE_TRANSPORT;
	tmpl.aalgos = ~0;
	tmpl.ealgos = ~0;
	tmpl.calgos = ~0;
	nlreq_attr(&r, XFRMA_TMPL, &tmpl, sizeof(tmpl));

	return nl_talk(fd, &r, NULL, 0);
}

/* A key manager: without one, the output path starts no acquire. */
static int acquire_listener(void)
{
	struct sockaddr_nl addr = {
		.nl_family = AF_NETLINK,
		.nl_groups = 1 << (XFRMNLGRP_ACQUIRE - 1),
	};
	struct timeval tv = { .tv_sec = 2 };
	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_XFRM);
	if (fd < 0)
		return -1;
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) ||
	    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv))) {
		close(fd);
		return -1;
	}
	return fd;
}

static uint32_t acquire_seq(int fd)
{
	struct nlmsghdr *nh;
	char buf[4096];
	ssize_t n;

	n = recv(fd, buf, sizeof(buf), 0);
	if (n < 0)
		return 0;

	for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, n); nh = NLMSG_NEXT(nh, n)) {
		if (nh->nlmsg_type == XFRM_MSG_ACQUIRE)
			return ((struct xfrm_user_acquire *)NLMSG_DATA(nh))->seq;
	}
	return 0;
}

/* Returns the counter from /proc/net/xfrm_stat, or -1 when unavailable. */
static long xfrm_counter(const char *name)
{
	char key[64];
	long val, ret = -1;
	FILE *f;

	f = fopen("/proc/net/xfrm_stat", "r");
	if (!f)
		return -1;
	while (fscanf(f, "%63s %ld", key, &val) == 2) {
		if (!strcmp(key, name)) {
			ret = val;
			break;
		}
	}
	fclose(f);
	return ret;
}

static int write_str(const char *path, const char *val)
{
	int fd, ret = 0;

	fd = open(path, O_WRONLY);
	if (fd < 0)
		return -errno;
	if (write(fd, val, strlen(val)) < 0)
		ret = -errno;
	close(fd);
	return ret;
}

FIXTURE(xfrm_sa_dir)
{
	int fd;
};

FIXTURE_SETUP(xfrm_sa_dir)
{
	struct timeval tv = { .tv_sec = 5 };
	struct ifreq ifr = {};
	int s;

	if (unshare(CLONE_NEWNET))
		SKIP(return, "unshare(CLONE_NEWNET): %s", strerror(errno));

	self->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_XFRM);
	if (self->fd < 0)
		SKIP(return, "NETLINK_XFRM socket: %s", strerror(errno));

	/* An unexpected failure must not hang the test. */
	setsockopt(self->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	s = socket(AF_INET, SOCK_DGRAM, 0);
	ASSERT_GE(s, 0);
	strcpy(ifr.ifr_name, "lo");
	ASSERT_EQ(0, ioctl(s, SIOCGIFFLAGS, &ifr));
	ifr.ifr_flags |= IFF_UP;
	ASSERT_EQ(0, ioctl(s, SIOCSIFFLAGS, &ifr));
	close(s);

	/* Loopback skips IPsec unless asked to do it. */
	ASSERT_EQ(0, write_str("/proc/sys/net/ipv4/conf/all/disable_xfrm", "0"));
	ASSERT_EQ(0, write_str("/proc/sys/net/ipv4/conf/all/disable_policy", "0"));
	ASSERT_EQ(0, write_str("/proc/sys/net/ipv4/conf/lo/disable_xfrm", "0"));
	ASSERT_EQ(0, write_str("/proc/sys/net/ipv4/conf/lo/disable_policy", "0"));
}

FIXTURE_TEARDOWN(xfrm_sa_dir)
{
	close(self->fd);
}

TEST_F(xfrm_sa_dir, duplicates)
{
	static const struct {
		uint8_t first, second;
		int expect;
	} cases[] = {
		{ DIR_NONE, DIR_NONE, -EEXIST },
		{ DIR_NONE, DIR_IN,   -EEXIST },
		{ DIR_NONE, DIR_OUT,  -EEXIST },
		{ DIR_IN,   DIR_NONE, -EEXIST },
		{ DIR_IN,   DIR_IN,   -EEXIST },
		{ DIR_IN,   DIR_OUT,  0 },
		{ DIR_OUT,  DIR_NONE, -EEXIST },
		{ DIR_OUT,  DIR_IN,   0 },
		{ DIR_OUT,  DIR_OUT,  -EEXIST },
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		TH_LOG("first dir %d, second dir %d", cases[i].first,
		       cases[i].second);
		ASSERT_EQ(0, sa_add(self->fd, XFRM_MSG_NEWSA, ADDR1,
				    cases[i].first, 1, XFRM_INF));
		EXPECT_EQ(cases[i].expect,
			  sa_add(self->fd, XFRM_MSG_NEWSA, ADDR1,
				 cases[i].second, 2, XFRM_INF));
		ASSERT_EQ(0, sa_flush(self->fd));
	}
}

TEST_F(xfrm_sa_dir, get_by_dir)
{
	struct sa_info info;

	ASSERT_EQ(0, sa_add(self->fd, XFRM_MSG_NEWSA, ADDR1, DIR_IN, 1, XFRM_INF));
	ASSERT_EQ(0, sa_add(self->fd, XFRM_MSG_NEWSA, ADDR1, DIR_OUT, 2, XFRM_INF));

	ASSERT_EQ(0, sa_get(self->fd, ADDR1, DIR_IN, &info));
	EXPECT_EQ(DIR_IN, info.dir);
	EXPECT_EQ(1, info.reqid);

	ASSERT_EQ(0, sa_get(self->fd, ADDR1, DIR_OUT, &info));
	EXPECT_EQ(DIR_OUT, info.dir);
	EXPECT_EQ(2, info.reqid);

	/* Without a direction, either state may answer. */
	EXPECT_EQ(0, sa_get(self->fd, ADDR1, DIR_NONE, &info));
}

TEST_F(xfrm_sa_dir, get_dir_mismatch)
{
	struct sa_info info;

	ASSERT_EQ(0, sa_add(self->fd, XFRM_MSG_NEWSA, ADDR1, DIR_OUT, 1, XFRM_INF));

	EXPECT_EQ(-ESRCH, sa_get(self->fd, ADDR1, DIR_IN, &info));
	EXPECT_EQ(0, sa_get(self->fd, ADDR1, DIR_OUT, &info));
	EXPECT_EQ(0, sa_get(self->fd, ADDR1, DIR_NONE, &info));

	/* A state without a direction matches either one. */
	ASSERT_EQ(0, sa_flush(self->fd));
	ASSERT_EQ(0, sa_add(self->fd, XFRM_MSG_NEWSA, ADDR1, DIR_NONE, 1, XFRM_INF));
	EXPECT_EQ(0, sa_get(self->fd, ADDR1, DIR_IN, &info));
	EXPECT_EQ(0, sa_get(self->fd, ADDR1, DIR_OUT, &info));
}

TEST_F(xfrm_sa_dir, delete_by_dir)
{
	struct sa_info info;

	ASSERT_EQ(0, sa_add(self->fd, XFRM_MSG_NEWSA, ADDR1, DIR_IN, 1, XFRM_INF));
	ASSERT_EQ(0, sa_add(self->fd, XFRM_MSG_NEWSA, ADDR1, DIR_OUT, 2, XFRM_INF));

	ASSERT_EQ(0, sa_del(self->fd, ADDR1, DIR_IN));
	EXPECT_EQ(-ESRCH, sa_get(self->fd, ADDR1, DIR_IN, &info));
	ASSERT_EQ(0, sa_get(self->fd, ADDR1, DIR_OUT, &info));
	EXPECT_EQ(2, info.reqid);
	EXPECT_EQ(-ESRCH, sa_del(self->fd, ADDR1, DIR_IN));

	ASSERT_EQ(0, sa_del(self->fd, ADDR1, DIR_OUT));
	EXPECT_EQ(-ESRCH, sa_get(self->fd, ADDR1, DIR_NONE, &info));
}

TEST_F(xfrm_sa_dir, delete_without_dir)
{
	struct sa_info info;

	ASSERT_EQ(0, sa_add(self->fd, XFRM_MSG_NEWSA, ADDR1, DIR_IN, 1, XFRM_INF));
	ASSERT_EQ(0, sa_add(self->fd, XFRM_MSG_NEWSA, ADDR1, DIR_OUT, 2, XFRM_INF));

	/* Exactly one of the two goes away. */
	ASSERT_EQ(0, sa_del(self->fd, ADDR1, DIR_NONE));
	ASSERT_EQ(0, sa_get(self->fd, ADDR1, DIR_NONE, &info));
	ASSERT_EQ(0, sa_del(self->fd, ADDR1, DIR_NONE));
	EXPECT_EQ(-ESRCH, sa_get(self->fd, ADDR1, DIR_NONE, &info));
}

TEST_F(xfrm_sa_dir, update_by_dir)
{
	struct sa_info info;

	ASSERT_EQ(0, sa_add(self->fd, XFRM_MSG_NEWSA, ADDR1, DIR_IN, 1, 100));
	ASSERT_EQ(0, sa_add(self->fd, XFRM_MSG_NEWSA, ADDR1, DIR_OUT, 2, 100));

	ASSERT_EQ(0, sa_add(self->fd, XFRM_MSG_UPDSA, ADDR1, DIR_IN, 1, 7));
	ASSERT_EQ(0, sa_get(self->fd, ADDR1, DIR_IN, &info));
	EXPECT_EQ(7, info.soft_pkts);
	ASSERT_EQ(0, sa_get(self->fd, ADDR1, DIR_OUT, &info));
	EXPECT_EQ(100, info.soft_pkts);

	ASSERT_EQ(0, sa_add(self->fd, XFRM_MSG_UPDSA, ADDR1, DIR_OUT, 2, 9));
	ASSERT_EQ(0, sa_get(self->fd, ADDR1, DIR_OUT, &info));
	EXPECT_EQ(9, info.soft_pkts);
	ASSERT_EQ(0, sa_get(self->fd, ADDR1, DIR_IN, &info));
	EXPECT_EQ(7, info.soft_pkts);

	/* A state with the wrong direction is not an update target. */
	ASSERT_EQ(0, sa_del(self->fd, ADDR1, DIR_IN));
	EXPECT_EQ(-ESRCH, sa_add(self->fd, XFRM_MSG_UPDSA, ADDR1, DIR_IN, 1, 5));
}

TEST_F(xfrm_sa_dir, get_ae_by_dir)
{
	int reqid;

	ASSERT_EQ(0, sa_add(self->fd, XFRM_MSG_NEWSA, ADDR1, DIR_IN, 1, XFRM_INF));
	ASSERT_EQ(0, sa_add(self->fd, XFRM_MSG_NEWSA, ADDR1, DIR_OUT, 2, XFRM_INF));

	ASSERT_EQ(0, ae_get_reqid(self->fd, DIR_IN, &reqid));
	EXPECT_EQ(1, reqid);
	ASSERT_EQ(0, ae_get_reqid(self->fd, DIR_OUT, &reqid));
	EXPECT_EQ(2, reqid);
}

TEST_F(xfrm_sa_dir, set_ae_by_dir)
{
	struct sa_info info;

	ASSERT_EQ(0, sa_add(self->fd, XFRM_MSG_NEWSA, ADDR1, DIR_IN, 1, XFRM_INF));
	ASSERT_EQ(0, sa_add(self->fd, XFRM_MSG_NEWSA, ADDR1, DIR_OUT, 2, XFRM_INF));

	ASSERT_EQ(0, ae_set_packets(self->fd, DIR_IN, 42));
	ASSERT_EQ(0, sa_get(self->fd, ADDR1, DIR_IN, &info));
	EXPECT_EQ(42, info.packets);
	ASSERT_EQ(0, sa_get(self->fd, ADDR1, DIR_OUT, &info));
	EXPECT_EQ(0, info.packets);

	ASSERT_EQ(0, ae_set_packets(self->fd, DIR_OUT, 7));
	ASSERT_EQ(0, sa_get(self->fd, ADDR1, DIR_OUT, &info));
	EXPECT_EQ(7, info.packets);
	ASSERT_EQ(0, sa_get(self->fd, ADDR1, DIR_IN, &info));
	EXPECT_EQ(42, info.packets);
}

TEST_F(xfrm_sa_dir, allocspi_dir)
{
	struct sockaddr_in dst = {
		.sin_family = AF_INET,
		.sin_port = htons(UDP_PORT),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	struct sa_info info;
	uint32_t seq;
	int acq, tx;

	acq = acquire_listener();
	ASSERT_GE(acq, 0);
	ASSERT_EQ(0, pol_add(self->fd, XFRM_POLICY_OUT, 1));

	/* Sending without a state makes the kernel add an output SA and ask. */
	tx = socket(AF_INET, SOCK_DGRAM, 0);
	ASSERT_GE(tx, 0);
	sendto(tx, "ping", 4, 0, (struct sockaddr *)&dst, sizeof(dst));
	close(tx);
	seq = acquire_seq(acq);
	ASSERT_NE(0U, seq);

	/* The key manager takes it as the input SA for the SPI it allocates. */
	ASSERT_EQ(0, spi_alloc(self->fd, DIR_IN, seq));
	ASSERT_EQ(0, sa_get(self->fd, ADDR1, DIR_IN, &info));
	EXPECT_EQ(DIR_IN, info.dir);

	/* The direction of an SA that has an SPI does not change. */
	ASSERT_EQ(0, spi_alloc(self->fd, DIR_OUT, seq));
	ASSERT_EQ(0, sa_get(self->fd, ADDR1, DIR_IN, &info));
	EXPECT_EQ(DIR_IN, info.dir);
	EXPECT_EQ(-ESRCH, sa_get(self->fd, ADDR1, DIR_OUT, &info));

	/* An output state may still share its ID. */
	ASSERT_EQ(0, sa_add(self->fd, XFRM_MSG_NEWSA, ADDR1, DIR_OUT, 2, XFRM_INF));
	ASSERT_EQ(0, sa_get(self->fd, ADDR1, DIR_OUT, &info));
	EXPECT_EQ(2, info.reqid);
	close(acq);
}

TEST_F(xfrm_sa_dir, expire_by_dir)
{
	struct sa_info info;

	ASSERT_EQ(0, sa_add(self->fd, XFRM_MSG_NEWSA, ADDR1, DIR_IN, 1, XFRM_INF));
	ASSERT_EQ(0, sa_add(self->fd, XFRM_MSG_NEWSA, ADDR1, DIR_OUT, 2, XFRM_INF));

	/* The input state is the older one, and the second in the hash. */
	ASSERT_EQ(0, sa_expire(self->fd, DIR_IN));
	EXPECT_EQ(-ESRCH, sa_get(self->fd, ADDR1, DIR_IN, &info));
	ASSERT_EQ(0, sa_get(self->fd, ADDR1, DIR_OUT, &info));
	EXPECT_EQ(2, info.reqid);
}

TEST_F(xfrm_sa_dir, migrate_by_dir)
{
	struct sa_info info;
	int ret;

	/* The input state is the newer one. */
	ASSERT_EQ(0, sa_add(self->fd, XFRM_MSG_NEWSA, ADDR1, DIR_OUT, 2, XFRM_INF));
	ASSERT_EQ(0, sa_add(self->fd, XFRM_MSG_NEWSA, ADDR1, DIR_IN, 1, XFRM_INF));
	/* An output state holds the target of the migrations below. */
	ASSERT_EQ(0, sa_add(self->fd, XFRM_MSG_NEWSA, ADDR2, DIR_OUT, 3, XFRM_INF));

	ret = sa_migrate(self->fd, DIR_OUT, ADDR2, 2);
	if (ret == -ENOPROTOOPT)
		SKIP(return, "XFRM_MSG_MIGRATE_STATE is not supported");

	/* The output state is not the first match, and its target is taken. */
	EXPECT_EQ(-EEXIST, ret);

	/* The target is held by a state of the other direction only. */
	ASSERT_EQ(0, sa_migrate(self->fd, DIR_IN, ADDR2, 1));
	ASSERT_EQ(0, sa_get(self->fd, ADDR2, DIR_IN, &info));
	EXPECT_EQ(1, info.reqid);
	EXPECT_EQ(-ESRCH, sa_get(self->fd, ADDR1, DIR_IN, &info));
	ASSERT_EQ(0, sa_get(self->fd, ADDR1, DIR_OUT, &info));
	EXPECT_EQ(2, info.reqid);
	ASSERT_EQ(0, sa_get(self->fd, ADDR2, DIR_OUT, &info));
	EXPECT_EQ(3, info.reqid);
}

/* Send one datagram through the policies, and wait for it. */
static int udp_ping(void)
{
	struct sockaddr_in dst = {
		.sin_family = AF_INET,
		.sin_port = htons(UDP_PORT),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	struct timeval tv = { .tv_usec = 300000 };
	int rx, tx, ret = -1;
	char buf[8];

	rx = socket(AF_INET, SOCK_DGRAM, 0);
	tx = socket(AF_INET, SOCK_DGRAM, 0);
	if (rx < 0 || tx < 0)
		goto out;
	if (bind(rx, (struct sockaddr *)&dst, sizeof(dst)))
		goto out;
	setsockopt(rx, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	if (sendto(tx, "ping", 4, 0, (struct sockaddr *)&dst, sizeof(dst)) != 4) {
		ret = -errno;
		goto out;
	}
	ret = recv(rx, buf, sizeof(buf), 0) == 4 ? 0 : -EAGAIN;
out:
	if (rx >= 0)
		close(rx);
	if (tx >= 0)
		close(tx);
	return ret;
}

/* Both states are used on one host, so they share their ID. */
static bool have_xfrm_stat(void)
{
	return xfrm_counter("XfrmInStateDirError") >= 0;
}

static void loopback_pair(struct __test_metadata *_metadata, int fd,
			  uint8_t first, uint8_t second, uint32_t out_saddr)
{
	struct sa_info info;

	ASSERT_EQ(0, pol_add(fd, XFRM_POLICY_OUT, 1));
	ASSERT_EQ(0, pol_add(fd, XFRM_POLICY_IN, 1));
	ASSERT_EQ(0, sa_add_saddr(fd, XFRM_MSG_NEWSA, ADDR1,
				  first == DIR_OUT ? out_saddr : INADDR_LOOPBACK,
				  first, 1, XFRM_INF));
	ASSERT_EQ(0, sa_add_saddr(fd, XFRM_MSG_NEWSA, ADDR1,
				  second == DIR_OUT ? out_saddr : INADDR_LOOPBACK,
				  second, 1, XFRM_INF));

	EXPECT_EQ(0, udp_ping());
	EXPECT_EQ(0, xfrm_counter("XfrmInStateDirError"));
	EXPECT_EQ(0, xfrm_counter("XfrmOutStateDirError"));

	/* Each state saw its own direction of the same datagram. */
	ASSERT_EQ(0, sa_get(fd, ADDR1, DIR_IN, &info));
	EXPECT_EQ(1, info.packets);
	ASSERT_EQ(0, sa_get(fd, ADDR1, DIR_OUT, &info));
	EXPECT_EQ(1, info.packets);
}

/* The newer state is the output one. */
TEST_F(xfrm_sa_dir, loopback_pair_input_first)
{
	if (!have_xfrm_stat())
		SKIP(return, "/proc/net/xfrm_stat is not available");

	loopback_pair(_metadata, self->fd, DIR_IN, DIR_OUT, INADDR_LOOPBACK);
}

/* The newer state is the input one. */
TEST_F(xfrm_sa_dir, loopback_pair_output_first)
{
	if (!have_xfrm_stat())
		SKIP(return, "/proc/net/xfrm_stat is not available");

	loopback_pair(_metadata, self->fd, DIR_OUT, DIR_IN, INADDR_LOOPBACK);
}

/* The input state matches the source address exactly, the output one not. */
TEST_F(xfrm_sa_dir, loopback_pair_wildcard_saddr)
{
	if (!have_xfrm_stat())
		SKIP(return, "/proc/net/xfrm_stat is not available");

	loopback_pair(_metadata, self->fd, DIR_OUT, DIR_IN, INADDR_ANY);
}

/* A single state without a direction serves both directions. */
TEST_F(xfrm_sa_dir, loopback_no_direction)
{
	struct sa_info info;

	if (!have_xfrm_stat())
		SKIP(return, "/proc/net/xfrm_stat is not available");

	ASSERT_EQ(0, pol_add(self->fd, XFRM_POLICY_OUT, 1));
	ASSERT_EQ(0, pol_add(self->fd, XFRM_POLICY_IN, 1));
	ASSERT_EQ(0, sa_add(self->fd, XFRM_MSG_NEWSA, ADDR1, DIR_NONE, 1, XFRM_INF));

	EXPECT_EQ(0, udp_ping());
	EXPECT_EQ(0, xfrm_counter("XfrmInStateDirError"));
	EXPECT_EQ(0, xfrm_counter("XfrmOutStateDirError"));

	ASSERT_EQ(0, sa_get(self->fd, ADDR1, DIR_NONE, &info));
	EXPECT_EQ(2, info.packets);
}

/* An output state alone cannot receive: still a direction error. */
TEST_F(xfrm_sa_dir, input_dir_error)
{
	long before;

	if (!have_xfrm_stat())
		SKIP(return, "/proc/net/xfrm_stat is not available");

	ASSERT_EQ(0, pol_add(self->fd, XFRM_POLICY_OUT, 1));
	ASSERT_EQ(0, pol_add(self->fd, XFRM_POLICY_IN, 1));
	ASSERT_EQ(0, sa_add(self->fd, XFRM_MSG_NEWSA, ADDR1, DIR_OUT, 1, XFRM_INF));

	before = xfrm_counter("XfrmInStateDirError");
	EXPECT_EQ(-EAGAIN, udp_ping());
	EXPECT_GT(xfrm_counter("XfrmInStateDirError"), before);
	EXPECT_EQ(0, xfrm_counter("XfrmInNoStates"));
}

/*
 * An input state alone cannot send: still a direction error. An output state
 * with the same ID is used as soon as it exists.
 */
TEST_F(xfrm_sa_dir, output_dir_error)
{
	long before, after;

	if (!have_xfrm_stat())
		SKIP(return, "/proc/net/xfrm_stat is not available");

	ASSERT_EQ(0, pol_add(self->fd, XFRM_POLICY_OUT, 1));
	ASSERT_EQ(0, pol_add(self->fd, XFRM_POLICY_IN, 1));
	ASSERT_EQ(0, sa_add(self->fd, XFRM_MSG_NEWSA, ADDR1, DIR_IN, 1, XFRM_INF));

	before = xfrm_counter("XfrmOutStateDirError");
	EXPECT_NE(0, udp_ping());
	after = xfrm_counter("XfrmOutStateDirError");
	EXPECT_GT(after, before);

	ASSERT_EQ(0, sa_add(self->fd, XFRM_MSG_NEWSA, ADDR1, DIR_OUT, 1, XFRM_INF));
	EXPECT_EQ(0, udp_ping());
	EXPECT_EQ(after, xfrm_counter("XfrmOutStateDirError"));
}

TEST_HARNESS_MAIN
