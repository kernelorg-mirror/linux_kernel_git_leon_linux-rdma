// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <net/dst.h>
#include <net/netns/generic.h>
#include <net/udp_tunnel.h>
#include <rdma/ib_verbs.h>

#include "rxe_net.h"
#include "rxe_ns.h"

/* The namespace and each attached RXE device own one allocation reference. */
struct rxe_ns_sock {
	struct mutex lock;
	refcount_t refs;
	unsigned int users;
	bool dead;
	struct sock __rcu *sk4;
	struct sock __rcu *sk6;
};

static unsigned int rxe_pernet_id;

static struct rxe_ns_sock *rxe_ns(struct net *net)
{
	return *(struct rxe_ns_sock **)net_generic(net, rxe_pernet_id);
}

static void rxe_ns_put(struct rxe_ns_sock *ns)
{
	if (refcount_dec_and_test(&ns->refs)) {
		mutex_destroy(&ns->lock);
		kfree(ns);
	}
}

static void rxe_ns_clear_dst(struct sock *sk)
{
	struct dst_entry *dst;

	if (!sk)
		return;
	sk_dst_reset(sk);
	dst = unrcu_pointer(xchg(&sk->sk_rx_dst, RCU_INITIALIZER(NULL)));
	dst_release(dst);
	sock_put(sk);
}

/* Called with ns->lock held while namespace services remain live. */
static void rxe_ns_close(struct rxe_ns_sock *ns)
{
	struct sock *sk4 = rcu_dereference_protected(ns->sk4,
						 lockdep_is_held(&ns->lock));
	struct sock *sk6 = rcu_dereference_protected(ns->sk6,
						 lockdep_is_held(&ns->lock));

	RCU_INIT_POINTER(ns->sk4, NULL);
	RCU_INIT_POINTER(ns->sk6, NULL);
	if (sk4) {
		sock_hold(sk4);
		udp_tunnel_sock_release(sk4);
	}
	if (sk6) {
		sock_hold(sk6);
		udp_tunnel_sock_release(sk6);
	}
	/* Drain socket lookups and receive-side destination cache updates. */
	synchronize_net();
	rxe_ns_clear_dst(sk4);
	rxe_ns_clear_dst(sk6);
}

/* The caller keeps net active until this function returns. */
struct rxe_ns_sock *rxe_ns_get(struct net *net)
{
	struct rxe_ns_sock *ns = rxe_ns(net);
	struct socket *sock;
	int err;

	mutex_lock(&ns->lock);
	if (ns->dead) {
		err = -ENETDOWN;
		goto err_unlock;
	}
	if (ns->users)
		goto found;

	sock = rxe_setup_udp_tunnel(net, htons(ROCE_V2_UDP_DPORT), false);
	if (IS_ERR(sock)) {
		err = PTR_ERR(sock);
		goto err_unlock;
	}
	rcu_assign_pointer(ns->sk4, sock->sk);
#if IS_ENABLED(CONFIG_IPV6)
	sock = rxe_setup_udp_tunnel(net, htons(ROCE_V2_UDP_DPORT), true);
	if (IS_ERR(sock)) {
		err = PTR_ERR(sock);
		if (err != -EAFNOSUPPORT)
			goto err_close;
	} else {
		rcu_assign_pointer(ns->sk6, sock->sk);
	}
#endif
found:
	ns->users++;
	refcount_inc(&ns->refs);
	mutex_unlock(&ns->lock);
	return ns;

#if IS_ENABLED(CONFIG_IPV6)
err_close:
	rxe_ns_close(ns);
#endif
err_unlock:
	mutex_unlock(&ns->lock);
	return ERR_PTR(err);
}

void rxe_ns_release(struct rxe_ns_sock *ns)
{
	mutex_lock(&ns->lock);
	if (!--ns->users && !ns->dead)
		rxe_ns_close(ns);
	mutex_unlock(&ns->lock);
	rxe_ns_put(ns);
}

#if IS_ENABLED(CONFIG_IPV6)
/* Returns an owned reference; the namespace must remain active. */
struct sock *rxe_ns_pernet_sk6(struct net *net)
{
	struct sock *sk;

	rcu_read_lock();
	sk = rcu_dereference(rxe_ns(net)->sk6);
	if (sk && !refcount_inc_not_zero(&sk->sk_refcnt))
		sk = NULL;
	rcu_read_unlock();
	return sk;
}
#endif

static int rxe_ns_init(struct net *net)
{
	struct rxe_ns_sock *ns;

	ns = kzalloc_obj(*ns, GFP_KERNEL_ACCOUNT);
	if (!ns)
		return -ENOMEM;
	mutex_init(&ns->lock);
	refcount_set(&ns->refs, 1);
	*(struct rxe_ns_sock **)net_generic(net, rxe_pernet_id) = ns;
	return 0;
}

static void rxe_ns_exit(struct net *net)
{
	struct rxe_ns_sock *ns = rxe_ns(net);

	mutex_lock(&ns->lock);
	ns->dead = true;
	rxe_ns_close(ns);
	mutex_unlock(&ns->lock);
	rxe_ns_put(ns);
}

static struct pernet_operations rxe_net_ops = {
	.init = rxe_ns_init,
	.exit = rxe_ns_exit,
	.id = &rxe_pernet_id,
	.size = sizeof(struct rxe_ns_sock *),
};

int rxe_namespace_init(void)
{
	return register_pernet_subsys(&rxe_net_ops);
}

void rxe_namespace_exit(void)
{
	unregister_pernet_subsys(&rxe_net_ops);
}
