// SPDX-License-Identifier: GPL-2.0

#include <net/sock.h>
#if IS_ENABLED(CONFIG_NET_UDP_TUNNEL)
#include <net/udp.h>
#endif

#ifdef CONFIG_NET

__rust_helper void rust_helper_sock_put(struct sock *sk)
{
	sock_put(sk);
}

__rust_helper void rust_helper_sock_hold(struct sock *sk)
{
	sock_hold(sk);
}

__rust_helper void rust_helper_sk_dst_reset(struct sock *sk)
{
	sk_dst_reset(sk);
}

#ifdef CONFIG_DEBUG_LOCK_ALLOC
__rust_helper void
rust_helper_sock_lock_init_class_and_name(struct sock *sk, const char *sname,
					struct lock_class_key *skey, const char *name,
					struct lock_class_key *key)
{
	sock_lock_init_class_and_name(sk, sname, skey, name, key);
}
#endif
#endif
