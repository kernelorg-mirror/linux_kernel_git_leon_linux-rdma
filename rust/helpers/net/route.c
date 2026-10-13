// SPDX-License-Identifier: GPL-2.0

#if IS_ENABLED(CONFIG_INET)
#include <net/route.h>
#include <net/ip6_route.h>

__rust_helper void rust_helper_sock_flow_init(const struct sock *sk,
					    struct flowi_common *flow)
{
	flow->flowic_uid = sk_uid(sk);
	security_sk_classify_flow(sk, flow);
}

__rust_helper struct rtable *
rust_helper_ip_route_output_key(struct net *net, struct flowi4 *flow)
{
	return ip_route_output_key(net, flow);
}

__rust_helper void rust_helper_dst_hold(struct dst_entry *dst)
{
	dst_hold(dst);
}

__rust_helper struct dst_entry *
rust_helper_dst_check(struct dst_entry *dst, u32 cookie)
{
	return dst_check(dst, cookie);
}

#if IS_ENABLED(CONFIG_IPV6)
__rust_helper u32 rust_helper_rt6_get_cookie(const struct rt6_info *rt)
{
	return rt6_get_cookie(rt);
}
#endif
#endif
