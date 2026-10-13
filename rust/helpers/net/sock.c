// SPDX-License-Identifier: GPL-2.0

#include <net/sock.h>
#if IS_ENABLED(CONFIG_NET_UDP_TUNNEL)
#include <net/udp.h>
#include <net/ipv6.h>
#include <linux/inetdevice.h>
#include <net/addrconf.h>
#include <net/ip.h>
#include <net/ip_fib.h>
#include <net/ip6_route.h>
#include <net/l3mdev.h>
#ifdef CONFIG_RUST_UDP_TUNNEL_KUNIT_TEST
#include <net/tcp.h>
#endif
#endif

#ifdef CONFIG_NET
#if IS_ENABLED(CONFIG_NET_UDP_TUNNEL)
/* The caller excludes configuration changes after binding has completed. */
__rust_helper bool rust_helper_udp_tunnel_sock_matches(struct sock *sk,
						     unsigned short family,
						     __be16 port)
{
	if (sk->sk_family != family || !sk->sk_kern_sock ||
	    inet_sk(sk)->inet_sport != port || sk->sk_dport ||
	    sk->sk_state != TCP_CLOSE || sk->sk_bound_dev_if)
		return false;

	if (family == AF_INET)
		return !inet_sk(sk)->inet_rcv_saddr;
#if IS_ENABLED(CONFIG_IPV6)
	if (family == AF_INET6)
		return sk->sk_ipv6only && ipv6_addr_any(&sk->sk_v6_rcv_saddr);
#endif
	return false;
}

/* The UDP receive path leaves tunnel GSO packets for the tunnel to segment. */
__rust_helper void
rust_helper_udp_tunnel_receive_segments(struct sock *sk, struct sk_buff *skb,
				       void (*receive)(struct sk_buff *))
{
	struct sk_buff *segs, *next;

	if (!skb_is_gso(skb)) {
		skb_mark_not_on_list(skb);
		receive(skb);
		return;
	}

	BUILD_BUG_ON(sizeof(struct udp_skb_cb) > SKB_GSO_CB_OFFSET);
	__skb_push(skb, -skb_mac_offset(skb));
	segs = udp_rcv_segment(sk, skb, skb->protocol == htons(ETH_P_IP));
	skb_list_walk_safe(segs, skb, next) {
		__skb_pull(skb, skb_transport_offset(skb));
		udp_post_segment_fix_csum(skb);
		skb_mark_not_on_list(skb);
		receive(skb);
	}
}

/* Receive runs under RCU, with a validated IP header and retained device. */
__rust_helper void rust_helper_udp_tunnel_resolve_loopback(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	struct net_device *local = NULL;
	struct net *net;

	if (!dev || (!(dev->flags & IFF_LOOPBACK) &&
		     !netif_is_l3_master(dev)))
		return;
	net = dev_net(dev);
	if (netif_is_l3_master(dev)) {
		int iif = 0;

		if (skb->protocol == htons(ETH_P_IP))
			iif = inet_sdif(skb);
#if IS_ENABLED(CONFIG_IPV6)
		else if (skb->protocol == htons(ETH_P_IPV6))
			iif = inet6_sdif(skb);
#endif
		/* VRF receive preserves the original ingress in the IP control
		 * block. A destination on another slave must not change that
		 * ingress identity. Only local delivery through the master needs
		 * the destination lookup below.
		 */
		if (iif && iif != dev->ifindex) {
			skb->dev = dev_get_by_index_rcu(net, iif);
			return;
		}
	}
	if (skb->protocol == htons(ETH_P_IP)) {
		struct flowi4 flow = { .daddr = ip_hdr(skb)->daddr };
		struct fib_result result = {};
		struct fib_table *table;
		u32 id = l3mdev_fib_table_rcu(dev);

		/* VRF masters provide local delivery for their own routing domain.
		 * A namespace-wide address lookup can select another VRF's address.
		 */
		table = fib_get_table(net, id ? id : RT_TABLE_LOCAL);
		if (table && !fib_table_lookup(table, &flow, &result,
					       FIB_LOOKUP_NOREF) &&
		    result.type == RTN_LOCAL)
			local = FIB_RES_DEV(result);
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (skb->protocol == htons(ETH_P_IPV6)) {
		struct dst_entry *dst = skb_dst(skb);
		struct inet6_dev *idev = dst ? ip6_dst_idev(dst) : NULL;

		/* Local IPv6 routes retain the addressed interface separately from
		 * their loopback output device, preserving link-local scope.
		 * Anycast addresses are not present in the unicast address list.
		 */
		if (idev && (dst_rt6_info(dst)->rt6i_flags & RTF_ANYCAST))
			local = idev->dev;
		else
			local = ipv6_dev_find(net, &ipv6_hdr(skb)->daddr,
					      idev ? idev->dev : NULL);
	}
#endif
	if (local)
		skb->dev = local;
}

__rust_helper void rust_helper_udp_tunnel_clear_receive(struct sock *sk)
{
	WRITE_ONCE(udp_sk(sk)->encap_rcv, NULL);
}

/* The socket is closed and network receive readers have been drained. */
__rust_helper void rust_helper_udp_tunnel_clear_dst(struct sock *sk)
{
	struct dst_entry *dst;

	sk_dst_reset(sk);
	dst = unrcu_pointer(xchg(&sk->sk_rx_dst, RCU_INITIALIZER(NULL)));
	dst_release(dst);
}

#ifdef CONFIG_RUST_UDP_TUNNEL_KUNIT_TEST
struct rust_udp_segment_result {
	unsigned int count;
	unsigned int seen;
	bool invalid;
};

static DEFINE_PER_CPU(struct rust_udp_segment_result, rust_udp_segments);

static void rust_udp_test_receive_segment(struct sk_buff *skb)
{
	struct rust_udp_segment_result *result = this_cpu_ptr(&rust_udp_segments);
	const unsigned int prefix = sizeof(struct udphdr) + sizeof(struct iphdr) +
				    sizeof(struct tcphdr);
	u8 marker;

	result->count++;
	if (skb_is_gso(skb) || skb->next || skb->len != prefix + 64 ||
	    ntohs(udp_hdr(skb)->len) != skb->len ||
	    ntohs(ip_hdr(skb)->tot_len) != skb->len + sizeof(struct iphdr) ||
	    skb_copy_bits(skb, prefix, &marker, sizeof(marker)) ||
	    marker < 1 || marker > 2)
		result->invalid = true;
	else
		result->seen |= BIT(marker - 1);
	kfree_skb(skb);
}

/* Keep static fixture references outside the inline Rust helper. */
int rust_udp_tunnel_test_segments(struct sock *sk);

/* Exercise a tunnel aggregate which ordinary UDP intentionally does not split. */
int rust_udp_tunnel_test_segments(struct sock *sk)
{
	const unsigned int network = ETH_HLEN;
	const unsigned int transport = network + sizeof(struct iphdr);
	const unsigned int inner = transport + sizeof(struct udphdr);
	const unsigned int tcp_offset = inner + sizeof(struct iphdr);
	const unsigned int payload = tcp_offset + sizeof(struct tcphdr);
	const unsigned int length = payload + 128;
	struct rust_udp_segment_result *result;
	struct sk_buff *skb;
	struct iphdr *outer, *iph;
	struct tcphdr *tcp;
	struct udphdr *udp;
	int err;

	skb = alloc_skb(NET_SKB_PAD + length, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;
	skb_reserve(skb, NET_SKB_PAD);
	skb_put_zero(skb, length);
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, network);
	skb_set_transport_header(skb, transport);
	skb_set_inner_mac_header(skb, inner);
	skb_set_inner_network_header(skb, inner);
	skb_set_inner_transport_header(skb, tcp_offset);
	skb_set_inner_protocol(skb, htons(ETH_P_IP));
	skb->protocol = htons(ETH_P_IP);
	skb->mac_len = ETH_HLEN;
	skb->encapsulation = 1;
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum_start = skb_headroom(skb) + tcp_offset;
	skb->csum_offset = offsetof(struct tcphdr, check);
	skb->dev = sock_net(sk)->loopback_dev;
	eth_hdr(skb)->h_proto = skb->protocol;
	outer = ip_hdr(skb);
	outer->version = 4;
	outer->ihl = 5;
	outer->ttl = 64;
	outer->protocol = IPPROTO_UDP;
	outer->saddr = htonl(INADDR_LOOPBACK);
	outer->daddr = htonl(INADDR_LOOPBACK);
	outer->tot_len = htons(length - network);
	ip_send_check(outer);
	udp = udp_hdr(skb);
	udp->source = htons(47916);
	udp->dest = htons(47916);
	udp->len = htons(length - transport);
	iph = (void *)(skb->data + inner);
	*iph = *outer;
	iph->protocol = IPPROTO_TCP;
	iph->tot_len = htons(length - inner);
	ip_send_check(iph);
	tcp = (void *)(skb->data + tcp_offset);
	tcp->source = htons(1234);
	tcp->dest = htons(4321);
	tcp->doff = sizeof(*tcp) / 4;
	tcp->ack = 1;
	tcp->check = ~tcp_v4_check(length - tcp_offset, iph->saddr, iph->daddr, 0);
	memset(skb->data + payload, 1, 64);
	memset(skb->data + payload + 64, 2, 64);
	skb_shinfo(skb)->gso_type = SKB_GSO_UDP_TUNNEL | SKB_GSO_TCPV4;
	skb_shinfo(skb)->gso_size = 64;
	skb_shinfo(skb)->gso_segs = 2;
	__skb_pull(skb, transport);
	if (udp_unexpected_gso(sk, skb)) {
		kfree_skb(skb);
		return -EINVAL;
	}

	local_bh_disable();
	rcu_read_lock();
	result = this_cpu_ptr(&rust_udp_segments);
	memset(result, 0, sizeof(*result));
	rust_helper_udp_tunnel_receive_segments(sk, skb, rust_udp_test_receive_segment);
	err = result->count == 2 && result->seen == 3 && !result->invalid ? 0 : -EINVAL;
	rcu_read_unlock();
	local_bh_enable();
	return err;
}

__rust_helper int rust_helper_udp_tunnel_test_segments(struct sock *sk)
{
	return rust_udp_tunnel_test_segments(sk);
}

__rust_helper int rust_helper_udp_tunnel_test_queue(struct sock *sk)
{
	struct sk_buff *skb = alloc_skb(32, GFP_KERNEL);
	int ret;

	if (!skb)
		return -ENOMEM;
	skb_put_zero(skb, 32);
	skb->protocol = htons(ETH_P_IP);
	local_bh_disable();
	ret = __udp_enqueue_schedule_skb(sk, skb);
	local_bh_enable();
	if (ret)
		kfree_skb(skb);
	return ret;
}

__rust_helper bool rust_helper_udp_tunnel_test_receive_empty(struct sock *sk)
{
	return skb_queue_empty(&sk->sk_receive_queue) &&
	       skb_queue_empty(&udp_sk(sk)->reader_queue) &&
	       !atomic_read(&sk->sk_rmem_alloc) && !sk->sk_forward_alloc;
}
#endif

#if IS_ENABLED(CONFIG_IPV6)
__rust_helper int rust_helper_ip6_sock_set_v6only(struct sock *sk)
{
	return ip6_sock_set_v6only(sk);
}

__rust_helper void rust_helper_udp_set_no_check6_tx(struct sock *sk, bool val)
{
	udp_set_no_check6_tx(sk, val);
}

__rust_helper void rust_helper_udp_set_no_check6_rx(struct sock *sk, bool val)
{
	udp_set_no_check6_rx(sk, val);
}
#endif
#endif

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
