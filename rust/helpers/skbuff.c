// SPDX-License-Identifier: GPL-2.0

#include <linux/skbuff.h>
#include <net/dst.h>

#ifdef CONFIG_RUST_SKBUFF_KUNIT_TEST
__rust_helper struct sk_buff *rust_helper_skb_test_page(void)
{
	unsigned long address = __get_free_page(GFP_KERNEL);
	struct sk_buff *skb;

	if (!address)
		return NULL;
	skb = build_skb((void *)address, PAGE_SIZE);
	if (!skb)
		free_page(address);
	return skb;
}
__rust_helper void rust_helper_skb_test_trim(struct sk_buff *skb, unsigned int len)
{
	skb_trim(skb, len);
}
#endif

__rust_helper bool rust_helper_pskb_may_pull(struct sk_buff *skb, unsigned int len)
{
	return pskb_may_pull(skb, len);
}

__rust_helper bool rust_helper_skb_dst_force(struct sk_buff *skb)
{
	return skb_dst_force(skb);
}

__rust_helper void rust_helper_skb_drop_receive_dst(struct sk_buff *skb)
{
	skb_dst_drop(skb);
}

__rust_helper unsigned char *rust_helper_skb_network_header(const struct sk_buff *skb)
{
	return skb_network_header(skb);
}

__rust_helper __be16 rust_helper_skb_protocol_field(const struct sk_buff *skb)
{
	return skb->protocol;
}

__rust_helper void rust_helper_kfree_skb(struct sk_buff *skb)
{
	kfree_skb(skb);
}

__rust_helper void rust_helper_skb_queue_head_init(struct sk_buff_head *list)
{
	skb_queue_head_init(list);
}

__rust_helper int rust_helper_skb_linearize(struct sk_buff *skb)
{
	return skb_linearize(skb);
}

__rust_helper int rust_helper_skb_linearize_private(struct sk_buff *skb)
{
	int ret;

	/* Page-backed heads may be shared by skb_zerocopy() without cloning. */
	if (skb->head_frag) {
		ret = pskb_expand_head(skb, 0, skb->data_len, GFP_ATOMIC);
		if (ret)
			return ret;
	}
	return skb_linearize_cow(skb);
}

__rust_helper void rust_helper_skb_set_mac_header(struct sk_buff *skb, int offset)
{
	skb_set_mac_header(skb, offset);
}

__rust_helper u8 rust_helper_skb_metadata_len(const struct sk_buff *skb)
{
	return skb_metadata_len(skb);
}

__rust_helper void *rust_helper_skb_metadata_end(const struct sk_buff *skb)
{
	return skb_metadata_end(skb);
}

__rust_helper struct sk_buff *rust_helper_alloc_skb(unsigned int size, gfp_t flags)
{
	return alloc_skb(size, flags);
}

__rust_helper void rust_helper_skb_reserve(struct sk_buff *skb, int len)
{
	skb_reserve(skb, len);
}

__rust_helper struct skb_shared_info *rust_helper_skb_shinfo(struct sk_buff *skb)
{
	return skb_shinfo(skb);
}

__rust_helper void rust_helper_skb_dst_set(struct sk_buff *skb, struct dst_entry *dst)
{
	skb_dst_set(skb, dst);
}

__rust_helper struct dst_entry *rust_helper_skb_dst(const struct sk_buff *skb)
{
	return skb_dst(skb);
}

__rust_helper void rust_helper_skb_clear_hash(struct sk_buff *skb)
{
	skb_clear_hash(skb);
}

__rust_helper void rust_helper_skb_reset_network_header(struct sk_buff *skb)
{
	skb_reset_network_header(skb);
}

__rust_helper void rust_helper_skb_reset_transport_header(struct sk_buff *skb)
{
	skb_reset_transport_header(skb);
}

__rust_helper void rust_helper_skb_set_protocol(struct sk_buff *skb, __be16 protocol)
{
	skb->protocol = protocol;
}

__rust_helper void rust_helper_skb_orphan(struct sk_buff *skb)
{
	skb_orphan(skb);
}

__rust_helper void rust_helper_skb_dst_drop(struct sk_buff *skb)
{
	skb_dst_drop(skb);
}
