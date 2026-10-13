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

__rust_helper void rust_helper_kfree_skb(struct sk_buff *skb)
{
	kfree_skb(skb);
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
