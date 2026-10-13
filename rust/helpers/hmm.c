// SPDX-License-Identifier: GPL-2.0

#include <linux/hmm.h>
#include <linux/mmu_notifier.h>

#ifdef CONFIG_INFINIBAND_ON_DEMAND_PAGING
__rust_helper struct page *rust_helper_hmm_pfn_to_page(unsigned long pfn)
{
	return hmm_pfn_to_page(pfn);
}

__rust_helper bool
rust_helper_mmu_notifier_range_blockable(const struct mmu_notifier_range *range)
{
	return mmu_notifier_range_blockable(range);
}

__rust_helper void
rust_helper_mmu_interval_set_seq(struct mmu_interval_notifier *mni,
				unsigned long seq)
{
	mmu_interval_set_seq(mni, seq);
}
#endif
