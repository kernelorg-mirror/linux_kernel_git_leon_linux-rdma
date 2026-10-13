// SPDX-License-Identifier: GPL-2.0

#include <linux/hmm.h>
#include <linux/mmu_notifier.h>

#ifdef CONFIG_INFINIBAND_ON_DEMAND_PAGING
__rust_helper struct page *rust_helper_hmm_pfn_to_page(unsigned long pfn)
{
	return hmm_pfn_to_page(pfn);
}
#endif
