// SPDX-License-Identifier: GPL-2.0

#include <linux/gfp.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/libnvdimm.h>

__rust_helper void rust_helper_arch_wb_cache_pmem(void *addr, size_t size)
{
	arch_wb_cache_pmem(addr, size);
}

__rust_helper phys_addr_t rust_helper_page_to_phys(const struct page *page)
{
	return page_to_phys(page);
}

__rust_helper struct page *rust_helper_alloc_pages(gfp_t gfp_mask,
						   unsigned int order)
{
	return alloc_pages(gfp_mask, order);
}

__rust_helper void *rust_helper_kmap_local_page(struct page *page)
{
	return kmap_local_page(page);
}

__rust_helper void rust_helper_kunmap_local(const void *addr)
{
	kunmap_local(addr);
}

__rust_helper void rust_helper_get_page(struct page *page)
{
	get_page(page);
}

__rust_helper void rust_helper_put_page(struct page *page)
{
	put_page(page);
}

#ifndef NODE_NOT_IN_PAGE_FLAGS
__rust_helper int rust_helper_page_to_nid(const struct page *page)
{
	return page_to_nid(page);
}
#endif

__rust_helper void rust_helper_flush_dcache_page(struct page *page)
{
	flush_dcache_page(page);
}

__rust_helper bool rust_helper_is_page_hwpoison(const struct page *page)
{
	return is_page_hwpoison(page);
}
