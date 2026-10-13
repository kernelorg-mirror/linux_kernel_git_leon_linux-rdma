// SPDX-License-Identifier: GPL-2.0

#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <asm/shmparam.h>

__rust_helper void *__must_check __realloc_size(2)
rust_helper_vrealloc_node_align(const void *p, size_t size, unsigned long align,
				gfp_t flags, int node)
{
	return vrealloc_node_align(p, size, align, flags, node);
}

__rust_helper bool rust_helper_is_vmalloc_addr(const void *x)
{
	return is_vmalloc_addr(x);
}

__rust_helper void *rust_helper_vmalloc_user_account(unsigned long size)
{
	return __vmalloc_node_range(size, SHMLBA, VMALLOC_START, VMALLOC_END,
				    GFP_KERNEL_ACCOUNT | __GFP_ZERO, PAGE_KERNEL,
				    VM_USERMAP, NUMA_NO_NODE,
				    __builtin_return_address(0));
}
