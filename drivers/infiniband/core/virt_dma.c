// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Tracked virtual DMA for software RDMA providers. */

#include <linux/interval_tree.h>
#include <linux/libnvdimm.h>
#include <linux/refcount.h>
#include <linux/overflow.h>
#include <linux/sort.h>
#include <rdma/ib_pmem.h>
#include <rdma/ib_verbs.h>

struct ib_virt_dma {
	spinlock_t lock;
	struct rb_root tuples;
	struct rb_root_cached mappings[DMA_NONE];
};

struct virt_dma_mapping {
	struct rb_node tuple;
	struct interval_tree_node interval;
	enum dma_data_direction direction;
	refcount_t refs;
	unsigned int maps;
	bool live;
};

/* References retain mapping identities, not their backing buffers. */
struct ib_virt_dma_range {
	refcount_t refs;
	struct ib_device *dev;
	unsigned long start;
	size_t size;
	unsigned int count;
	struct virt_dma_mapping *mappings[] __counted_by(count);
};

static void virt_dma_put(struct virt_dma_mapping *mapping)
{
	if (refcount_dec_and_test(&mapping->refs))
		kfree(mapping);
}

/**
 * ib_virt_dma_enable - Track the lifetime of virtual DMA mappings
 * @dev: Unpublished software RDMA device
 *
 * Call once, before registering the device. Mappings made afterwards retain
 * their kernel virtual addresses but may fail if tracking allocation fails.
 * The DMA API caller keeps the entire buffer allocated and available for
 * device accesses in the requested direction until it unmaps the buffer.
 * Unmap synchronizes with accesses through ib_virt_dma_read/write().
 *
 * Context: Process context. The caller exclusively owns @dev.
 * Return: 0 on success or a negative errno.
 */
int ib_virt_dma_enable(struct ib_device *dev)
{
	struct ib_virt_dma *dma;
	unsigned int i;

	if (!ib_uses_virt_dma(dev) || dev->virt_dma)
		return -EINVAL;
	dma = kzalloc_obj(*dma);
	if (!dma)
		return -ENOMEM;
	spin_lock_init(&dma->lock);
	dma->tuples = RB_ROOT;
	for (i = 0; i < DMA_NONE; i++)
		dma->mappings[i] = RB_ROOT_CACHED;
	dev->virt_dma = dma;
	return 0;
}
EXPORT_SYMBOL_GPL(ib_virt_dma_enable);

/* All clients and provider accesses have drained before device release. */
void ib_virt_dma_release(struct ib_device *dev)
{
	struct ib_virt_dma *dma = dev->virt_dma;
	struct virt_dma_mapping *mapping;
	struct rb_node *node;

	if (!dma)
		return;
	WARN_ON_ONCE(!RB_EMPTY_ROOT(&dma->tuples));
	while ((node = rb_first(&dma->tuples))) {
		mapping = rb_entry(node, struct virt_dma_mapping, tuple);
		rb_erase(node, &dma->tuples);
		interval_tree_remove(&mapping->interval,
				     &dma->mappings[mapping->direction]);
		virt_dma_put(mapping);
	}
	kfree(dma);
}

/* Exact tuple lookup must not walk unrelated overlapping mappings. */
static int virt_dma_compare(const void *key, const struct rb_node *node)
{
	const struct virt_dma_mapping *a = key;
	const struct virt_dma_mapping *b;

	b = rb_entry(node, struct virt_dma_mapping, tuple);
	if (a->interval.start != b->interval.start)
		return a->interval.start < b->interval.start ? -1 : 1;
	if (a->interval.last != b->interval.last)
		return a->interval.last < b->interval.last ? -1 : 1;
	return (int)a->direction - (int)b->direction;
}

static int virt_dma_compare_nodes(struct rb_node *node,
				  const struct rb_node *other)
{
	return virt_dma_compare(rb_entry(node, struct virt_dma_mapping, tuple),
				other);
}

/**
 * ib_virt_dma_map - Track a software device's DMA mapping
 * @dev: Device owning the mapping
 * @addr: Directly addressable, physically contiguous DMA-compatible storage
 * @size: Nonzero storage size in bytes
 * @direction: Permitted direction of DMA access
 *
 * The caller must retain the backing storage until unmap, as for the native
 * DMA API. Vmalloc, stack, and temporary kmap addresses are not supported.
 *
 * Return: The virtual DMA address, or DMA_MAPPING_ERROR on failure.
 */
u64 ib_virt_dma_map(struct ib_device *dev, void *addr, size_t size,
		    enum dma_data_direction direction)
{
	struct ib_virt_dma *dma = dev->virt_dma;
	struct virt_dma_mapping *mapping;
	struct rb_node *node;
	unsigned long start = (uintptr_t)addr, last, flags;

	if (!dma)
		return start;
	if (!size || !addr || !valid_dma_direction(direction) ||
	    check_add_overflow(start, size - 1, &last))
		return DMA_MAPPING_ERROR;
	mapping = kmalloc_obj(*mapping, GFP_ATOMIC);
	if (!mapping)
		return DMA_MAPPING_ERROR;
	mapping->interval.start = start;
	mapping->interval.last = last;
	mapping->direction = direction;
	refcount_set(&mapping->refs, 1);
	mapping->maps = 1;
	mapping->live = true;
	spin_lock_irqsave(&dma->lock, flags);
	/* Unmap identifies a tuple, so equivalent live maps share an identity. */
	node = rb_find_add(&mapping->tuple, &dma->tuples, virt_dma_compare_nodes);
	if (node) {
		struct virt_dma_mapping *entry;

		entry = rb_entry(node, struct virt_dma_mapping, tuple);
		if (entry->maps == UINT_MAX) {
			spin_unlock_irqrestore(&dma->lock, flags);
			kfree(mapping);
			return DMA_MAPPING_ERROR;
		}
		entry->maps++;
		spin_unlock_irqrestore(&dma->lock, flags);
		kfree(mapping);
		return start;
	}
	interval_tree_insert(&mapping->interval, &dma->mappings[direction]);
	spin_unlock_irqrestore(&dma->lock, flags);
	return start;
}
EXPORT_SYMBOL_GPL(ib_virt_dma_map);

void ib_virt_dma_unmap(struct ib_device *dev, u64 addr, size_t size,
		       enum dma_data_direction direction)
{
	struct ib_virt_dma *dma = dev->virt_dma;
	struct virt_dma_mapping key = {}, *mapping = NULL;
	struct rb_node *node;
	unsigned long start = addr, last, flags;

	if (!dma)
		return;
	if (WARN_ON_ONCE(addr != start || !size ||
			 check_add_overflow(start, size - 1, &last)))
		return;
	key.interval.start = start;
	key.interval.last = last;
	key.direction = direction;
	spin_lock_irqsave(&dma->lock, flags);
	node = rb_find(&key, &dma->tuples, virt_dma_compare);
	if (node) {
		mapping = rb_entry(node, struct virt_dma_mapping, tuple);
		if (--mapping->maps) {
			spin_unlock_irqrestore(&dma->lock, flags);
			return;
		}
		mapping->live = false;
		rb_erase(node, &dma->tuples);
		interval_tree_remove(&mapping->interval,
				     &dma->mappings[direction]);
	}
	spin_unlock_irqrestore(&dma->lock, flags);
	if (!WARN_ON_ONCE(!mapping))
		virt_dma_put(mapping);
}
EXPORT_SYMBOL_GPL(ib_virt_dma_unmap);

int ib_dma_virt_map_sg(struct ib_device *dev, struct scatterlist *sg, int nents,
		       enum dma_data_direction direction)
{
	struct scatterlist *s;
	int i;

	for_each_sg(sg, s, nents, i) {
		sg_dma_address(s) = ib_virt_dma_map(dev, sg_virt(s), s->length,
						 direction);
		if (ib_dma_mapping_error(dev, sg_dma_address(s))) {
			ib_dma_virt_unmap_sg(dev, sg, i, direction);
			return 0;
		}
		sg_dma_len(s) = s->length;
	}
	return nents;
}
EXPORT_SYMBOL(ib_dma_virt_map_sg);

void ib_dma_virt_unmap_sg(struct ib_device *dev, struct scatterlist *sg,
			  int nents, enum dma_data_direction direction)
{
	struct scatterlist *s;
	int i;

	for_each_sg(sg, s, nents, i)
		ib_virt_dma_unmap(dev, sg_dma_address(s), sg_dma_len(s), direction);
}
EXPORT_SYMBOL_GPL(ib_dma_virt_unmap_sg);

/* Every locked pass stops at its capacity, including the counting pass. */
static int virt_dma_capture(struct ib_virt_dma *dma,
			    struct ib_virt_dma_range *range,
			    unsigned long start, unsigned long last,
			    unsigned int capacity, unsigned int *count)
{
	struct interval_tree_node *node;
	unsigned int direction;

	*count = 0;
	for (direction = 0; direction < DMA_NONE; direction++) {
		for (node = interval_tree_iter_first(&dma->mappings[direction],
						    start, last); node;
		     node = interval_tree_iter_next(node, start, last)) {
			struct virt_dma_mapping *mapping;

			if (*count == capacity)
				return capacity == IB_VIRT_DMA_MAX_CAPTURE_MAPPINGS ?
					-E2BIG : -EAGAIN;
			if (range) {
				mapping = container_of(node, struct virt_dma_mapping,
						       interval);
				refcount_inc(&mapping->refs);
				range->mappings[*count] = mapping;
			}
			(*count)++;
		}
	}
	return 0;
}

static int virt_dma_capture_compare(const void *left, const void *right)
{
	const struct virt_dma_mapping * const *a = left;
	const struct virt_dma_mapping * const *b = right;

	return ((*a)->interval.start > (*b)->interval.start) -
	       ((*a)->interval.start < (*b)->interval.start);
}

/**
 * ib_virt_dma_range_alloc - Capture mapping identities intersecting a range
 * @dev: Device with tracking enabled, retained until this call returns
 * @addr: Start of the range, possibly partially mapped
 * @size: Range size, from 1 through PAGE_SIZE
 *
 * The returned handle retains the device and the intersecting mapping records.
 * It does not keep their backing buffers mapped: the final unmap of an
 * equivalent address/size/direction tuple revokes access without waiting for
 * handles to be freed. A later mapping at the same address cannot
 * restore access through an old handle. Each operation checks its full range
 * and DMA direction while holding the lock that excludes unmap.
 *
 * At most IB_VIRT_DMA_MAX_CAPTURE_MAPPINGS distinct tuples may intersect the
 * handle. This bounds later scans even under a provider's outer IRQ lock.
 * Equivalent live maps share one tuple and do not consume extra capacity.
 * Allocation and failed-capture cleanup occur outside the mapping lock.
 *
 * Context: Process or softirq context compatible with spinlock_t on PREEMPT_RT.
 * Hardirq, raw-spinlocked and explicitly non-preemptible contexts are excluded.
 * Return: An owned handle, -E2BIG for excess capture complexity, -EAGAIN if
 * concurrent map changes exhaust bounded retries, or another error pointer.
 */
struct ib_virt_dma_range *ib_virt_dma_range_alloc(struct ib_device *dev,
					       u64 addr, size_t size)
{
	struct ib_virt_dma *dma = dev->virt_dma;
	struct ib_virt_dma_range *range;
	unsigned long start = addr, last, flags;
	unsigned int count, captured, attempt;
	int ret;

	if (!dma || addr != start || !size || size > PAGE_SIZE ||
	    check_add_overflow(start, size - 1, &last))
		return ERR_PTR(-EINVAL);
	for (attempt = 0; attempt < 3; attempt++) {
		spin_lock_irqsave(&dma->lock, flags);
		ret = virt_dma_capture(dma, NULL, start, last,
				       IB_VIRT_DMA_MAX_CAPTURE_MAPPINGS, &count);
		spin_unlock_irqrestore(&dma->lock, flags);
		if (ret)
			return ERR_PTR(ret);
		range = kmalloc(struct_size(range, mappings, count), GFP_ATOMIC);
		if (!range)
			return ERR_PTR(-ENOMEM);
		refcount_set(&range->refs, 1);
		range->dev = dev;
		range->start = start;
		range->size = size;
		range->count = count;
		get_device(&dev->dev);
		spin_lock_irqsave(&dma->lock, flags);
		ret = virt_dma_capture(dma, range, start, last, count, &captured);
		spin_unlock_irqrestore(&dma->lock, flags);
		range->count = captured;
		if (!ret) {
			/* Restore ascending start order across direction trees. */
			sort(range->mappings, captured, sizeof(*range->mappings),
			     virt_dma_capture_compare, NULL);
			return range;
		}
		ib_virt_dma_range_free(range);
		if (ret != -EAGAIN)
			return ERR_PTR(ret);
	}
	return ERR_PTR(-EAGAIN);
}
EXPORT_SYMBOL_GPL(ib_virt_dma_range_alloc);

/**
 * ib_virt_dma_range_get - Retain immutable captured mapping identities
 * @range: Live captured handle
 */
void ib_virt_dma_range_get(struct ib_virt_dma_range *range)
{
	refcount_inc(&range->refs);
}
EXPORT_SYMBOL_GPL(ib_virt_dma_range_get);

/**
 * ib_virt_dma_range_free - Release a captured range after its users have drained
 * @range: Owned handle, or NULL
 */
void ib_virt_dma_range_free(struct ib_virt_dma_range *range)
{
	unsigned int i;

	if (!range || !refcount_dec_and_test(&range->refs))
		return;
	for (i = 0; i < range->count; i++)
		virt_dma_put(range->mappings[i]);
	put_device(&range->dev->dev);
	kfree(range);
}
EXPORT_SYMBOL_GPL(ib_virt_dma_range_free);

/*
 * Find the greatest end among intervals beginning at or before start.
 * When a node qualifies, every node in its left subtree qualifies too; the
 * augmentation summarizes that subtree without visiting its overlapping nodes.
 * Only one root-to-leaf path is visited, so each query is O(log mappings).
 */
static bool virt_dma_prefix_last(const struct rb_root_cached *root,
				 unsigned long start, unsigned long *last)
{
	struct rb_node *rb = root->rb_root.rb_node;
	bool found = false;

	while (rb) {
		struct interval_tree_node *node;

		node = rb_entry(rb, struct interval_tree_node, rb);
		if (node->start > start) {
			rb = rb->rb_left;
			continue;
		}
		*last = max(*last, node->last);
		if (rb->rb_left) {
			node = rb_entry(rb->rb_left, struct interval_tree_node, rb);
			*last = max(*last, node->__subtree_last);
		}
		found = true;
		rb = rb->rb_right;
	}
	return found;
}

static bool virt_dma_direction(enum dma_data_direction requested,
			       enum dma_data_direction mapped)
{
	return requested == DMA_NONE || mapped == DMA_BIDIRECTIONAL ||
	       requested == mapped;
}

/* Called with dma->lock held, including throughout the subsequent access. */
static bool virt_dma_covers(struct ib_virt_dma *dma,
			    const struct ib_virt_dma_range *range,
			    unsigned long start,
			    unsigned long last,
			    enum dma_data_direction direction)
{
	unsigned int i;

	if (range) {
		if (start < range->start || last - range->start >= range->size)
			return false;
		/* Capture admission bounds this scan independently of map count. */
		for (i = 0; i < range->count; i++) {
			struct virt_dma_mapping *mapping = range->mappings[i];
			struct interval_tree_node *node = &mapping->interval;

			if (!mapping->live || !virt_dma_direction(direction,
								mapping->direction))
				continue;
			if (node->start > start)
				return false;
			if (node->last >= last)
				return true;
			if (node->last >= start)
				start = node->last + 1;
		}
		return false;
	}
	for (;;) {
		unsigned long covered = 0;
		bool found = false;

		for (i = 0; i < DMA_NONE; i++) {
			if (virt_dma_direction(direction, i))
				found |= virt_dma_prefix_last(&dma->mappings[i],
							      start, &covered);
		}
		if (!found || covered < start)
			return false;
		if (covered >= last)
			return true;
		/* Each query covers another byte: at most PAGE_SIZE iterations. */
		start = covered + 1;
	}
}

/*
 * DMA mappings can include padding or bytes not initialized by their owner.
 * Materialize their object representation through opaque register outputs so
 * copying to Rust storage does not propagate LLVM undef values. This does not
 * relieve DMA clients of initializing data before exposing it to a peer.
 */
static void virt_dma_copy_from(void *dst, const void *src, size_t size)
{
	while (size >= sizeof(unsigned long)) {
		unsigned long value;

		memcpy(&value, src, sizeof(value));
		OPTIMIZER_HIDE_VAR(value);
		memcpy(dst, &value, sizeof(value));
		dst += sizeof(value);
		src += sizeof(value);
		size -= sizeof(value);
	}
	while (size--) {
		unsigned char value = *(const unsigned char *)src++;

		OPTIMIZER_HIDE_VAR(value);
		*(unsigned char *)dst++ = value;
	}
}

static int virt_dma_copy(struct ib_device *dev,
			 const struct ib_virt_dma_range *range, u64 addr, void *buf,
			 size_t size, enum dma_data_direction direction)
{
	struct ib_virt_dma *dma = dev->virt_dma;
	unsigned long start = addr, last, flags;
	int ret = -EFAULT;

	/* Bound byte work and the number of advancing coverage queries. */
	if (size > PAGE_SIZE)
		return -EINVAL;
	if (!size)
		return 0;
	if (!dma || addr != start ||
	    check_add_overflow(start, size - 1, &last))
		return -EFAULT;
	spin_lock_irqsave(&dma->lock, flags);
	if (virt_dma_covers(dma, range, start, last, direction)) {
		if (direction == DMA_TO_DEVICE)
			virt_dma_copy_from(buf, (void *)start, size);
		else
			memcpy((void *)start, buf, size);
		ret = 0;
	}
	spin_unlock_irqrestore(&dma->lock, flags);
	return ret;
}

/**
 * ib_virt_dma_read - Copy bytes from a live virtual DMA mapping
 * @dev: Device with virtual DMA tracking enabled
 * @addr: Virtual DMA address, which may be untrusted
 * @buf: Writable kernel buffer, disjoint from the mapped range
 * @size: Number of bytes to copy, at most PAGE_SIZE
 *
 * The entire range must be mapped for DMA_TO_DEVICE or DMA_BIDIRECTIONAL.
 * The mapping lock keeps the backing live throughout the copy: a concurrent
 * unmap cannot return and allow the DMA API caller to free the buffer yet.
 * No reference or pointer into the mapping is returned to the provider.
 * Copied bytes are materialized values even if the DMA caller left some
 * mapped storage uninitialized. The caller remains responsible for disclosure.
 *
 * Return: 0 on success or a negative errno. On error @buf is unchanged.
 */
int ib_virt_dma_read(struct ib_device *dev, u64 addr, void *buf, size_t size)
{
	return virt_dma_copy(dev, NULL, addr, buf, size, DMA_TO_DEVICE);
}
EXPORT_SYMBOL_GPL(ib_virt_dma_read);

/**
 * ib_virt_dma_write - Copy bytes to a live virtual DMA mapping
 * @dev: Device with virtual DMA tracking enabled
 * @addr: Virtual DMA address, which may be untrusted
 * @buf: Readable kernel buffer, disjoint from the mapped range
 * @size: Number of bytes to copy, at most PAGE_SIZE
 *
 * The range must be mapped for DMA_FROM_DEVICE or DMA_BIDIRECTIONAL.
 * Mapping lifetime and locking follow ib_virt_dma_read().
 *
 * Return: 0 on success or a negative errno. On error the range is unchanged.
 */
int ib_virt_dma_write(struct ib_device *dev, u64 addr, const void *buf,
		      size_t size)
{
	return virt_dma_copy(dev, NULL, addr, (void *)buf, size, DMA_FROM_DEVICE);
}
EXPORT_SYMBOL_GPL(ib_virt_dma_write);

static int virt_dma_atomic(struct ib_device *dev,
			   const struct ib_virt_dma_range *range, u64 addr,
		       enum ib_virt_dma_atomic_op op, u64 compare, u64 value,
		       u64 *original)
{
	struct ib_virt_dma *dma = dev->virt_dma;
	unsigned long start = addr, flags;
	enum dma_data_direction direction;
	atomic64_t *ptr = (void *)start;
	int ret = -EFAULT;

	if (op != IB_VIRT_DMA_CMP_SWAP && op != IB_VIRT_DMA_FETCH_ADD &&
	    op != IB_VIRT_DMA_WRITE)
		return -EINVAL;
	if (addr & (sizeof(u64) - 1))
		return -EINVAL;
	if (!dma || addr != start)
		return -EFAULT;
	direction = op == IB_VIRT_DMA_WRITE ? DMA_FROM_DEVICE : DMA_BIDIRECTIONAL;
	spin_lock_irqsave(&dma->lock, flags);
	if (virt_dma_covers(dma, range, start, start + sizeof(u64) - 1, direction)) {
		if (op == IB_VIRT_DMA_WRITE) {
			/* Publish the value after earlier provider memory accesses. */
			atomic64_set_release(ptr, value);
			*original = 0;
		} else if (op == IB_VIRT_DMA_FETCH_ADD) {
			*original = atomic64_fetch_add(value, ptr);
		} else {
			*original = atomic64_cmpxchg(ptr, compare, value);
		}
		/* Generic atomic64 implementations need the same output boundary. */
		OPTIMIZER_HIDE_VAR(*original);
		ret = 0;
	}
	spin_unlock_irqrestore(&dma->lock, flags);
	return ret;
}
/**
 * ib_virt_dma_atomic - Access an aligned 64-bit virtual DMA location
 * @dev: Device with virtual DMA tracking enabled
 * @addr: Virtual DMA address, which may be untrusted
 * @op: Atomic operation to perform
 * @compare: Comparison value for IB_VIRT_DMA_CMP_SWAP
 * @value: Replacement value or addend
 * @original: Writable result storage, disjoint from the mapped range
 *
 * Read-modify-write requires DMA_BIDIRECTIONAL; atomic write also accepts
 * DMA_FROM_DEVICE. The mapping lock retains the backing while kernel atomic
 * primitives serialize aliases accessed through other memory interfaces.
 * Atomic write uses release ordering.
 *
 * Return: 0 on success or a negative errno. On error memory is unchanged.
 */
int ib_virt_dma_atomic(struct ib_device *dev, u64 addr,
		       enum ib_virt_dma_atomic_op op, u64 compare, u64 value,
		       u64 *original)
{
	return virt_dma_atomic(dev, NULL, addr, op, compare, value, original);
}
EXPORT_SYMBOL_GPL(ib_virt_dma_atomic);

/* Validate before adding an offset supplied by a provider or remote peer. */
static bool virt_dma_range_valid(const struct ib_virt_dma_range *range,
				size_t offset, size_t size)
{
	return offset <= range->size && size <= range->size - offset;
}

int ib_virt_dma_range_read(const struct ib_virt_dma_range *range, size_t offset,
			   void *buf, size_t size)
{
	if (!virt_dma_range_valid(range, offset, size))
		return -EFAULT;
	return virt_dma_copy(range->dev, range, range->start + offset, buf,
			     size, DMA_TO_DEVICE);
}
EXPORT_SYMBOL_GPL(ib_virt_dma_range_read);

int ib_virt_dma_range_write(const struct ib_virt_dma_range *range, size_t offset,
			    const void *buf, size_t size)
{
	if (!virt_dma_range_valid(range, offset, size))
		return -EFAULT;
	return virt_dma_copy(range->dev, range, range->start + offset,
			     (void *)buf, size, DMA_FROM_DEVICE);
}
EXPORT_SYMBOL_GPL(ib_virt_dma_range_write);

int ib_virt_dma_range_atomic(const struct ib_virt_dma_range *range, size_t offset,
			     enum ib_virt_dma_atomic_op op, u64 compare,
			     u64 value, u64 *original)
{
	if (!virt_dma_range_valid(range, offset, sizeof(u64)))
		return -EFAULT;
	return virt_dma_atomic(range->dev, range, range->start + offset, op,
			       compare, value, original);
}
EXPORT_SYMBOL_GPL(ib_virt_dma_range_atomic);

int ib_virt_dma_range_flush(const struct ib_virt_dma_range *range, size_t offset,
			    size_t size)
{
	struct ib_virt_dma *dma = range->dev->virt_dma;
	unsigned long start, flags;
	int ret = -EFAULT;

	if (!virt_dma_range_valid(range, offset, size))
		return -EFAULT;
	if (!size)
		return 0;
	start = range->start + offset;
	spin_lock_irqsave(&dma->lock, flags);
	if (virt_dma_covers(dma, range, start, start + size - 1, DMA_NONE)) {
		if (!IS_ENABLED(CONFIG_ARCH_HAS_PMEM_API)) {
			ret = -EOPNOTSUPP;
		} else {
			arch_wb_cache_pmem((void *)start, size);
			/* Complete writeback before unmap can release the backing. */
			wmb();
			ret = 0;
		}
	}
	spin_unlock_irqrestore(&dma->lock, flags);
	return ret;
}
EXPORT_SYMBOL_GPL(ib_virt_dma_range_flush);

bool ib_virt_dma_range_is_persistent(const struct ib_virt_dma_range *range,
				     size_t offset, size_t size)
{
	struct ib_virt_dma *dma = range->dev->virt_dma;
	unsigned long start, flags;
	bool persistent = false;

	if (!virt_dma_range_valid(range, offset, size))
		return false;
	if (!size)
		return true;
	start = range->start + offset;
	spin_lock_irqsave(&dma->lock, flags);
	persistent = virt_dma_covers(dma, range, start, start + size - 1, DMA_NONE);
	spin_unlock_irqrestore(&dma->lock, flags);
	if (!persistent)
		return false;

	/* This examines resource metadata, not backing bytes. Even if unmap
	 * revokes the capture, its immutable direct-map address still identifies
	 * the same physical interval. Recheck live coverage after the lookup.
	 * resource_lock must never nest under an IRQ-safe mapping lock.
	 */
	if (!ib_pmem_range(virt_to_phys((void *)start), size))
		return false;
	spin_lock_irqsave(&dma->lock, flags);
	persistent = virt_dma_covers(dma, range, start, start + size - 1, DMA_NONE);
	spin_unlock_irqrestore(&dma->lock, flags);
	return persistent;
}
EXPORT_SYMBOL_GPL(ib_virt_dma_range_is_persistent);
