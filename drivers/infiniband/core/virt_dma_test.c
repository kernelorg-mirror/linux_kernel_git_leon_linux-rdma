// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
#include <kunit/test.h>
#include <linux/kthread.h>
#include <linux/sched/task.h>
#include <rdma/ib_pmem.h>
#include <rdma/ib_verbs.h>

struct virt_dma_test {
	struct ib_device *dev;
	u8 data[64] __aligned(8);
	struct {
		u64 addr;
		size_t size;
		enum dma_data_direction direction;
	} mappings[IB_VIRT_DMA_MAX_CAPTURE_MAPPINGS + 8];
	unsigned int count;
};

static int virt_dma_test_init(struct kunit *test)
{
	struct virt_dma_test *ctx;
	int ret;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;
	ctx->dev = _ib_alloc_device(sizeof(*ctx->dev), &init_net);
	if (!ctx->dev)
		return -ENOMEM;
	ret = ib_virt_dma_enable(ctx->dev);
	if (ret) {
		ib_dealloc_device(ctx->dev);
		return ret;
	}
	test->priv = ctx;
	return 0;
}

static void virt_dma_test_unmap(struct virt_dma_test *ctx, unsigned int index)
{
	ib_dma_unmap_single(ctx->dev, ctx->mappings[index].addr,
			    ctx->mappings[index].size,
			    ctx->mappings[index].direction);
	ctx->mappings[index].size = 0;
}

static void virt_dma_test_exit(struct kunit *test)
{
	struct virt_dma_test *ctx = test->priv;
	unsigned int i;

	if (!ctx)
		return;
	for (i = 0; i < ctx->count; i++)
		if (ctx->mappings[i].size)
			virt_dma_test_unmap(ctx, i);
	ib_dealloc_device(ctx->dev);
}

static void virt_dma_test_map(struct kunit *test, size_t offset, size_t size,
			      enum dma_data_direction direction)
{
	struct virt_dma_test *ctx = test->priv;
	unsigned int index = ctx->count;
	u64 addr;

	KUNIT_ASSERT_LT(test, index, ARRAY_SIZE(ctx->mappings));
	addr = ib_dma_map_single(ctx->dev, ctx->data + offset, size, direction);
	KUNIT_ASSERT_EQ(test, ib_dma_mapping_error(ctx->dev, addr), 0);
	ctx->mappings[index].addr = addr;
	ctx->mappings[index].size = size;
	ctx->mappings[index].direction = direction;
	ctx->count++;
}

static void virt_dma_bounds(struct kunit *test)
{
	struct virt_dma_test *ctx = test->priv;
	u64 addr = (uintptr_t)ctx->data;
	u8 output[16], input[16];

	memset(input, 0xa5, sizeof(input));
	virt_dma_test_map(test, 8, 16, DMA_BIDIRECTIONAL);
	KUNIT_ASSERT_EQ(test, ctx->count, 1);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_write(ctx->dev, addr + 8, input, 16), 0);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_read(ctx->dev, addr + 8, output, 16), 0);
	KUNIT_EXPECT_MEMEQ(test, output, input, 16);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_read(ctx->dev, addr + 7, output, 16),
			-EFAULT);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_read(ctx->dev, addr + 9, output, 16),
			-EFAULT);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_read(ctx->dev, U64_MAX - 1, output, 16),
			-EFAULT);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_read(ctx->dev, addr, output, PAGE_SIZE + 1),
			-EINVAL);
	virt_dma_test_unmap(ctx, 0);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_write(ctx->dev, addr + 8, input, 16),
			-EFAULT);
	virt_dma_test_map(test, 8, 16, DMA_TO_DEVICE);
	KUNIT_ASSERT_EQ(test, ctx->count, 2);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_write(ctx->dev, addr + 8, input, 16),
			-EFAULT);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_read(ctx->dev, addr + 8, output, 16), 0);
}

static void virt_dma_read_alignment(struct kunit *test)
{
	struct virt_dma_test *ctx = test->priv;
	u64 addr = (uintptr_t)ctx->data;
	u8 output[64];
	size_t source, target, length, i;

	for (i = 0; i < sizeof(ctx->data); i++)
		ctx->data[i] = i + 1;
	virt_dma_test_map(test, 0, sizeof(ctx->data), DMA_TO_DEVICE);
	KUNIT_ASSERT_EQ(test, ctx->count, 1);
	for (source = 0; source < sizeof(unsigned long); source++) {
		for (target = 0; target < sizeof(unsigned long); target++) {
			for (length = 0; length <= 3 * sizeof(unsigned long); length++) {
				memset(output, 0xa5, sizeof(output));
				KUNIT_ASSERT_EQ(test, ib_virt_dma_read(ctx->dev,
					addr + source, output + target, length), 0);
				for (i = 0; i < sizeof(output); i++)
					KUNIT_EXPECT_EQ(test, output[i],
						i >= target && i - target < length ?
						ctx->data[source + i - target] : (u8)0xa5);
			}
		}
	}
}

static void virt_dma_directions(struct kunit *test)
{
	struct virt_dma_test *ctx = test->priv;
	u64 addr = (uintptr_t)ctx->data;
	u8 bytes[8] = {};

	virt_dma_test_map(test, 0, 8, DMA_TO_DEVICE);
	virt_dma_test_map(test, 8, 8, DMA_FROM_DEVICE);
	KUNIT_ASSERT_EQ(test, ctx->count, 2);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_read(ctx->dev, addr, bytes, 8), 0);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_write(ctx->dev, addr, bytes, 8), -EFAULT);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_write(ctx->dev, addr + 8, bytes, 8), 0);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_read(ctx->dev, addr + 8, bytes, 8), -EFAULT);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_read(ctx->dev, addr + 4, bytes, 8), -EFAULT);
}

static void virt_dma_overlaps(struct kunit *test)
{
	struct virt_dma_test *ctx = test->priv;
	u64 addr = (uintptr_t)ctx->data;
	u8 bytes[32] = {};

	virt_dma_test_map(test, 0, 16, DMA_BIDIRECTIONAL);
	virt_dma_test_map(test, 0, 16, DMA_BIDIRECTIONAL);
	virt_dma_test_map(test, 8, 16, DMA_BIDIRECTIONAL);
	virt_dma_test_map(test, 24, 8, DMA_BIDIRECTIONAL);
	KUNIT_ASSERT_EQ(test, ctx->count, 4);
	virt_dma_test_unmap(ctx, 0);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_read(ctx->dev, addr, bytes, 32), 0);
	virt_dma_test_unmap(ctx, 1);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_read(ctx->dev, addr, bytes, 32), -EFAULT);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_read(ctx->dev, addr + 8, bytes, 24), 0);
	virt_dma_test_unmap(ctx, 2);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_read(ctx->dev, addr + 8, bytes, 24), -EFAULT);
}

static void virt_dma_scatterlist(struct kunit *test)
{
	struct virt_dma_test *ctx = test->priv;
	struct scatterlist sg[3];
	struct sg_table table = { .sgl = sg, .orig_nents = 3 };
	u64 addr = (uintptr_t)ctx->data;
	u8 bytes[32] = {};
	int ret;

	sg_init_table(sg, 3);
	sg_set_buf(&sg[0], ctx->data, 8);
	sg_set_buf(&sg[1], ctx->data + 8, 8);
	sg_set_buf(&sg[2], ctx->data + 16, 16);
	ret = ib_dma_map_sgtable_attrs(ctx->dev, &table, DMA_BIDIRECTIONAL, 0);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, table.nents, 3);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_write(ctx->dev, addr, bytes, 32), 0);
	ib_dma_unmap_sgtable_attrs(ctx->dev, &table, DMA_BIDIRECTIONAL, 0);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_read(ctx->dev, addr, bytes, 32), -EFAULT);

	/* A failed element must roll back earlier mappings in the list. */
	sg_set_buf(&sg[2], ctx->data + 16, 0);
	ret = ib_dma_map_sg(ctx->dev, sg, 3, DMA_TO_DEVICE);
	KUNIT_EXPECT_EQ(test, ret, 0);
	if (ret)
		ib_dma_unmap_sg(ctx->dev, sg, 3, DMA_TO_DEVICE);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_read(ctx->dev, addr, bytes, 8), -EFAULT);
}

static void virt_dma_atomics(struct kunit *test)
{
	struct virt_dma_test *ctx = test->priv;
	u64 addr = (uintptr_t)ctx->data;
	u64 original = 0, value = 7;

	virt_dma_test_map(test, 0, 8, DMA_BIDIRECTIONAL);
	KUNIT_ASSERT_EQ(test, ctx->count, 1);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_write(ctx->dev, addr, &value, 8), 0);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_atomic(ctx->dev, addr,
		IB_VIRT_DMA_CMP_SWAP, 7, 19, &original), 0);
	KUNIT_EXPECT_EQ(test, original, 7);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_atomic(ctx->dev, addr,
		IB_VIRT_DMA_CMP_SWAP, 7, 23, &original), 0);
	KUNIT_EXPECT_EQ(test, original, 19);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_atomic(ctx->dev, addr,
		IB_VIRT_DMA_FETCH_ADD, 0, U64_MAX, &original), 0);
	KUNIT_EXPECT_EQ(test, original, 19);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_read(ctx->dev, addr, &value, 8), 0);
	KUNIT_EXPECT_EQ(test, value, 18);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_atomic(ctx->dev, addr + 1,
		IB_VIRT_DMA_WRITE, 0, 0, &original), -EINVAL);
	virt_dma_test_unmap(ctx, 0);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_atomic(ctx->dev, addr,
		IB_VIRT_DMA_FETCH_ADD, 0, 1, &original), -EFAULT);
	virt_dma_test_map(test, 0, 8, DMA_FROM_DEVICE);
	KUNIT_ASSERT_EQ(test, ctx->count, 2);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_atomic(ctx->dev, addr,
		IB_VIRT_DMA_CMP_SWAP, 18, 23, &original), -EFAULT);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_atomic(ctx->dev, addr,
		IB_VIRT_DMA_WRITE, 0, 29, &original), 0);
	KUNIT_EXPECT_MEMEQ(test, ctx->data, &(u64){ 29 }, sizeof(u64));
}

static void virt_dma_page_and_bvec(struct kunit *test)
{
	struct virt_dma_test *ctx = test->priv;
	struct page *page = virt_to_page(ctx->data);
	struct bio_vec bvec;
	u64 addr;
	u8 bytes[8] = {};

	addr = ib_dma_map_page(ctx->dev, page, offset_in_page(ctx->data),
			       sizeof(bytes), DMA_BIDIRECTIONAL);
	KUNIT_ASSERT_EQ(test, ib_dma_mapping_error(ctx->dev, addr), 0);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_write(ctx->dev, addr, bytes, 8), 0);
	ib_dma_unmap_page(ctx->dev, addr, sizeof(bytes), DMA_BIDIRECTIONAL);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_read(ctx->dev, addr, bytes, 8), -EFAULT);
	bvec_set_page(&bvec, page, sizeof(bytes), offset_in_page(ctx->data));
	addr = ib_dma_map_bvec(ctx->dev, &bvec, DMA_TO_DEVICE);
	KUNIT_ASSERT_EQ(test, ib_dma_mapping_error(ctx->dev, addr), 0);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_read(ctx->dev, addr, bytes, 8), 0);
	ib_dma_unmap_bvec(ctx->dev, addr, sizeof(bytes), DMA_TO_DEVICE);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_read(ctx->dev, addr, bytes, 8), -EFAULT);
}

struct virt_dma_atomic_race {
	struct ib_device *dev;
	u64 addr;
	struct completion started;
};

#define VIRT_DMA_ATOMIC_ITERATIONS 100000

static int virt_dma_atomic_thread(void *data)
{
	struct virt_dma_atomic_race *race = data;
	u64 original;
	int i, ret;

	complete(&race->started);
	for (i = 0; i < VIRT_DMA_ATOMIC_ITERATIONS; i++) {
		ret = ib_virt_dma_atomic(race->dev, race->addr,
					IB_VIRT_DMA_FETCH_ADD, 0, 1, &original);
		if (ret)
			return ret;
	}
	return 0;
}

static void virt_dma_atomic_alias(struct kunit *test)
{
	struct virt_dma_test *ctx = test->priv;
	struct virt_dma_atomic_race race = {
		.dev = ctx->dev,
		.addr = (uintptr_t)ctx->data,
	};
	struct task_struct *thread;
	u64 value = 0;
	int i, ret;

	virt_dma_test_map(test, 0, sizeof(value), DMA_BIDIRECTIONAL);
	KUNIT_ASSERT_EQ(test, ctx->count, 1);
	init_completion(&race.started);
	thread = kthread_create(virt_dma_atomic_thread, &race, "virt_dma_atomic");
	KUNIT_ASSERT_FALSE(test, IS_ERR(thread));
	/* Retain the task even if it exits before kthread_stop(). */
	get_task_struct(thread);
	wake_up_process(thread);
	wait_for_completion(&race.started);
	for (i = 0; i < VIRT_DMA_ATOMIC_ITERATIONS; i++)
		atomic64_inc((atomic64_t *)ctx->data);
	ret = kthread_stop(thread);
	put_task_struct(thread);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_read(ctx->dev, race.addr, &value, 8), 0);
	KUNIT_EXPECT_EQ(test, value, 2 * VIRT_DMA_ATOMIC_ITERATIONS);
}

static void virt_dma_range_release(void *data)
{
	ib_virt_dma_range_free(data);
}

static struct ib_virt_dma_range *virt_dma_test_range(struct kunit *test,
						   size_t offset, size_t size)
{
	struct virt_dma_test *ctx = test->priv;
	struct ib_virt_dma_range *range;

	range = ib_virt_dma_range_alloc(ctx->dev, (uintptr_t)ctx->data + offset,
				       size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, range);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test,
				virt_dma_range_release, range), 0);
	return range;
}

static void virt_dma_range_duplicates(struct kunit *test)
{
	struct virt_dma_test *ctx = test->priv;
	struct ib_virt_dma_range *range;
	u8 bytes[16] = {};

	virt_dma_test_map(test, 8, sizeof(bytes), DMA_BIDIRECTIONAL);
	KUNIT_ASSERT_EQ(test, ctx->count, 1);
	range = virt_dma_test_range(test, 8, sizeof(bytes));
	virt_dma_test_map(test, 8, sizeof(bytes), DMA_BIDIRECTIONAL);
	KUNIT_ASSERT_EQ(test, ctx->count, 2);
	/* Unmapping the newer equivalent tuple must not revoke the capture. */
	virt_dma_test_unmap(ctx, 1);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_range_read(range, 0, bytes,
						  sizeof(bytes)), 0);
	virt_dma_test_unmap(ctx, 0);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_range_read(range, 0, bytes,
						  sizeof(bytes)), -EFAULT);
	/* After the final unmap, a new tuple cannot revive the old identity. */
	virt_dma_test_map(test, 8, sizeof(bytes), DMA_BIDIRECTIONAL);
	KUNIT_ASSERT_EQ(test, ctx->count, 3);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_range_read(range, 0, bytes,
						  sizeof(bytes)), -EFAULT);
}

static void virt_dma_range_references(struct kunit *test)
{
	struct virt_dma_test *ctx = test->priv;
	struct ib_virt_dma_range *range;
	u8 bytes[8] = {};

	virt_dma_test_map(test, 0, sizeof(bytes), DMA_BIDIRECTIONAL);
	range = virt_dma_test_range(test, 0, sizeof(bytes));
	ib_virt_dma_range_get(range);
	ib_virt_dma_range_free(range);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_range_read(range, 0, bytes, sizeof(bytes)), 0);
	virt_dma_test_unmap(ctx, 0);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_range_read(range, 0, bytes, sizeof(bytes)),
			-EFAULT);
}

static void virt_dma_range_revocation(struct kunit *test)
{
	struct virt_dma_test *ctx = test->priv;
	struct ib_virt_dma_range *range, *replacement;
	u8 bytes[16] = {};
	u64 original;

	virt_dma_test_map(test, 8, 16, DMA_BIDIRECTIONAL);
	KUNIT_ASSERT_EQ(test, ctx->count, 1);
	/* Unmapped ends are allowed at capture, checked at each access. */
	range = virt_dma_test_range(test, 0, 32);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_range_write(range, 8, bytes, 16), 0);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_range_read(range, 8, bytes, 16), 0);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_range_read(range, 0, bytes, 16), -EFAULT);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_range_read(range, 17, bytes, 16), -EFAULT);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_range_read(range, SIZE_MAX, bytes, 16),
			-EFAULT);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_range_atomic(range, 8,
		IB_VIRT_DMA_FETCH_ADD, 0, 1, &original), 0);
	KUNIT_EXPECT_EQ(test, original, 0);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_range_atomic(range, 9,
		IB_VIRT_DMA_WRITE, 0, 1, &original), -EINVAL);
	virt_dma_test_unmap(ctx, 0);
	virt_dma_test_map(test, 8, 16, DMA_BIDIRECTIONAL);
	KUNIT_ASSERT_EQ(test, ctx->count, 2);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_range_write(range, 8, bytes, 16), -EFAULT);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_range_read(range, 8, bytes, 16), -EFAULT);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_range_flush(range, 8, 16), -EFAULT);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_range_atomic(range, 8,
		IB_VIRT_DMA_FETCH_ADD, 0, 1, &original), -EFAULT);
	replacement = virt_dma_test_range(test, 8, 16);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_range_write(replacement, 0, bytes, 16), 0);
}

static void virt_dma_range_coverage(struct kunit *test)
{
	struct virt_dma_test *ctx = test->priv;
	struct ib_virt_dma_range *range;
	u8 bytes[32] = {};
	u64 original;

	virt_dma_test_map(test, 0, 8, DMA_TO_DEVICE);
	virt_dma_test_map(test, 8, 8, DMA_BIDIRECTIONAL);
	virt_dma_test_map(test, 8, 8, DMA_BIDIRECTIONAL);
	virt_dma_test_map(test, 24, 8, DMA_FROM_DEVICE);
	KUNIT_ASSERT_EQ(test, ctx->count, 4);
	range = virt_dma_test_range(test, 0, 32);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_range_read(range, 0, bytes, 16), 0);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_range_write(range, 0, bytes, 16), -EFAULT);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_range_atomic(range, 0,
		IB_VIRT_DMA_FETCH_ADD, 0, 1, &original), -EFAULT);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_range_atomic(range, 24,
		IB_VIRT_DMA_WRITE, 0, 1, &original), 0);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_range_read(range, 0, bytes, 32), -EFAULT);
	virt_dma_test_map(test, 16, 16, DMA_BIDIRECTIONAL);
	KUNIT_ASSERT_EQ(test, ctx->count, 5);
	/* A mapping added after capture cannot fill the original hole. */
	KUNIT_EXPECT_EQ(test, ib_virt_dma_range_read(range, 0, bytes, 32), -EFAULT);
	virt_dma_test_unmap(ctx, 1);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_range_read(range, 0, bytes, 16), 0);
	virt_dma_test_unmap(ctx, 2);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_range_read(range, 0, bytes, 16), -EFAULT);
}

static void virt_dma_capture_limit(struct kunit *test)
{
	struct virt_dma_test *ctx = test->priv;
	struct ib_virt_dma_range *range, *duplicate, *excess;
	const unsigned int limit = IB_VIRT_DMA_MAX_CAPTURE_MAPPINGS;
	u64 addr = (uintptr_t)ctx->data;
	u8 bytes[sizeof(ctx->data)] = {};
	unsigned int i;

	virt_dma_test_map(test, 0, sizeof(ctx->data), DMA_BIDIRECTIONAL);
	for (i = 0; i < limit - 1; i++) {
		virt_dma_test_map(test, i % 8, i / 8 + 1, DMA_BIDIRECTIONAL);
		KUNIT_ASSERT_EQ(test, ctx->count, i + 2);
	}
	range = virt_dma_test_range(test, 0, sizeof(ctx->data));
	/* Equivalent maps share an identity even at the admission boundary. */
	virt_dma_test_map(test, 0, sizeof(ctx->data), DMA_BIDIRECTIONAL);
	KUNIT_ASSERT_EQ(test, ctx->count, limit + 1);
	duplicate = virt_dma_test_range(test, 0, sizeof(ctx->data));
	virt_dma_test_unmap(ctx, 0);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_range_read(duplicate, 0, bytes,
						  sizeof(bytes)), 0);

	i = limit - 1;
	virt_dma_test_map(test, i % 8, i / 8 + 1, DMA_BIDIRECTIONAL);
	KUNIT_ASSERT_EQ(test, ctx->count, limit + 2);
	excess = ib_virt_dma_range_alloc(ctx->dev, addr, sizeof(ctx->data));
	KUNIT_EXPECT_TRUE(test, IS_ERR(excess));
	if (IS_ERR(excess))
		KUNIT_EXPECT_EQ(test, PTR_ERR(excess), -E2BIG);
	else
		ib_virt_dma_range_free(excess);
	/* Capture admission never limits ordinary DMA map/read/write access. */
	KUNIT_EXPECT_EQ(test, ib_virt_dma_write(ctx->dev, addr, bytes,
					    sizeof(bytes)), 0);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_read(ctx->dev, addr, bytes,
					   sizeof(bytes)), 0);
	virt_dma_test_unmap(ctx, limit);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_read(ctx->dev, addr, bytes,
					   sizeof(bytes)), -EFAULT);
	virt_dma_test_map(test, 0, sizeof(ctx->data), DMA_BIDIRECTIONAL);
	KUNIT_ASSERT_EQ(test, ctx->count, limit + 3);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_read(ctx->dev, addr, bytes,
					   sizeof(bytes)), 0);
	/* The exact-tuple index must not resurrect the old mapping incarnation. */
	KUNIT_EXPECT_EQ(test, ib_virt_dma_range_read(range, 0, bytes,
						  sizeof(bytes)), -EFAULT);
	virt_dma_test_unmap(ctx, limit + 1);
	virt_dma_test_range(test, 0, sizeof(ctx->data));
}

static void virt_dma_tuple_directions(struct kunit *test)
{
	struct virt_dma_test *ctx = test->priv;
	struct ib_virt_dma_range *range;
	u64 addr = (uintptr_t)ctx->data, original = 0;
	u8 bytes[sizeof(ctx->data)] = {};

	virt_dma_test_map(test, 0, sizeof(ctx->data), DMA_TO_DEVICE);
	virt_dma_test_map(test, 0, sizeof(ctx->data), DMA_FROM_DEVICE);
	KUNIT_ASSERT_EQ(test, ctx->count, 2);
	range = virt_dma_test_range(test, 0, sizeof(ctx->data));
	KUNIT_EXPECT_EQ(test, ib_virt_dma_read(ctx->dev, addr, bytes,
					   sizeof(bytes)), 0);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_write(ctx->dev, addr, bytes,
					    sizeof(bytes)), 0);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_atomic(ctx->dev, addr,
			IB_VIRT_DMA_FETCH_ADD, 0, 1, &original), -EFAULT);
	virt_dma_test_unmap(ctx, 0);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_read(ctx->dev, addr, bytes,
					   sizeof(bytes)), -EFAULT);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_write(ctx->dev, addr, bytes,
					    sizeof(bytes)), 0);
	virt_dma_test_map(test, 0, sizeof(ctx->data), DMA_BIDIRECTIONAL);
	KUNIT_ASSERT_EQ(test, ctx->count, 3);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_atomic(ctx->dev, addr,
			IB_VIRT_DMA_FETCH_ADD, 0, 1, &original), 0);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_range_read(range, 0, bytes,
						  sizeof(bytes)), -EFAULT);
	virt_dma_test_unmap(ctx, 2);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_read(ctx->dev, addr, bytes,
					   sizeof(bytes)), -EFAULT);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_range_write(range, 0, bytes,
						   sizeof(bytes)), 0);
}

/* Compare the augmented-tree query with an independent byte-coverage oracle. */
static void virt_dma_coverage_oracle(struct kunit *test)
{
	struct virt_dma_test *ctx = test->priv;
	u64 addr = (uintptr_t)ctx->data;
	u8 bytes[sizeof(ctx->data)] = {};
	unsigned int phase, i, offset, length, byte;

	for (i = 0; i < 32; i++) {
		offset = (i * 13) % 64;
		length = 1 + (i * 7) % (64 - offset);
		virt_dma_test_map(test, offset, length, i % DMA_NONE);
		KUNIT_ASSERT_EQ(test, ctx->count, i + 1);
	}
	for (phase = 0; phase < 2; phase++) {
		u64 readable = 0, writable = 0;

		if (phase)
			for (i = 0; i < ctx->count; i += 2)
				virt_dma_test_unmap(ctx, i);
		for (i = 0; i < ctx->count; i++) {
			offset = ctx->mappings[i].addr - addr;
			for (byte = offset; byte < offset + ctx->mappings[i].size;
			     byte++) {
				if (ctx->mappings[i].direction != DMA_FROM_DEVICE)
					readable |= BIT_ULL(byte);
				if (ctx->mappings[i].direction != DMA_TO_DEVICE)
					writable |= BIT_ULL(byte);
			}
		}
		for (offset = 0; offset < sizeof(ctx->data); offset++) {
			for (length = 1; length <= sizeof(ctx->data) - offset;
			     length++) {
				u64 mask = (U64_MAX >> (64 - length)) << offset;

				KUNIT_EXPECT_EQ(test, ib_virt_dma_read(ctx->dev,
					addr + offset, bytes, length),
					(readable & mask) == mask ? 0 : -EFAULT);
				KUNIT_EXPECT_EQ(test, ib_virt_dma_write(ctx->dev,
					addr + offset, bytes, length),
					(writable & mask) == mask ? 0 : -EFAULT);
			}
		}
	}
}

static void virt_dma_persistent_bounds(struct kunit *test)
{
	struct virt_dma_test *ctx = test->priv;
	struct ib_virt_dma_range *range;

	range = virt_dma_test_range(test, 0, 32);
	KUNIT_EXPECT_FALSE(test, ib_virt_dma_range_is_persistent(range, 0, 8));
	KUNIT_EXPECT_TRUE(test, ib_virt_dma_range_is_persistent(range, 32, 0));
	KUNIT_EXPECT_FALSE(test, ib_virt_dma_range_is_persistent(range, 33, 0));
	KUNIT_EXPECT_FALSE(test, ib_virt_dma_range_is_persistent(range, SIZE_MAX, 8));
	/* Later mappings cannot fill the holes of an existing capture. */
	virt_dma_test_map(test, 0, 32, DMA_BIDIRECTIONAL);
	KUNIT_ASSERT_EQ(test, ctx->count, 1);
	KUNIT_EXPECT_FALSE(test, ib_virt_dma_range_is_persistent(range, 0, 8));
}

static void virt_dma_flush_support(struct kunit *test)
{
	struct virt_dma_test *ctx = test->priv;
	struct ib_virt_dma_range *range;
	int expected = IS_ENABLED(CONFIG_ARCH_HAS_PMEM_API) ? 0 : -EOPNOTSUPP;

	virt_dma_test_map(test, 0, 32, DMA_BIDIRECTIONAL);
	KUNIT_ASSERT_EQ(test, ctx->count, 1);
	range = virt_dma_test_range(test, 0, 32);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_range_flush(range, 0, 32), expected);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_range_flush(range, 32, 0), 0);
	virt_dma_test_unmap(ctx, 0);
	KUNIT_EXPECT_EQ(test, ib_virt_dma_range_flush(range, 0, 32), -EFAULT);
}

static void virt_dma_persistent_resource_coverage(struct kunit *test)
{
	struct ib_pmem_walk walk = { .next = 0x1000, .end = 0x3000 };
	struct resource first = { .start = 0x1000, .end = 0x1fff };
	struct resource gap = { .start = 0x2001, .end = 0x2fff };
	struct resource adjacent = { .start = 0x2000, .end = 0x2fff };
	struct resource byte = { .start = 0x1000, .end = 0x1000 };

	KUNIT_EXPECT_EQ(test, ib_pmem_resource(&first, &walk), 0);
	KUNIT_EXPECT_LT(test, ib_pmem_resource(&gap, &walk), 0);
	KUNIT_EXPECT_EQ(test, ib_pmem_resource(&adjacent, &walk), 1);
	walk.next = 0x1000;
	walk.end = 0x1001;
	KUNIT_EXPECT_EQ(test, ib_pmem_resource(&byte, &walk), 1);
	KUNIT_EXPECT_FALSE(test, ib_pmem_range(U64_MAX, 1));
}

static struct kunit_case virt_dma_cases[] = {
	KUNIT_CASE(virt_dma_coverage_oracle),
	KUNIT_CASE(virt_dma_capture_limit),
	KUNIT_CASE(virt_dma_tuple_directions),
	KUNIT_CASE(virt_dma_persistent_bounds),
	KUNIT_CASE(virt_dma_flush_support),
	KUNIT_CASE(virt_dma_persistent_resource_coverage),
	KUNIT_CASE(virt_dma_range_duplicates),
	KUNIT_CASE(virt_dma_range_revocation),
	KUNIT_CASE(virt_dma_range_references),
	KUNIT_CASE(virt_dma_range_coverage),
	KUNIT_CASE(virt_dma_bounds),
	KUNIT_CASE(virt_dma_read_alignment),
	KUNIT_CASE(virt_dma_directions),
	KUNIT_CASE(virt_dma_overlaps),
	KUNIT_CASE(virt_dma_scatterlist),
	KUNIT_CASE(virt_dma_atomics),
	KUNIT_CASE(virt_dma_page_and_bvec),
	KUNIT_CASE(virt_dma_atomic_alias),
	{}
};

static struct kunit_suite virt_dma_suite = {
	.name = "ib_virt_dma",
	.init = virt_dma_test_init,
	.exit = virt_dma_test_exit,
	.test_cases = virt_dma_cases,
};
kunit_test_suite(virt_dma_suite);

MODULE_DESCRIPTION("KUnit tests for InfiniBand virtual DMA mappings");
MODULE_LICENSE("Dual BSD/GPL");
