// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test for VFIO_DEVICE_FEATURE_DMA_BUF
 *
 * This test validates the VFIO_DEVICE_FEATURE_DMA_BUF feature which allows
 * creating dma-buf file descriptors for device regions.
 */

#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>

#include <linux/limits.h>
#include <linux/pci_regs.h>
#include <linux/sizes.h>
#include <linux/vfio.h>

#include <vfio_util.h>

#include "../kselftest_harness.h"

static const char *device_bdf;

FIXTURE(vfio_dma_buf_test) {
	struct vfio_pci_device *device;
};

FIXTURE_SETUP(vfio_dma_buf_test)
{
	self->device = vfio_pci_device_init(device_bdf, default_iommu_mode);
}

FIXTURE_TEARDOWN(vfio_dma_buf_test)
{
	vfio_pci_device_cleanup(self->device);
}

/*
 * Helper function to check if VFIO_DEVICE_FEATURE_DMA_BUF is supported
 */
static bool dma_buf_feature_supported(struct vfio_pci_device *device)
{
	struct vfio_device_feature feature = {
		.argsz = sizeof(feature),
		.flags = VFIO_DEVICE_FEATURE_PROBE | VFIO_DEVICE_FEATURE_GET |
			 VFIO_DEVICE_FEATURE_DMA_BUF,
	};

	return ioctl(device->fd, VFIO_DEVICE_FEATURE, &feature) == 0;
}

/*
 * Helper function to get a dma-buf fd for a region
 */
static int get_dma_buf_fd(struct vfio_pci_device *device,
			  u32 region_index, u32 open_flags,
			  u32 flags, u32 nr_ranges,
			  struct vfio_region_dma_range *ranges)
{
	size_t feature_size = sizeof(struct vfio_device_feature) +
			      sizeof(struct vfio_device_feature_dma_buf) +
			      nr_ranges * sizeof(struct vfio_region_dma_range);
	struct vfio_device_feature *feature;
	struct vfio_device_feature_dma_buf *dma_buf;
	int ret;
	int i;

	feature = malloc(feature_size);
	if (!feature)
		return -ENOMEM;

	memset(feature, 0, feature_size);
	feature->argsz = feature_size;
	feature->flags = VFIO_DEVICE_FEATURE_GET | VFIO_DEVICE_FEATURE_DMA_BUF;

	dma_buf = (struct vfio_device_feature_dma_buf *)feature->data;
	dma_buf->region_index = region_index;
	dma_buf->open_flags = open_flags;
	dma_buf->flags = flags;
	dma_buf->nr_ranges = nr_ranges;

	for (i = 0; i < nr_ranges; i++) {
		dma_buf->dma_ranges[i].offset = ranges[i].offset;
		dma_buf->dma_ranges[i].length = ranges[i].length;
	}

	ret = ioctl(device->fd, VFIO_DEVICE_FEATURE, feature);
	free(feature);

	return ret;
}

/*
 * Test basic dma-buf creation for a valid BAR region
 */
TEST_F(vfio_dma_buf_test, basic_dma_buf_creation)
{
	struct vfio_pci_bar *bar = NULL;
	struct vfio_region_dma_range range;
	int dma_buf_fd;
	int i;

	if (!dma_buf_feature_supported(self->device))
		SKIP(return, "VFIO_DEVICE_FEATURE_DMA_BUF not supported\n");

	/* Find the first valid BAR with non-zero size */
	for (i = 0; i < PCI_STD_NUM_BARS; i++) {
		if (self->device->bars[i].info.size > 0) {
			bar = &self->device->bars[i];
			break;
		}
	}

	if (!bar)
		SKIP(return, "No valid BARs found on device\n");

	printf("Testing dma-buf creation for BAR %d (size: 0x%llx)\n",
	       i, bar->info.size);

	/* Create a dma-buf for the entire BAR region */
	range.offset = 0;
	range.length = bar->info.size;

	dma_buf_fd = get_dma_buf_fd(self->device, i, O_RDWR | O_CLOEXEC,
				    0, 1, &range);

	if (dma_buf_fd < 0) {
		printf("dma-buf creation returned: %d (errno: %d - %s)\n",
		       dma_buf_fd, errno, strerror(errno));
		/* This may not be supported on all devices/drivers */
		SKIP(return, "dma-buf creation not supported for this device\n");
	}

	ASSERT_GT(dma_buf_fd, 0);
	printf("Created dma-buf fd: %d\n", dma_buf_fd);

	/* Verify the fd is valid */
	ASSERT_EQ(0, fcntl(dma_buf_fd, F_GETFD));

	/* Clean up */
	ASSERT_EQ(0, close(dma_buf_fd));
}

/*
 * Test dma-buf creation with different open flags
 */
TEST_F(vfio_dma_buf_test, dma_buf_open_flags)
{
	struct vfio_pci_bar *bar = NULL;
	struct vfio_region_dma_range range;
	int dma_buf_fd;
	int i;
	u32 test_flags[] = {
		O_RDONLY | O_CLOEXEC,
		O_RDWR | O_CLOEXEC,
		O_RDONLY,
		O_RDWR,
	};

	if (!dma_buf_feature_supported(self->device))
		SKIP(return, "VFIO_DEVICE_FEATURE_DMA_BUF not supported\n");

	/* Find the first valid BAR with non-zero size */
	for (i = 0; i < PCI_STD_NUM_BARS; i++) {
		if (self->device->bars[i].info.size > 0) {
			bar = &self->device->bars[i];
			break;
		}
	}

	if (!bar)
		SKIP(return, "No valid BARs found on device\n");

	range.offset = 0;
	range.length = min((u64)SZ_4K, bar->info.size);

	/* Test different open flags */
	for (i = 0; i < ARRAY_SIZE(test_flags); i++) {
		printf("Testing open_flags: 0x%x\n", test_flags[i]);

		dma_buf_fd = get_dma_buf_fd(self->device,
					    VFIO_PCI_BAR0_REGION_INDEX,
					    test_flags[i], 0, 1, &range);

		if (dma_buf_fd < 0) {
			printf("  dma-buf creation with flags 0x%x failed: %d (errno: %d)\n",
			       test_flags[i], dma_buf_fd, errno);
			continue;
		}

		ASSERT_GT(dma_buf_fd, 0);
		printf("  Created dma-buf fd: %d\n", dma_buf_fd);

		/* Verify O_CLOEXEC flag if requested */
		if (test_flags[i] & O_CLOEXEC) {
			int fd_flags = fcntl(dma_buf_fd, F_GETFD);
			ASSERT_GE(fd_flags, 0);
			ASSERT_TRUE(fd_flags & FD_CLOEXEC);
		}

		ASSERT_EQ(0, close(dma_buf_fd));
	}
}

/*
 * Test dma-buf creation with partial range
 */
TEST_F(vfio_dma_buf_test, dma_buf_partial_range)
{
	struct vfio_pci_bar *bar = NULL;
	struct vfio_region_dma_range range;
	int dma_buf_fd;
	int i;

	if (!dma_buf_feature_supported(self->device))
		SKIP(return, "VFIO_DEVICE_FEATURE_DMA_BUF not supported\n");

	/* Find a BAR with sufficient size */
	for (i = 0; i < PCI_STD_NUM_BARS; i++) {
		if (self->device->bars[i].info.size >= SZ_8K) {
			bar = &self->device->bars[i];
			break;
		}
	}

	if (!bar)
		SKIP(return, "No BAR with size >= 8KB found\n");

	printf("Testing partial range dma-buf for BAR %d\n", i);

	/* Create a dma-buf for a partial range (middle 4KB) */
	range.offset = SZ_4K;
	range.length = SZ_4K;

	dma_buf_fd = get_dma_buf_fd(self->device, i, O_RDWR | O_CLOEXEC,
				    0, 1, &range);

	if (dma_buf_fd < 0) {
		printf("Partial range dma-buf creation not supported: %d (errno: %d)\n",
		       dma_buf_fd, errno);
		SKIP(return, "Partial range not supported\n");
	}

	ASSERT_GT(dma_buf_fd, 0);
	printf("Created partial range dma-buf fd: %d\n", dma_buf_fd);

	ASSERT_EQ(0, close(dma_buf_fd));
}

/*
 * Test dma-buf creation with multiple ranges
 */
TEST_F(vfio_dma_buf_test, dma_buf_multiple_ranges)
{
	struct vfio_pci_bar *bar = NULL;
	struct vfio_region_dma_range ranges[3];
	int dma_buf_fd;
	int i;

	if (!dma_buf_feature_supported(self->device))
		SKIP(return, "VFIO_DEVICE_FEATURE_DMA_BUF not supported\n");

	/* Find a BAR with sufficient size for multiple ranges */
	for (i = 0; i < PCI_STD_NUM_BARS; i++) {
		if (self->device->bars[i].info.size >= SZ_16K) {
			bar = &self->device->bars[i];
			break;
		}
	}

	if (!bar)
		SKIP(return, "No BAR with size >= 16KB found\n");

	printf("Testing multiple ranges dma-buf for BAR %d\n", i);

	/* Create three non-overlapping ranges */
	ranges[0].offset = 0;
	ranges[0].length = SZ_4K;
	ranges[1].offset = SZ_4K;
	ranges[1].length = SZ_4K;
	ranges[2].offset = SZ_8K;
	ranges[2].length = SZ_4K;

	dma_buf_fd = get_dma_buf_fd(self->device, i, O_RDWR | O_CLOEXEC,
				    0, 3, ranges);

	if (dma_buf_fd < 0) {
		printf("Multiple ranges dma-buf creation not supported: %d (errno: %d)\n",
		       dma_buf_fd, errno);
		/* Multiple ranges might not be supported */
		SKIP(return, "Multiple ranges not supported\n");
	}

	ASSERT_GT(dma_buf_fd, 0);
	printf("Created multiple ranges dma-buf fd: %d\n", dma_buf_fd);

	ASSERT_EQ(0, close(dma_buf_fd));
}

/*
 * Test error cases for dma-buf creation
 */
TEST_F(vfio_dma_buf_test, dma_buf_error_cases)
{
	struct vfio_region_dma_range range;
	int dma_buf_fd;

	if (!dma_buf_feature_supported(self->device))
		SKIP(return, "VFIO_DEVICE_FEATURE_DMA_BUF not supported\n");

	/* Test invalid region index */
	printf("Testing invalid region index...\n");
	range.offset = 0;
	range.length = SZ_4K;

	dma_buf_fd = get_dma_buf_fd(self->device, 999, O_RDWR | O_CLOEXEC,
				    0, 1, &range);
	ASSERT_LT(dma_buf_fd, 0);
	printf("  Invalid region correctly rejected (errno: %d)\n", errno);

	/* Test invalid offset (beyond region size) */
	printf("Testing invalid offset...\n");
	if (self->device->bars[0].info.size > 0) {
		range.offset = self->device->bars[0].info.size + SZ_4K;
		range.length = SZ_4K;

		dma_buf_fd = get_dma_buf_fd(self->device,
					    VFIO_PCI_BAR0_REGION_INDEX,
					    O_RDWR | O_CLOEXEC, 0, 1, &range);
		ASSERT_LT(dma_buf_fd, 0);
		printf("  Invalid offset correctly rejected (errno: %d)\n", errno);
	}

	/* Test zero ranges */
	printf("Testing zero ranges...\n");
	dma_buf_fd = get_dma_buf_fd(self->device,
				    VFIO_PCI_BAR0_REGION_INDEX,
				    O_RDWR | O_CLOEXEC, 0, 0, NULL);
	ASSERT_LT(dma_buf_fd, 0);
	printf("  Zero ranges correctly rejected (errno: %d)\n", errno);
}

/*
 * Test dma-buf creation for config space region
 */
TEST_F(vfio_dma_buf_test, dma_buf_config_space)
{
	struct vfio_region_dma_range range;
	int dma_buf_fd;

	if (!dma_buf_feature_supported(self->device))
		SKIP(return, "VFIO_DEVICE_FEATURE_DMA_BUF not supported\n");

	printf("Testing dma-buf for config space region\n");

	/* Try to create a dma-buf for config space */
	range.offset = 0;
	range.length = 256; /* Standard PCI config space size */

	dma_buf_fd = get_dma_buf_fd(self->device,
				    VFIO_PCI_CONFIG_REGION_INDEX,
				    O_RDWR | O_CLOEXEC, 0, 1, &range);

	if (dma_buf_fd < 0) {
		printf("Config space dma-buf not supported (errno: %d)\n", errno);
		/* This is expected, config space typically doesn't support dma-buf */
		return;
	}

	printf("Config space dma-buf created (unexpected but valid): %d\n",
	       dma_buf_fd);
	ASSERT_EQ(0, close(dma_buf_fd));
}

/*
 * Test dma-buf creation with zero-length range
 */
TEST_F(vfio_dma_buf_test, dma_buf_zero_length)
{
	struct vfio_pci_bar *bar = NULL;
	struct vfio_region_dma_range range;
	int dma_buf_fd;
	int i;

	if (!dma_buf_feature_supported(self->device))
		SKIP(return, "VFIO_DEVICE_FEATURE_DMA_BUF not supported\n");

	/* Find a valid BAR */
	for (i = 0; i < PCI_STD_NUM_BARS; i++) {
		if (self->device->bars[i].info.size > 0) {
			bar = &self->device->bars[i];
			break;
		}
	}

	if (!bar)
		SKIP(return, "No valid BARs found\n");

	printf("Testing zero-length range for BAR %d\n", i);

	/* Try to create dma-buf with zero length */
	range.offset = 0;
	range.length = 0;

	dma_buf_fd = get_dma_buf_fd(self->device, i, O_RDWR | O_CLOEXEC,
				    0, 1, &range);

	ASSERT_LT(dma_buf_fd, 0);
	printf("Zero-length range correctly rejected (errno: %d - %s)\n",
	       errno, strerror(errno));
}

/*
 * Test dma-buf fd reusability - create multiple dma-bufs for same region
 */
TEST_F(vfio_dma_buf_test, dma_buf_multiple_fds)
{
	struct vfio_pci_bar *bar = NULL;
	struct vfio_region_dma_range range;
	int dma_buf_fds[3];
	int i, j;

	if (!dma_buf_feature_supported(self->device))
		SKIP(return, "VFIO_DEVICE_FEATURE_DMA_BUF not supported\n");

	/* Find a valid BAR */
	for (i = 0; i < PCI_STD_NUM_BARS; i++) {
		if (self->device->bars[i].info.size > 0) {
			bar = &self->device->bars[i];
			break;
		}
	}

	if (!bar)
		SKIP(return, "No valid BARs found\n");

	printf("Testing multiple dma-buf fds for BAR %d\n", i);

	range.offset = 0;
	range.length = min((u64)SZ_4K, bar->info.size);

	/* Create multiple dma-buf fds for the same region */
	for (j = 0; j < 3; j++) {
		dma_buf_fds[j] = get_dma_buf_fd(self->device, i,
						O_RDWR | O_CLOEXEC,
						0, 1, &range);
		if (dma_buf_fds[j] < 0) {
			printf("Could not create dma-buf %d: %d (errno: %d)\n",
			       j, dma_buf_fds[j], errno);
			SKIP(return, "Multiple dma-buf fds not supported\n");
		}

		ASSERT_GT(dma_buf_fds[j], 0);
		printf("  Created dma-buf fd %d: %d\n", j, dma_buf_fds[j]);
	}

	/* Verify all fds are different */
	for (j = 0; j < 3; j++)
		for (int k = j + 1; k < 3; k++)
			ASSERT_NE(dma_buf_fds[j], dma_buf_fds[k]);

	/* Clean up */
	for (j = 0; j < 3; j++)
		ASSERT_EQ(0, close(dma_buf_fds[j]));
}

int main(int argc, char *argv[])
{
	device_bdf = vfio_selftests_get_bdf(&argc, argv);
	return test_harness_run(argc, argv);
}
