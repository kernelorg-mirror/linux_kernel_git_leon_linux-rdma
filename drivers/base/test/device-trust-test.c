// SPDX-License-Identifier: GPL-2.0

#include <kunit/platform_device.h>
#include <kunit/resource.h>
#include <kunit/test.h>

#include <linux/completion.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/slab.h>

#include "../base.h"

struct device_trust_test_context {
	struct device dev;
	struct device_driver drv;

	enum device_trust_level resolve_level;
	enum device_trust_policy resolve_policy;
	enum device_trust_level configure_level;
	enum device_trust_level probe_level;
	enum device_trust_level remove_level;
	enum device_trust_level cleanup_level;
	const struct device_driver *resolve_driver;
	const struct device_driver *reject_driver;
	struct completion *released;

	int match_ret;
	int resolve_ret;
	int configure_ret;
	int probe_ret;
	unsigned int resolve_count;
	unsigned int configure_count;
	unsigned int probe_count;
	unsigned int remove_count;
	unsigned int cleanup_count;
	bool probe_adversarial;
	bool device_initialized;
	bool device_registered;
	bool driver_registered;
};

static struct device_trust_test_context *
to_device_trust_test_context(struct device *dev)
{
	return container_of(dev, struct device_trust_test_context, dev);
}

static int device_trust_test_match(struct device *dev,
				   const struct device_driver *drv)
{
	struct device_trust_test_context *ctx =
		to_device_trust_test_context(dev);

	return READ_ONCE(ctx->match_ret);
}

static int device_trust_test_resolve(struct device *dev,
				     const struct device_driver *drv,
				     enum device_trust_policy policy,
				     enum device_trust_level *level)
{
	struct device_trust_test_context *ctx =
		to_device_trust_test_context(dev);

	ctx->resolve_count++;
	ctx->resolve_policy = policy;
	ctx->resolve_driver = drv;
	if (ctx->reject_driver && drv == ctx->reject_driver)
		return -EPERM;
	if (ctx->resolve_ret)
		return ctx->resolve_ret;

	*level = ctx->resolve_level;
	return 0;
}

static int device_trust_test_dma_configure(struct device *dev)
{
	struct device_trust_test_context *ctx =
		to_device_trust_test_context(dev);

	ctx->configure_count++;
	ctx->configure_level = device_get_trust_level(dev);
	return ctx->configure_ret;
}

static void device_trust_test_dma_cleanup(struct device *dev)
{
	struct device_trust_test_context *ctx =
		to_device_trust_test_context(dev);

	ctx->cleanup_count++;
	ctx->cleanup_level = device_get_trust_level(dev);
}

static int device_trust_test_probe(struct device *dev)
{
	struct device_trust_test_context *ctx =
		to_device_trust_test_context(dev);

	ctx->probe_count++;
	ctx->probe_level = device_get_trust_level(dev);
	ctx->probe_adversarial = device_is_adversarial(dev);
	return ctx->probe_ret;
}

static int device_trust_test_remove(struct device *dev)
{
	struct device_trust_test_context *ctx =
		to_device_trust_test_context(dev);

	ctx->remove_count++;
	ctx->remove_level = device_get_trust_level(dev);
	return 0;
}

static const struct bus_type device_trust_test_plain_bus = {
	.name = "device-trust-test-plain",
	.match = device_trust_test_match,
	.dma_configure = device_trust_test_dma_configure,
	.dma_cleanup = device_trust_test_dma_cleanup,
};

static const struct bus_type device_trust_test_resolving_bus = {
	.name = "device-trust-test-resolving",
	.match = device_trust_test_match,
	.trust_resolve = device_trust_test_resolve,
	.dma_configure = device_trust_test_dma_configure,
	.dma_cleanup = device_trust_test_dma_cleanup,
};

static const struct device_type device_trust_test_child_type = {
	.need_parent_lock = true,
};

static bool device_trust_test_plain_bus_registered;
static bool device_trust_test_resolving_bus_registered;

static void device_trust_test_release(struct device *dev)
{
	struct device_trust_test_context *ctx =
		to_device_trust_test_context(dev);
	struct completion *released = ctx->released;

	kfree(ctx);
	complete(released);
}

/*
 * The fixture is freed when the last reference to its device is dropped,
 * which deferred probing, device links and delayed kobject release may do
 * after the test. Wait for that so the release callback never outlives it.
 */
static void device_trust_test_device_unregister(void *data)
{
	struct device_trust_test_context *ctx = data;
	struct completion *released = ctx->released;

	if (!ctx->device_initialized)
		return;

	ctx->device_initialized = false;
	if (ctx->device_registered) {
		ctx->device_registered = false;
		device_unregister(&ctx->dev);
	} else {
		put_device(&ctx->dev);
	}
	if (!wait_for_completion_timeout(released, 10 * HZ)) {
		WARN(1, "device-trust test fixture is still referenced\n");
		wait_for_completion(released);
	}
}

static void device_trust_test_driver_unregister(void *data)
{
	struct device_trust_test_context *ctx = data;

	if (!ctx->driver_registered)
		return;

	ctx->driver_registered = false;
	driver_unregister(&ctx->drv);
}

static struct device_trust_test_context *
device_trust_test_device_register_parent(struct kunit *test,
					 const struct bus_type *bus,
					 enum device_trust_policy policy,
					 enum device_trust_policy boot_policy,
					 struct device *parent)
{
	struct device_trust_test_context *ctx;
	struct completion *released;
	int ret;

	released = kunit_kzalloc(test, sizeof(*released), GFP_KERNEL);
	if (!released)
		return ERR_PTR(-ENOMEM);
	init_completion(released);

	ctx = kzalloc_obj(*ctx);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	ctx->released = released;
	ctx->match_ret = 1;
	ctx->resolve_level = DEVICE_TRUST_FULL;
	ctx->drv.probe_type = PROBE_FORCE_SYNCHRONOUS;
	ctx->drv.suppress_bind_attrs = true;
	device_initialize(&ctx->dev);
	ctx->dev.bus = bus;
	ctx->dev.parent = parent;
	if (parent && bus == &device_trust_test_plain_bus)
		ctx->dev.type = &device_trust_test_child_type;
	ctx->dev.release = device_trust_test_release;
	ctx->dev.trust_policy = policy;
	ctx->device_initialized = true;

	ret = kunit_add_action_or_reset(test,
					device_trust_test_device_unregister, ctx);
	if (ret)
		return ERR_PTR(ret);

	ret = dev_set_name(&ctx->dev, "%s-%s",
			   bus ? bus->name : "device-trust-test-busless",
			   test->name);
	if (ret)
		return ERR_PTR(ret);

	device_trust_apply_boot_policy(&ctx->dev, boot_policy, NULL);
	ret = device_add(&ctx->dev);
	if (ret)
		return ERR_PTR(ret);
	ctx->device_registered = true;

	return ctx;
}

static struct device_trust_test_context *
device_trust_test_device_register(struct kunit *test,
				  const struct bus_type *bus,
				  enum device_trust_policy policy)
{
	return device_trust_test_device_register_parent(test, bus, policy,
						       DEVICE_TRUST_POLICY_DEFAULT, NULL);
}

static int device_trust_test_driver_register(struct kunit *test,
					     struct device_trust_test_context *ctx)
{
	int ret;

	ctx->drv.name = test->name;
	ctx->drv.bus = ctx->dev.bus ?: &device_trust_test_plain_bus;
	ctx->drv.probe = device_trust_test_probe;
	ctx->drv.remove = device_trust_test_remove;

	ret = kunit_add_action_or_reset(test,
					device_trust_test_driver_unregister, ctx);
	if (ret)
		return ret;

	ret = driver_register(&ctx->drv);
	if (ret)
		return ret;
	ctx->driver_registered = true;

	return 0;
}

static void device_trust_expect_policy_locked(struct kunit *test,
					      struct device *dev)
{
	enum device_trust_policy original = dev->trust_policy;
	enum device_trust_level active = device_get_trust_level(dev);
	enum device_trust_policy policy;

	for (policy = DEVICE_TRUST_POLICY_DEFAULT;
	     policy <= DEVICE_TRUST_POLICY_FULL; policy++) {
		KUNIT_EXPECT_EQ(test, device_trust_set_policy(dev, policy),
				policy == original ? 0 : -EBUSY);
		KUNIT_EXPECT_EQ(test, dev->trust_policy, original);
		KUNIT_EXPECT_EQ(test, device_get_trust_level(dev), active);
	}
}

static void device_trust_default_bind_test(struct kunit *test)
{
	struct device_trust_test_context *ctx;
	int ret;

	ctx = device_trust_test_device_register(
		test, &device_trust_test_plain_bus, DEVICE_TRUST_POLICY_DEFAULT);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&ctx->dev),
			DEVICE_TRUST_DISABLED);
	KUNIT_EXPECT_EQ(test, device_get_committed_trust_level(&ctx->dev),
			DEVICE_TRUST_DISABLED);

	ret = device_trust_test_driver_register(test, ctx);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_ASSERT_TRUE(test, device_is_bound(&ctx->dev));
	KUNIT_EXPECT_EQ(test, ctx->configure_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->configure_level, DEVICE_TRUST_FULL);
	KUNIT_EXPECT_EQ(test, ctx->probe_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->probe_level, DEVICE_TRUST_FULL);
	KUNIT_EXPECT_FALSE(test, ctx->probe_adversarial);
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&ctx->dev),
			DEVICE_TRUST_FULL);
	device_trust_expect_policy_locked(test, &ctx->dev);

	device_release_driver(&ctx->dev);
	KUNIT_EXPECT_EQ(test, ctx->remove_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->remove_level, DEVICE_TRUST_FULL);
	KUNIT_EXPECT_EQ(test, ctx->cleanup_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->cleanup_level, DEVICE_TRUST_FULL);
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&ctx->dev),
			DEVICE_TRUST_DISABLED);
	KUNIT_EXPECT_EQ(test, device_get_committed_trust_level(&ctx->dev),
			DEVICE_TRUST_FULL);
	device_trust_expect_policy_locked(test, &ctx->dev);
}

static void device_trust_bus_adversary_bind_test(struct kunit *test)
{
	struct device_trust_test_context *ctx;
	int ret;

	ctx = device_trust_test_device_register(
		test, &device_trust_test_resolving_bus,
		DEVICE_TRUST_POLICY_DEFAULT);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	ctx->resolve_level = DEVICE_TRUST_ADVERSARY;

	ret = device_trust_test_driver_register(test, ctx);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_ASSERT_TRUE(test, device_is_bound(&ctx->dev));
	KUNIT_EXPECT_EQ(test, ctx->resolve_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->resolve_policy,
			DEVICE_TRUST_POLICY_DEFAULT);
	KUNIT_EXPECT_PTR_EQ(test, ctx->resolve_driver, &ctx->drv);
	KUNIT_EXPECT_EQ(test, ctx->configure_level, DEVICE_TRUST_ADVERSARY);
	KUNIT_EXPECT_EQ(test, ctx->probe_level, DEVICE_TRUST_ADVERSARY);
	KUNIT_EXPECT_TRUE(test, ctx->probe_adversarial);

	device_release_driver(&ctx->dev);
	KUNIT_EXPECT_EQ(test, ctx->remove_level, DEVICE_TRUST_ADVERSARY);
	KUNIT_EXPECT_EQ(test, ctx->cleanup_level, DEVICE_TRUST_ADVERSARY);
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&ctx->dev),
			DEVICE_TRUST_DISABLED);
}

static void device_trust_test_other_driver_unregister(void *data)
{
	driver_unregister(data);
}

static void device_trust_default_pinned_test(struct kunit *test)
{
	struct device_trust_test_context *ctx;
	struct device_driver *other;
	int ret;

	ctx = device_trust_test_device_register(test, &device_trust_test_resolving_bus,
						DEVICE_TRUST_POLICY_DEFAULT);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	ctx->resolve_level = DEVICE_TRUST_ADVERSARY;
	KUNIT_ASSERT_EQ(test, device_trust_test_driver_register(test, ctx), 0);
	KUNIT_ASSERT_TRUE(test, device_is_bound(&ctx->dev));
	device_release_driver(&ctx->dev);
	device_trust_expect_policy_locked(test, &ctx->dev);

	other = kunit_kzalloc(test, sizeof(*other), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, other);
	other->name = "device-trust-pinned-other";
	other->bus = ctx->dev.bus;
	other->probe = device_trust_test_probe;
	other->remove = device_trust_test_remove;
	other->probe_type = PROBE_FORCE_SYNCHRONOUS;
	other->suppress_bind_attrs = true;
	ctx->resolve_level = DEVICE_TRUST_FULL;
	KUNIT_ASSERT_EQ(test, driver_register(other), 0);
	ret = kunit_add_action_or_reset(test,
					device_trust_test_other_driver_unregister, other);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, device_driver_attach(other, &ctx->dev), -EINVAL);
	KUNIT_EXPECT_PTR_EQ(test, ctx->resolve_driver, other);
	KUNIT_EXPECT_FALSE(test, device_is_bound(&ctx->dev));
	KUNIT_EXPECT_EQ(test, ctx->configure_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->probe_count, 1);
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&ctx->dev),
			DEVICE_TRUST_DISABLED);
	KUNIT_EXPECT_EQ(test, ctx->dev.trust_policy, DEVICE_TRUST_POLICY_DEFAULT);

	ctx->resolve_level = DEVICE_TRUST_ADVERSARY;
	KUNIT_ASSERT_EQ(test, device_driver_attach(other, &ctx->dev), 0);
	KUNIT_EXPECT_TRUE(test, device_is_bound(&ctx->dev));
	KUNIT_EXPECT_PTR_EQ(test, ctx->dev.driver, other);
	KUNIT_EXPECT_EQ(test, ctx->probe_level, DEVICE_TRUST_ADVERSARY);
	device_trust_expect_policy_locked(test, &ctx->dev);
}

static void device_trust_authorize_test(struct kunit *test,
					enum device_trust_policy initial_policy,
					enum device_trust_policy boot_policy,
					enum device_trust_policy policy,
					enum device_trust_level level)
{
	struct device_trust_test_context *ctx;
	int ret;

	ctx = device_trust_test_device_register_parent(
		test, &device_trust_test_plain_bus, initial_policy, boot_policy, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	KUNIT_ASSERT_EQ(test, ctx->dev.trust_policy, DEVICE_TRUST_POLICY_DISABLED);

	ret = device_trust_test_driver_register(test, ctx);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = device_driver_attach(&ctx->drv, &ctx->dev);
	KUNIT_EXPECT_EQ(test, ret, -EPERM);
	KUNIT_EXPECT_FALSE(test, device_is_bound(&ctx->dev));
	KUNIT_EXPECT_EQ(test, ctx->configure_count, 0);
	KUNIT_EXPECT_EQ(test, ctx->probe_count, 0);
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&ctx->dev),
			DEVICE_TRUST_DISABLED);
	KUNIT_EXPECT_EQ(test, device_get_committed_trust_level(&ctx->dev),
			DEVICE_TRUST_DISABLED);
	KUNIT_EXPECT_TRUE(test, dev_can_match(&ctx->dev));
	KUNIT_EXPECT_EQ(test, device_trust_set_policy(&ctx->dev,
						      DEVICE_TRUST_POLICY_DISABLED), 0);
	KUNIT_EXPECT_EQ(test, device_trust_set_policy(&ctx->dev,
						      DEVICE_TRUST_POLICY_DEFAULT), -EBUSY);

	KUNIT_ASSERT_EQ(test, device_trust_set_policy(&ctx->dev, policy), 0);
	device_trust_apply_boot_policy(&ctx->dev, DEVICE_TRUST_POLICY_DISABLED, NULL);
	KUNIT_EXPECT_EQ(test, ctx->dev.trust_policy, policy);
	device_trust_expect_policy_locked(test, &ctx->dev);
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&ctx->dev),
			DEVICE_TRUST_DISABLED);
	KUNIT_EXPECT_EQ(test, device_get_committed_trust_level(&ctx->dev),
			DEVICE_TRUST_DISABLED);

	KUNIT_ASSERT_EQ(test, device_driver_attach(&ctx->drv, &ctx->dev), 0);
	KUNIT_ASSERT_TRUE(test, device_is_bound(&ctx->dev));
	KUNIT_EXPECT_EQ(test, ctx->configure_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->configure_level, level);
	KUNIT_EXPECT_EQ(test, ctx->probe_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->probe_level, level);
	device_trust_expect_policy_locked(test, &ctx->dev);

	device_release_driver(&ctx->dev);
	KUNIT_EXPECT_EQ(test, ctx->cleanup_level, level);
	device_trust_apply_boot_policy(&ctx->dev, DEVICE_TRUST_POLICY_DISABLED, NULL);
	KUNIT_EXPECT_EQ(test, ctx->dev.trust_policy, policy);
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&ctx->dev),
			DEVICE_TRUST_DISABLED);
	KUNIT_EXPECT_EQ(test, device_get_committed_trust_level(&ctx->dev),
			level);
	device_trust_expect_policy_locked(test, &ctx->dev);
}

static void device_trust_disabled_bind_test(struct kunit *test)
{
	device_trust_authorize_test(test, DEVICE_TRUST_POLICY_DISABLED,
				    DEVICE_TRUST_POLICY_DEFAULT, DEVICE_TRUST_POLICY_ADVERSARY,
				    DEVICE_TRUST_ADVERSARY);
}

static void device_trust_disabled_full_bind_test(struct kunit *test)
{
	device_trust_authorize_test(test, DEVICE_TRUST_POLICY_DISABLED,
				    DEVICE_TRUST_POLICY_DEFAULT, DEVICE_TRUST_POLICY_FULL,
				    DEVICE_TRUST_FULL);
}

static void device_trust_global_disabled_adversary_test(struct kunit *test)
{
	device_trust_authorize_test(test, DEVICE_TRUST_POLICY_ADVERSARY,
				    DEVICE_TRUST_POLICY_DISABLED, DEVICE_TRUST_POLICY_ADVERSARY,
				    DEVICE_TRUST_ADVERSARY);
}

static void device_trust_global_disabled_full_test(struct kunit *test)
{
	device_trust_authorize_test(test, DEVICE_TRUST_POLICY_FULL,
				    DEVICE_TRUST_POLICY_DISABLED, DEVICE_TRUST_POLICY_FULL,
				    DEVICE_TRUST_FULL);
}

static void device_trust_test_link_wait(void *data)
{
	device_link_wait_removal();
}

static void device_trust_supplier_retry_test(struct kunit *test)
{
	struct device_trust_test_context *supplier, *consumer;
	struct device_link *link;
	int ret;

	supplier = device_trust_test_device_register(test, &device_trust_test_plain_bus,
						     DEVICE_TRUST_POLICY_DEFAULT);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, supplier);
	KUNIT_ASSERT_EQ(test, device_trust_test_driver_register(test, supplier), 0);
	KUNIT_ASSERT_TRUE(test, device_is_bound(&supplier->dev));
	/* Runs after the consumer is gone and before the supplier goes. */
	ret = kunit_add_action_or_reset(test, device_trust_test_link_wait, NULL);
	KUNIT_ASSERT_EQ(test, ret, 0);
	consumer = device_trust_test_device_register(test, &device_trust_test_resolving_bus,
						     DEVICE_TRUST_POLICY_DISABLED);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, consumer);
	consumer->resolve_level = DEVICE_TRUST_ADVERSARY;
	link = device_link_add(&consumer->dev, &supplier->dev, 0);
	KUNIT_ASSERT_NOT_NULL(test, link);

	KUNIT_ASSERT_EQ(test, device_trust_test_driver_register(test, consumer), 0);
	KUNIT_ASSERT_EQ(test, link->status, DL_STATE_AVAILABLE);
	KUNIT_EXPECT_EQ(test, consumer->dev.links.status, DL_DEV_NO_DRIVER);
	KUNIT_EXPECT_EQ(test, consumer->configure_count, 0);
	KUNIT_ASSERT_EQ(test, device_trust_set_policy(&consumer->dev,
						      DEVICE_TRUST_POLICY_ADVERSARY), 0);
	consumer->resolve_ret = -EAGAIN;
	KUNIT_EXPECT_EQ(test, device_driver_attach(&consumer->drv, &consumer->dev), -EAGAIN);
	KUNIT_ASSERT_EQ(test, link->status, DL_STATE_AVAILABLE);
	KUNIT_EXPECT_EQ(test, consumer->dev.links.status, DL_DEV_NO_DRIVER);

	consumer->resolve_ret = 0;
	KUNIT_ASSERT_EQ(test, device_driver_attach(&consumer->drv, &consumer->dev), 0);
	KUNIT_EXPECT_TRUE(test, device_is_bound(&consumer->dev));
	KUNIT_EXPECT_EQ(test, link->status, DL_STATE_ACTIVE);
	device_release_driver(&consumer->dev);
	KUNIT_ASSERT_EQ(test, link->status, DL_STATE_AVAILABLE);
	device_release_driver(&supplier->dev);
	KUNIT_EXPECT_FALSE(test, device_is_bound(&supplier->dev));
}

static void device_trust_match_defer_authorize_test(struct kunit *test)
{
	struct device_trust_test_context *ctx;

	ctx = device_trust_test_device_register(test, &device_trust_test_plain_bus,
						DEVICE_TRUST_POLICY_DISABLED);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	ctx->match_ret = -EPROBE_DEFER;

	KUNIT_ASSERT_EQ(test, device_trust_test_driver_register(test, ctx), 0);
	KUNIT_EXPECT_TRUE(test, dev_can_match(&ctx->dev));
	KUNIT_EXPECT_EQ(test, ctx->configure_count, 0);
	KUNIT_EXPECT_EQ(test, ctx->probe_count, 0);
	KUNIT_ASSERT_EQ(test, device_trust_set_policy(&ctx->dev,
						      DEVICE_TRUST_POLICY_ADVERSARY), 0);
	device_trust_expect_policy_locked(test, &ctx->dev);

	WRITE_ONCE(ctx->match_ret, 1);
	KUNIT_ASSERT_EQ(test, device_attach(&ctx->dev), 1);
	KUNIT_EXPECT_TRUE(test, device_is_bound(&ctx->dev));
	KUNIT_EXPECT_EQ(test, ctx->probe_level, DEVICE_TRUST_ADVERSARY);
}

static void device_trust_test_parent_unregister(void *data)
{
	root_device_unregister(data);
}

static void device_trust_async_policy_test(struct kunit *test)
{
	struct device_trust_test_context *ctx;
	struct device *parent;
	int ret;

	parent = root_device_register(test->name);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, parent);
	ret = kunit_add_action_or_reset(test,
					device_trust_test_parent_unregister, parent);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ctx = device_trust_test_device_register_parent(test, &device_trust_test_plain_bus,
						       DEVICE_TRUST_POLICY_DEFAULT,
						       DEVICE_TRUST_POLICY_DEFAULT, parent);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	ctx->drv.probe_type = PROBE_PREFER_ASYNCHRONOUS;

	/* The queued probe cannot acquire the parent until policy is disabled. */
	device_lock(parent);
	ret = device_trust_test_driver_register(test, ctx);
	if (!ret)
		ret = device_trust_set_policy(&ctx->dev,
					      DEVICE_TRUST_POLICY_DISABLED);
	device_unlock(parent);
	wait_for_device_probe();
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_FALSE(test, device_is_bound(&ctx->dev));
	KUNIT_EXPECT_TRUE(test, dev_can_match(&ctx->dev));
	KUNIT_EXPECT_EQ(test, ctx->configure_count, 0);
	KUNIT_EXPECT_EQ(test, ctx->probe_count, 0);
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&ctx->dev),
			DEVICE_TRUST_DISABLED);
	KUNIT_EXPECT_EQ(test, device_trust_set_policy(&ctx->dev,
						      DEVICE_TRUST_POLICY_DEFAULT), -EBUSY);

	KUNIT_ASSERT_EQ(test, device_trust_set_policy(&ctx->dev,
						      DEVICE_TRUST_POLICY_ADVERSARY), 0);
	KUNIT_ASSERT_EQ(test, device_driver_attach(&ctx->drv, &ctx->dev), 0);
	KUNIT_EXPECT_TRUE(test, device_is_bound(&ctx->dev));
	KUNIT_EXPECT_EQ(test, ctx->probe_level, DEVICE_TRUST_ADVERSARY);
}

static void device_trust_generic_adversary_bind_test(struct kunit *test)
{
	struct device_trust_test_context *ctx;
	int ret;

	ctx = device_trust_test_device_register(
		test, &device_trust_test_plain_bus,
		DEVICE_TRUST_POLICY_ADVERSARY);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	ret = device_trust_test_driver_register(test, ctx);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_ASSERT_TRUE(test, device_is_bound(&ctx->dev));
	KUNIT_EXPECT_EQ(test, ctx->configure_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->configure_level, DEVICE_TRUST_ADVERSARY);
	KUNIT_EXPECT_EQ(test, ctx->probe_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->probe_level, DEVICE_TRUST_ADVERSARY);
	KUNIT_EXPECT_TRUE(test, ctx->probe_adversarial);

	device_release_driver(&ctx->dev);
	KUNIT_EXPECT_EQ(test, ctx->remove_level, DEVICE_TRUST_ADVERSARY);
	KUNIT_EXPECT_EQ(test, ctx->cleanup_level, DEVICE_TRUST_ADVERSARY);
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&ctx->dev),
			DEVICE_TRUST_DISABLED);
}

static int device_trust_platform_probe(struct platform_device *pdev)
{
	return 0;
}

static void device_trust_no_iommu_bind_test(struct kunit *test)
{
	struct platform_device *pdev;
	struct platform_driver *drv;

	drv = kunit_kzalloc(test, sizeof(*drv), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, drv);
	drv->driver.name = test->name;
	drv->driver.probe_type = PROBE_FORCE_SYNCHRONOUS;
	drv->driver.suppress_bind_attrs = true;
	drv->probe = device_trust_platform_probe;
	pdev = kunit_platform_device_alloc(test, test->name, PLATFORM_DEVID_NONE);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, pdev);
	pdev->dev.trust_policy = DEVICE_TRUST_POLICY_DISABLED;
	KUNIT_ASSERT_EQ(test, kunit_platform_device_add(test, pdev), 0);
	KUNIT_ASSERT_PTR_EQ(test, pdev->dev.iommu_group, NULL);
	KUNIT_ASSERT_EQ(test, kunit_platform_driver_register(test, drv), 0);
	KUNIT_EXPECT_FALSE(test, device_is_bound(&pdev->dev));

	KUNIT_ASSERT_EQ(test, device_trust_set_policy(&pdev->dev,
						      DEVICE_TRUST_POLICY_ADVERSARY), 0);
	KUNIT_ASSERT_EQ(test, device_driver_attach(&drv->driver, &pdev->dev), 0);
	KUNIT_ASSERT_TRUE(test, device_is_bound(&pdev->dev));
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&pdev->dev), DEVICE_TRUST_ADVERSARY);

	device_release_driver(&pdev->dev);
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&pdev->dev), DEVICE_TRUST_DISABLED);
	KUNIT_ASSERT_EQ(test, device_driver_attach(&drv->driver, &pdev->dev), 0);
	KUNIT_EXPECT_TRUE(test, device_is_bound(&pdev->dev));
}

static void device_trust_explicit_policy_mismatch_test(struct kunit *test)
{
	struct device_trust_test_context *ctx;
	int ret;

	ctx = device_trust_test_device_register(
		test, &device_trust_test_resolving_bus,
		DEVICE_TRUST_POLICY_ADVERSARY);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	ctx->resolve_level = DEVICE_TRUST_FULL;

	ret = device_trust_test_driver_register(test, ctx);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = device_driver_attach(&ctx->drv, &ctx->dev);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_GT(test, ctx->resolve_count, 0);
	KUNIT_EXPECT_EQ(test, ctx->resolve_policy,
			DEVICE_TRUST_POLICY_ADVERSARY);
	KUNIT_EXPECT_FALSE(test, device_is_bound(&ctx->dev));
	KUNIT_EXPECT_EQ(test, ctx->configure_count, 0);
	KUNIT_EXPECT_EQ(test, ctx->probe_count, 0);

	KUNIT_ASSERT_EQ(test, device_trust_set_policy(&ctx->dev,
						      DEVICE_TRUST_POLICY_FULL), 0);
	KUNIT_ASSERT_EQ(test, device_driver_attach(&ctx->drv, &ctx->dev), 0);
	KUNIT_EXPECT_TRUE(test, device_is_bound(&ctx->dev));
	KUNIT_EXPECT_EQ(test, ctx->probe_level, DEVICE_TRUST_FULL);
}

static void device_trust_resolver_retry_test(struct kunit *test, int error,
					     enum device_trust_level level)
{
	struct device_trust_test_context *ctx;

	ctx = device_trust_test_device_register(test, &device_trust_test_resolving_bus,
						DEVICE_TRUST_POLICY_DEFAULT);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	ctx->resolve_ret = error;
	ctx->resolve_level = level;

	KUNIT_ASSERT_EQ(test, device_trust_test_driver_register(test, ctx), 0);
	KUNIT_EXPECT_FALSE(test, device_is_bound(&ctx->dev));
	KUNIT_EXPECT_GT(test, ctx->resolve_count, 0);
	KUNIT_EXPECT_EQ(test, ctx->configure_count, 0);
	KUNIT_EXPECT_EQ(test, ctx->probe_count, 0);
	KUNIT_ASSERT_EQ(test, device_trust_set_policy(&ctx->dev,
						      DEVICE_TRUST_POLICY_FULL), 0);
	KUNIT_ASSERT_EQ(test, device_trust_set_policy(&ctx->dev,
						      DEVICE_TRUST_POLICY_ADVERSARY), 0);
	KUNIT_ASSERT_EQ(test, device_trust_set_policy(&ctx->dev,
						      DEVICE_TRUST_POLICY_DEFAULT), 0);
	KUNIT_ASSERT_EQ(test, device_trust_set_policy(&ctx->dev,
						      DEVICE_TRUST_POLICY_DISABLED), 0);
	KUNIT_ASSERT_EQ(test, device_trust_set_policy(&ctx->dev,
						      DEVICE_TRUST_POLICY_ADVERSARY), 0);
	KUNIT_EXPECT_EQ(test, device_driver_attach(&ctx->drv, &ctx->dev), error ?: -EINVAL);
	device_trust_expect_policy_locked(test, &ctx->dev);

	ctx->resolve_ret = 0;
	ctx->resolve_level = DEVICE_TRUST_ADVERSARY;
	KUNIT_ASSERT_EQ(test, device_driver_attach(&ctx->drv, &ctx->dev), 0);
	KUNIT_EXPECT_TRUE(test, device_is_bound(&ctx->dev));
	KUNIT_EXPECT_EQ(test, ctx->probe_level, DEVICE_TRUST_ADVERSARY);
	device_trust_expect_policy_locked(test, &ctx->dev);
}

static void device_trust_resolver_failure_test(struct kunit *test)
{
	device_trust_resolver_retry_test(test, -EAGAIN, DEVICE_TRUST_FULL);
}

static void device_trust_resolver_disabled_test(struct kunit *test)
{
	device_trust_resolver_retry_test(test, 0, DEVICE_TRUST_DISABLED);
}

static void device_trust_probe_failure_test(struct kunit *test)
{
	struct device_trust_test_context *ctx;
	int ret;

	ctx = device_trust_test_device_register(
		test, &device_trust_test_resolving_bus,
		DEVICE_TRUST_POLICY_ADVERSARY);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	ctx->resolve_level = DEVICE_TRUST_ADVERSARY;
	ctx->probe_ret = -EINVAL;

	ret = device_trust_test_driver_register(test, ctx);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_FALSE(test, device_is_bound(&ctx->dev));
	KUNIT_EXPECT_EQ(test, ctx->configure_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->configure_level, DEVICE_TRUST_ADVERSARY);
	KUNIT_EXPECT_EQ(test, ctx->probe_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->probe_level, DEVICE_TRUST_ADVERSARY);
	KUNIT_EXPECT_EQ(test, ctx->remove_count, 0);
	KUNIT_EXPECT_EQ(test, ctx->cleanup_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->cleanup_level, DEVICE_TRUST_ADVERSARY);
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&ctx->dev),
			DEVICE_TRUST_DISABLED);
	device_trust_expect_policy_locked(test, &ctx->dev);
}

static void device_trust_probe_defer_test(struct kunit *test)
{
	struct device_trust_test_context *ctx;
	int ret;

	ctx = device_trust_test_device_register(
		test, &device_trust_test_resolving_bus,
		DEVICE_TRUST_POLICY_DEFAULT);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	ctx->resolve_level = DEVICE_TRUST_ADVERSARY;
	ctx->probe_ret = -EPROBE_DEFER;

	ret = device_trust_test_driver_register(test, ctx);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_FALSE(test, device_is_bound(&ctx->dev));
	KUNIT_EXPECT_EQ(test, ctx->resolve_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->configure_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->probe_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->cleanup_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->cleanup_level, DEVICE_TRUST_ADVERSARY);
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&ctx->dev),
			DEVICE_TRUST_DISABLED);
	device_trust_expect_policy_locked(test, &ctx->dev);

	ctx->probe_ret = 0;
	ret = device_driver_attach(&ctx->drv, &ctx->dev);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_ASSERT_TRUE(test, device_is_bound(&ctx->dev));
	KUNIT_EXPECT_EQ(test, ctx->resolve_count, 2);
	KUNIT_EXPECT_EQ(test, ctx->configure_count, 2);
	KUNIT_EXPECT_EQ(test, ctx->probe_count, 2);
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&ctx->dev),
			DEVICE_TRUST_ADVERSARY);

	device_release_driver(&ctx->dev);
	KUNIT_EXPECT_EQ(test, ctx->remove_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->remove_level, DEVICE_TRUST_ADVERSARY);
	KUNIT_EXPECT_EQ(test, ctx->cleanup_count, 2);
	KUNIT_EXPECT_EQ(test, ctx->cleanup_level, DEVICE_TRUST_ADVERSARY);
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&ctx->dev),
			DEVICE_TRUST_DISABLED);
	device_trust_expect_policy_locked(test, &ctx->dev);
}

static void device_trust_dma_failure_test(struct kunit *test)
{
	struct device_trust_test_context *ctx;
	int ret;

	ctx = device_trust_test_device_register(
		test, &device_trust_test_resolving_bus,
		DEVICE_TRUST_POLICY_DEFAULT);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	ctx->resolve_level = DEVICE_TRUST_ADVERSARY;
	ctx->configure_ret = -EIO;

	ret = device_trust_test_driver_register(test, ctx);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_FALSE(test, device_is_bound(&ctx->dev));
	KUNIT_EXPECT_EQ(test, ctx->configure_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->configure_level, DEVICE_TRUST_ADVERSARY);
	KUNIT_EXPECT_EQ(test, ctx->probe_count, 0);
	KUNIT_EXPECT_EQ(test, ctx->remove_count, 0);
	KUNIT_EXPECT_EQ(test, ctx->cleanup_count, 0);
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&ctx->dev),
			DEVICE_TRUST_DISABLED);
	KUNIT_EXPECT_EQ(test, device_get_committed_trust_level(&ctx->dev),
			DEVICE_TRUST_ADVERSARY);
	device_trust_expect_policy_locked(test, &ctx->dev);

	ctx->configure_ret = 0;
	ctx->resolve_level = DEVICE_TRUST_FULL;
	KUNIT_EXPECT_EQ(test, device_driver_attach(&ctx->drv, &ctx->dev), -EINVAL);
	KUNIT_EXPECT_EQ(test, ctx->configure_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->probe_count, 0);
	ctx->resolve_level = DEVICE_TRUST_ADVERSARY;
	KUNIT_ASSERT_EQ(test, device_driver_attach(&ctx->drv, &ctx->dev), 0);
	KUNIT_EXPECT_TRUE(test, device_is_bound(&ctx->dev));
	KUNIT_EXPECT_EQ(test, ctx->configure_count, 2);
	KUNIT_EXPECT_EQ(test, ctx->probe_level, DEVICE_TRUST_ADVERSARY);
}

static void device_trust_force_bind_guard_test(struct kunit *test)
{
	struct device_trust_test_context *ctx;
	unsigned int resolve_count;
	int ret;

	ctx = device_trust_test_device_register(
		test, &device_trust_test_resolving_bus,
		DEVICE_TRUST_POLICY_DISABLED);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	ret = device_trust_test_driver_register(test, ctx);
	KUNIT_ASSERT_EQ(test, ret, 0);
	resolve_count = ctx->resolve_count;

	device_lock(&ctx->dev);
	ctx->dev.driver = &ctx->drv;
	ret = device_bind_driver(&ctx->dev);
	ctx->dev.driver = NULL;
	device_unlock(&ctx->dev);

	KUNIT_EXPECT_EQ(test, ret, -EOPNOTSUPP);
	KUNIT_EXPECT_EQ(test, ctx->resolve_count, resolve_count);
	KUNIT_EXPECT_FALSE(test, device_is_bound(&ctx->dev));
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&ctx->dev),
			DEVICE_TRUST_DISABLED);
}

static void device_trust_legacy_force_bind_test(struct kunit *test)
{
	struct device_trust_test_context *ctx;
	int ret;

	ctx = device_trust_test_device_register(
		test, &device_trust_test_plain_bus,
		DEVICE_TRUST_POLICY_DISABLED);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	ret = device_trust_test_driver_register(test, ctx);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_ASSERT_EQ(test, device_trust_set_policy(&ctx->dev,
						      DEVICE_TRUST_POLICY_FULL), 0);

	device_lock(&ctx->dev);
	ctx->dev.driver = &ctx->drv;
	ret = device_bind_driver(&ctx->dev);
	if (ret)
		ctx->dev.driver = NULL;
	device_unlock(&ctx->dev);

	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_ASSERT_TRUE(test, device_is_bound(&ctx->dev));
	KUNIT_EXPECT_EQ(test, ctx->configure_count, 0);
	KUNIT_EXPECT_EQ(test, ctx->probe_count, 0);
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&ctx->dev),
			DEVICE_TRUST_FULL);

	device_release_driver(&ctx->dev);
	KUNIT_EXPECT_EQ(test, ctx->remove_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->remove_level, DEVICE_TRUST_FULL);
	KUNIT_EXPECT_EQ(test, ctx->cleanup_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->cleanup_level, DEVICE_TRUST_FULL);
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&ctx->dev),
			DEVICE_TRUST_DISABLED);
}

static void device_trust_busless_force_bind_test(struct kunit *test)
{
	struct device_trust_test_context *ctx;
	int ret;

	ctx = device_trust_test_device_register(
		test, NULL, DEVICE_TRUST_POLICY_DEFAULT);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	ret = device_trust_test_driver_register(test, ctx);
	KUNIT_ASSERT_EQ(test, ret, 0);

	device_lock(&ctx->dev);
	ctx->dev.driver = &ctx->drv;
	ret = device_bind_driver(&ctx->dev);
	if (ret)
		ctx->dev.driver = NULL;
	device_unlock(&ctx->dev);

	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_ASSERT_TRUE(test, device_is_bound(&ctx->dev));
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&ctx->dev),
			DEVICE_TRUST_FULL);

	device_release_driver(&ctx->dev);
	KUNIT_EXPECT_EQ(test, ctx->remove_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->remove_level, DEVICE_TRUST_FULL);
	KUNIT_EXPECT_EQ(test, ctx->cleanup_count, 0);
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&ctx->dev),
			DEVICE_TRUST_DISABLED);
}

static const struct bus_type device_trust_test_pci_bus = { .name = "pci" };
static const struct bus_type device_trust_test_usb_bus = { .name = "usb" };
static const struct bus_type device_trust_test_platform_bus = { .name = "platform" };

struct device_trust_test_stub {
	struct device_driver drv;
	struct device_private private;
	struct device dev;
};

/* Stack instances of these objects overflow the frame limit under KASAN. */
static struct device_trust_test_stub *
device_trust_test_stub_alloc(struct kunit *test)
{
	struct device_trust_test_stub *stub;

	stub = kunit_kzalloc(test, sizeof(*stub), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, stub);

	return stub;
}

static struct device *
device_trust_test_stub_reset(struct device_trust_test_stub *stub,
			     const struct bus_type *bus, const char *name,
			     enum device_trust_policy policy)
{
	memset(stub, 0, sizeof(*stub));
	stub->drv.bus = bus;
	stub->drv.name = "test";
	stub->dev.bus = bus;
	stub->dev.init_name = name;
	stub->dev.trust_policy = policy;
	mutex_init(&stub->dev.mutex);

	return &stub->dev;
}

static struct device *
device_trust_test_pci_stub(struct device_trust_test_stub *stub, const char *name,
			   enum device_trust_policy policy)
{
	return device_trust_test_stub_reset(stub, &device_trust_test_pci_bus, name,
					    policy);
}

static void device_trust_cmdline_policies_test(struct kunit *test)
{
	static const char options[] =
		"pci:0000:01:00.0=adversary,usb:1-1=full,usb:1-2=disabled,platform:i8042=default";
	static const struct {
		const struct bus_type *bus;
		const char *name;
		enum device_trust_policy policy;
	} cases[] = {
		{ &device_trust_test_pci_bus, "0000:01:00.0", DEVICE_TRUST_POLICY_ADVERSARY },
		{ &device_trust_test_usb_bus, "1-1", DEVICE_TRUST_POLICY_FULL },
		{ &device_trust_test_usb_bus, "1-2", DEVICE_TRUST_POLICY_DISABLED },
		{ &device_trust_test_platform_bus, "i8042", DEVICE_TRUST_POLICY_DEFAULT },
	};
	struct device_trust_test_stub *stub = device_trust_test_stub_alloc(test);
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		enum device_trust_policy policy = DEVICE_TRUST_POLICY_DISABLED;
		struct device *dev = device_trust_test_stub_reset(stub, cases[i].bus,
								  cases[i].name,
								  DEVICE_TRUST_POLICY_DEFAULT);
		int ret;

		ret = device_trust_parse_cmdline(options, dev, &policy);
		KUNIT_EXPECT_EQ_MSG(test, ret, 1, "case %u", i);
		KUNIT_EXPECT_EQ_MSG(test, policy, cases[i].policy, "case %u", i);
	}
}

static void device_trust_cmdline_exact_match_test(struct kunit *test)
{
	static const char * const options[] = {
		"pcie:0000:01:00.0=full",
		"pc:0000:01:00.0=full",
		"usb:0000:01:00.0=full",
		"pci:0000:01:00.01=full",
		"pci:0000:01:00=full",
		"pci:0000:01:00.1=full",
	};
	struct device_trust_test_stub *stub = device_trust_test_stub_alloc(test);
	struct device *dev = device_trust_test_pci_stub(stub, "0000:01:00.0",
							DEVICE_TRUST_POLICY_DEFAULT);
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(options); i++) {
		enum device_trust_policy policy = DEVICE_TRUST_POLICY_ADVERSARY;
		int ret;

		ret = device_trust_parse_cmdline(options[i], dev, &policy);
		KUNIT_EXPECT_EQ_MSG(test, ret, 0, "%s", options[i]);
		KUNIT_EXPECT_EQ_MSG(test, policy, DEVICE_TRUST_POLICY_ADVERSARY,
				    "%s", options[i]);
	}
}

static void device_trust_cmdline_last_match_test(struct kunit *test)
{
	static const char options[] =
		"pci:0000:01:00.0=disabled,usb:1-1=full,pci:0000:01:00.0=full,usb:1-2=disabled";
	static const char defaults[] =
		"pci:0000:01:00.0=disabled,pci:0000:01:00.0=default";
	struct device_trust_test_stub *stub = device_trust_test_stub_alloc(test);
	struct device *dev = device_trust_test_pci_stub(stub, "0000:01:00.0",
							DEVICE_TRUST_POLICY_DEFAULT);
	enum device_trust_policy policy = DEVICE_TRUST_POLICY_ADVERSARY;
	int ret;

	ret = device_trust_parse_cmdline(options, dev, &policy);
	KUNIT_ASSERT_EQ(test, ret, 1);
	KUNIT_EXPECT_EQ(test, policy, DEVICE_TRUST_POLICY_FULL);

	ret = device_trust_parse_cmdline(defaults, dev, &policy);
	KUNIT_ASSERT_EQ(test, ret, 1);
	KUNIT_EXPECT_EQ(test, policy, DEVICE_TRUST_POLICY_DEFAULT);
}

static void device_trust_cmdline_nameless_test(struct kunit *test)
{
	struct device_trust_test_stub *stub = device_trust_test_stub_alloc(test);
	struct device *dev = device_trust_test_pci_stub(stub, NULL,
							DEVICE_TRUST_POLICY_DEFAULT);
	enum device_trust_policy policy = DEVICE_TRUST_POLICY_ADVERSARY;
	int ret;

	ret = device_trust_parse_cmdline("pci:0000:01:00.0=full", dev, &policy);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, policy, DEVICE_TRUST_POLICY_ADVERSARY);
}

static void device_trust_cmdline_validate_test(struct kunit *test)
{
	static const char valid[] = "pci:0000:01:00.0=adversary,usb:1-2=disabled";
	static const char invalid[] = "pci:0000:01:00.0=adversary,usb:1-2=invalid";

	KUNIT_EXPECT_EQ(test, device_trust_parse_cmdline(valid, NULL, NULL), 0);
	KUNIT_EXPECT_EQ(test, device_trust_parse_cmdline(invalid, NULL, NULL), -EINVAL);
}

static void device_trust_cmdline_invalid_test(struct kunit *test)
{
	static const char * const options[] = {
		"",
		",pci:0000:01:00.0=full",
		"pci:0000:01:00.0=full,",
		"pci:0000:01:00.0=full,,usb:1-2=disabled",
		":0000:01:00.0=full",
		"pci:=full",
		"pci:0000:01:00.0=",
		"pci=full",
		"pci=bad:0000:01:00.0=full",
		"pci:0000:01:00.0",
		"pci:0000:01:00.0=unknown",
		"pci:0000:01:00.0=full=disabled",
		"pc i:0000:01:00.0=full",
		"pci:0000:01:00.0 =full",
		"pci:0000:01:00.0= full",
		"pci:0000:01:00.0=full\n",
		"pci:0000:01:00.0\t=full",
		"pci:0000:01:00.0\001=full",
		"p\"ci:0000:01:00.0=full",
		"pci:0000:01:00.0=\"full\"",
		"pci:0000:01:00.0=full,usb:1-2=unknown",
	};
	struct device_trust_test_stub *stub = device_trust_test_stub_alloc(test);
	struct device *dev = device_trust_test_pci_stub(stub, "0000:01:00.0",
							DEVICE_TRUST_POLICY_DEFAULT);
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(options); i++) {
		enum device_trust_policy policy = DEVICE_TRUST_POLICY_ADVERSARY;
		int ret;

		ret = device_trust_parse_cmdline(options[i], dev, &policy);
		KUNIT_EXPECT_EQ_MSG(test, ret, -EINVAL, "case %u", i);
		KUNIT_EXPECT_EQ_MSG(test, policy, DEVICE_TRUST_POLICY_ADVERSARY,
				    "case %u", i);
	}
}

static void device_trust_boot_precedence_test(struct kunit *test)
{
	static const char * const overrides[] = {
		[DEVICE_TRUST_POLICY_DEFAULT] = "pci:0000:01:00.0=default",
		[DEVICE_TRUST_POLICY_DISABLED] = "pci:0000:01:00.0=disabled",
		[DEVICE_TRUST_POLICY_ADVERSARY] = "pci:0000:01:00.0=adversary",
		[DEVICE_TRUST_POLICY_FULL] = "pci:0000:01:00.0=full",
	};
	struct device_trust_test_stub *stub = device_trust_test_stub_alloc(test);
	unsigned int initial, global, override;

	for (initial = DEVICE_TRUST_POLICY_DEFAULT;
	     initial <= DEVICE_TRUST_POLICY_FULL; initial++) {
		for (global = DEVICE_TRUST_POLICY_DEFAULT;
		     global <= DEVICE_TRUST_POLICY_FULL; global++) {
			struct device *dev = device_trust_test_pci_stub(stub, "0000:01:00.0",
									initial);
			enum device_trust_policy expected = global ?: initial;

			device_trust_apply_boot_policy(dev, global, NULL);
			KUNIT_EXPECT_EQ(test, dev->trust_policy, expected);
			device_trust_apply_boot_policy(dev, global,
						       "pci:0000:02:00.0=full");
			KUNIT_EXPECT_EQ(test, dev->trust_policy, expected);
			for (override = 0; override < ARRAY_SIZE(overrides); override++) {
				dev->trust_policy = initial;
				device_trust_apply_boot_policy(dev, global,
							       overrides[override]);
				KUNIT_EXPECT_EQ(test, dev->trust_policy, override);
				device_trust_apply_boot_policy(dev, global,
							       overrides[override]);
				KUNIT_EXPECT_EQ(test, dev->trust_policy, override);
			}
		}
	}
}

static void device_trust_global_busless_test(struct kunit *test)
{
	struct device_trust_test_stub *stub = device_trust_test_stub_alloc(test);
	struct device *dev = device_trust_test_stub_reset(stub, NULL, NULL,
							  DEVICE_TRUST_POLICY_FULL);

	device_trust_apply_boot_policy(dev, DEVICE_TRUST_POLICY_DISABLED,
				       "pci:0000:01:00.0=full");
	KUNIT_EXPECT_EQ(test, dev->trust_policy, DEVICE_TRUST_POLICY_DISABLED);
}

static void device_trust_driver_precedence_test(struct kunit *test)
{
	static const char * const driver_rules[] = {
		"pci:test=default", "pci:test=disabled",
		"pci:test=adversary", "pci:test=full",
	};
	static const char * const device_rules[] = {
		NULL, "pci:0000:01:00.0=default", "pci:0000:01:00.0=disabled",
		"pci:0000:01:00.0=adversary", "pci:0000:01:00.0=full",
	};
	struct device_trust_test_stub *stub = device_trust_test_stub_alloc(test);
	unsigned int initial, global, driver, device;
	struct device *dev;
	bool allowed, ok;

	for (initial = DEVICE_TRUST_POLICY_DEFAULT;
	     initial <= DEVICE_TRUST_POLICY_FULL; initial++) {
		for (global = DEVICE_TRUST_POLICY_DEFAULT;
		     global <= DEVICE_TRUST_POLICY_FULL; global++) {
			for (driver = 0; driver < ARRAY_SIZE(driver_rules); driver++) {
				for (device = 0; device < ARRAY_SIZE(device_rules); device++) {
					dev = device_trust_test_pci_stub(stub, "0000:01:00.0",
									 initial);

					device_trust_apply_boot_policy(dev, global,
								       device_rules[device]);
					/* The verdict for a claim before registration */
					allowed = device_trust_claim_allowed(dev, &stub->drv,
									     device_rules[device],
									     driver_rules[driver]);
					dev->p = &stub->private;
					device_trust_apply_boot_policy(dev, global,
								       device_rules[device]);
					device_trust_init_state(dev);
					device_lock(dev);
					device_trust_apply_driver_policy(dev, &stub->drv,
									 driver_rules[driver]);
					device_unlock(dev);
					KUNIT_EXPECT_EQ(test, dev->trust_policy,
							device ? device - 1 : driver);
					/* Driver rules are left to admission */
					ok = !device || device - 1 != DEVICE_TRUST_POLICY_DISABLED;
					KUNIT_EXPECT_EQ(test, allowed, ok);
				}
			}
		}
	}
}

static void device_trust_claim_allowed_test(struct kunit *test)
{
	struct device_trust_test_stub *stub = device_trust_test_stub_alloc(test);
	struct device *dev;

	dev = device_trust_test_pci_stub(stub, "0000:01:00.0", DEVICE_TRUST_POLICY_DISABLED);
	KUNIT_EXPECT_FALSE(test, device_trust_claim_allowed(dev, &stub->drv, NULL, NULL));
	KUNIT_EXPECT_FALSE(test, device_trust_claim_allowed(dev, &stub->drv, NULL,
							    "pci:other=full"));
	KUNIT_EXPECT_TRUE(test, device_trust_claim_allowed(dev, &stub->drv,
							   "pci:0000:01:00.0=full", NULL));
	KUNIT_EXPECT_FALSE(test, device_trust_claim_allowed(dev, &stub->drv,
							    "pci:0000:01:00.0=disabled",
							    "pci:test=full"));
	KUNIT_EXPECT_TRUE(test, device_trust_claim_allowed(dev, &stub->drv, NULL,
							   "pci:test=full"));
	KUNIT_EXPECT_TRUE(test, device_trust_claim_allowed(dev, &stub->drv, NULL,
							   "pci:test=disabled"));

	dev = device_trust_test_pci_stub(stub, "0000:01:00.0", DEVICE_TRUST_POLICY_DEFAULT);
	KUNIT_EXPECT_TRUE(test, device_trust_claim_allowed(dev, &stub->drv, NULL, NULL));
}

static void device_trust_driver_matching_test(struct kunit *test)
{
	static const char * const unmatched[] = {
		NULL, "usb:test=disabled", "pc:test=disabled", "pcie:test=disabled",
		"pci:tes=disabled", "pci:test1=disabled", "pci:te*=disabled",
		"pci:test=disabled,pci:other=invalid", "pci:test=disabled,",
	};
	struct device_trust_test_stub *stub = device_trust_test_stub_alloc(test);
	struct device *dev = device_trust_test_pci_stub(stub, NULL,
							DEVICE_TRUST_POLICY_DEFAULT);
	unsigned int i;

	dev->p = &stub->private;
	device_trust_init_state(dev);
	for (i = 0; i < ARRAY_SIZE(unmatched); i++) {
		device_lock(dev);
		device_trust_apply_driver_policy(dev, &stub->drv, unmatched[i]);
		device_unlock(dev);
		KUNIT_EXPECT_EQ(test, dev->trust_policy, DEVICE_TRUST_POLICY_DEFAULT);
	}
	device_lock(dev);
	device_trust_apply_driver_policy(dev, &stub->drv,
					 "pci:test=disabled,pci:test=adversary");
	device_unlock(dev);
	KUNIT_EXPECT_EQ(test, dev->trust_policy, DEVICE_TRUST_POLICY_ADVERSARY);
}

static void device_trust_driver_user_precedence_test(struct kunit *test)
{
	struct device_trust_test_stub *stub = device_trust_test_stub_alloc(test);
	enum device_trust_policy policy;

	for (policy = DEVICE_TRUST_POLICY_DEFAULT;
	     policy <= DEVICE_TRUST_POLICY_FULL; policy++) {
		struct device *dev = device_trust_test_pci_stub(stub, NULL,
								policy);

		dev->p = &stub->private;
		device_trust_init_state(dev);
		KUNIT_ASSERT_EQ(test, device_trust_set_policy(dev, policy), 0);
		device_lock(dev);
		device_trust_apply_driver_policy(dev, &stub->drv, "pci:test=disabled");
		device_trust_apply_driver_policy(dev, &stub->drv, "pci:test=full");
		device_unlock(dev);
		KUNIT_EXPECT_EQ(test, dev->trust_policy, policy);
	}
}

static void device_trust_driver_rejected_write_test(struct kunit *test)
{
	struct device_trust_test_stub *stub = device_trust_test_stub_alloc(test);
	struct device *dev = device_trust_test_pci_stub(stub, NULL,
							DEVICE_TRUST_POLICY_DISABLED);

	dev->p = &stub->private;
	device_trust_init_state(dev);
	KUNIT_ASSERT_EQ(test, device_trust_set_policy(dev, DEVICE_TRUST_POLICY_DEFAULT),
			-EBUSY);
	KUNIT_ASSERT_EQ(test, device_trust_set_policy(dev, DEVICE_TRUST_POLICY_FULL + 1),
			-EINVAL);
	device_lock(dev);
	device_trust_apply_driver_policy(dev, &stub->drv, "pci:test=full");
	device_unlock(dev);
	KUNIT_EXPECT_EQ(test, dev->trust_policy, DEVICE_TRUST_POLICY_FULL);
}

static void device_trust_driver_authorize_test(struct kunit *test)
{
	const struct device_driver drv = {
		.bus = &device_trust_test_plain_bus,
		.name = "test",
	};
	struct device_trust_test_context *ctx;
	const struct device_driver other = {
		.bus = &device_trust_test_plain_bus,
		.name = "other",
	};
	int ret;

	ctx = device_trust_test_device_register(
		test, &device_trust_test_plain_bus, DEVICE_TRUST_POLICY_DEFAULT);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	device_lock(&ctx->dev);
	device_trust_apply_driver_policy(&ctx->dev, &drv,
					 "device-trust-test-plain:test=disabled");
	device_unlock(&ctx->dev);
	KUNIT_ASSERT_EQ(test, device_trust_test_driver_register(test, ctx), 0);
	KUNIT_EXPECT_FALSE(test, device_is_bound(&ctx->dev));
	KUNIT_EXPECT_EQ(test, ctx->configure_count, 0);
	KUNIT_EXPECT_EQ(test, ctx->probe_count, 0);

	device_lock(&ctx->dev);
	device_trust_apply_driver_policy(&ctx->dev, &other,
					 "device-trust-test-plain:other=full");
	device_unlock(&ctx->dev);
	KUNIT_EXPECT_EQ(test, ctx->dev.trust_policy, DEVICE_TRUST_POLICY_DISABLED);
	KUNIT_ASSERT_EQ(test, device_trust_set_policy(&ctx->dev,
						     DEVICE_TRUST_POLICY_ADVERSARY), 0);
	device_lock(&ctx->dev);
	device_trust_apply_driver_policy(&ctx->dev, &drv,
					 "device-trust-test-plain:test=full");
	device_unlock(&ctx->dev);
	ret = device_attach(&ctx->dev);
	KUNIT_ASSERT_EQ(test, ret, 1);
	KUNIT_EXPECT_EQ(test, ctx->probe_level, DEVICE_TRUST_ADVERSARY);

	device_release_driver(&ctx->dev);
	device_lock(&ctx->dev);
	device_trust_apply_driver_policy(&ctx->dev, &drv,
					 "device-trust-test-plain:test=full");
	device_unlock(&ctx->dev);
	KUNIT_EXPECT_EQ(test, ctx->dev.trust_policy, DEVICE_TRUST_POLICY_ADVERSARY);
	device_trust_expect_policy_locked(test, &ctx->dev);
}

static void device_trust_driver_resolver_failure_test(struct kunit *test)
{
	const struct device_driver drv = {
		.bus = &device_trust_test_resolving_bus,
		.name = "test",
	};
	struct device_trust_test_context *ctx;

	ctx = device_trust_test_device_register(
		test, &device_trust_test_resolving_bus, DEVICE_TRUST_POLICY_DISABLED);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	device_lock(&ctx->dev);
	device_trust_apply_driver_policy(&ctx->dev, &drv,
					 "device-trust-test-resolving:test=full");
	device_unlock(&ctx->dev);
	ctx->resolve_ret = -EIO;
	KUNIT_ASSERT_EQ(test, device_trust_test_driver_register(test, ctx), 0);
	KUNIT_EXPECT_FALSE(test, device_is_bound(&ctx->dev));
	KUNIT_EXPECT_EQ(test, ctx->resolve_policy, DEVICE_TRUST_POLICY_FULL);
	KUNIT_EXPECT_EQ(test, ctx->configure_count, 0);

	device_lock(&ctx->dev);
	device_trust_apply_driver_policy(&ctx->dev, &drv,
					 "device-trust-test-resolving:test=disabled");
	device_unlock(&ctx->dev);
	KUNIT_EXPECT_EQ(test, ctx->dev.trust_policy, DEVICE_TRUST_POLICY_FULL);
	KUNIT_EXPECT_EQ(test, device_trust_set_policy(&ctx->dev,
						     DEVICE_TRUST_POLICY_ADVERSARY), 0);
}

static void device_trust_claimed_policy_test(struct kunit *test)
{
	struct device_trust_test_context *ctx;

	ctx = device_trust_test_device_register(test, &device_trust_test_plain_bus,
						DEVICE_TRUST_POLICY_DEFAULT);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	/* A driver that claimed the device before registration skipped admission. */
	device_lock(&ctx->dev);
	ctx->dev.driver = &ctx->drv;
	device_unlock(&ctx->dev);
	KUNIT_EXPECT_EQ(test, device_trust_set_policy(&ctx->dev,
						      DEVICE_TRUST_POLICY_DISABLED), -EBUSY);
	KUNIT_EXPECT_EQ(test, device_trust_set_policy(&ctx->dev,
						      DEVICE_TRUST_POLICY_DEFAULT), 0);
	KUNIT_EXPECT_EQ(test, ctx->dev.trust_policy, DEVICE_TRUST_POLICY_DEFAULT);

	device_lock(&ctx->dev);
	ctx->dev.driver = NULL;
	device_unlock(&ctx->dev);
	KUNIT_EXPECT_EQ(test, device_trust_set_policy(&ctx->dev,
						      DEVICE_TRUST_POLICY_DISABLED), 0);
}

static void device_trust_try_attach_test(struct kunit *test)
{
	struct device_trust_test_context *ctx;
	struct device *parent;
	bool parent_free;
	int ret;

	parent = root_device_register(test->name);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, parent);
	ret = kunit_add_action_or_reset(test,
					device_trust_test_parent_unregister, parent);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ctx = device_trust_test_device_register_parent(test, &device_trust_test_plain_bus,
						       DEVICE_TRUST_POLICY_DEFAULT,
						       DEVICE_TRUST_POLICY_DEFAULT, parent);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	ctx->match_ret = 0;
	KUNIT_ASSERT_EQ(test, device_trust_test_driver_register(test, ctx), 0);

	device_lock(parent);
	KUNIT_EXPECT_EQ(test, device_driver_try_attach(&ctx->drv, &ctx->dev), -EBUSY);
	device_unlock(parent);

	device_lock(&ctx->dev);
	KUNIT_EXPECT_EQ(test, device_driver_try_attach(&ctx->drv, &ctx->dev), -EBUSY);
	device_unlock(&ctx->dev);

	parent_free = device_trylock(parent);
	if (parent_free)
		device_unlock(parent);
	KUNIT_EXPECT_TRUE(test, parent_free);
	KUNIT_EXPECT_FALSE(test, device_is_bound(&ctx->dev));
	KUNIT_EXPECT_EQ(test, ctx->probe_count, 0);

	KUNIT_ASSERT_EQ(test, device_driver_try_attach(&ctx->drv, &ctx->dev), 0);
	KUNIT_EXPECT_TRUE(test, device_is_bound(&ctx->dev));
	KUNIT_EXPECT_EQ(test, ctx->probe_count, 1);
}

static void device_trust_scan_continues_test(struct kunit *test)
{
	struct device_trust_test_context *ctx;
	struct device_driver *other;
	int ret;

	ctx = device_trust_test_device_register(test, &device_trust_test_resolving_bus,
						DEVICE_TRUST_POLICY_DEFAULT);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	ctx->match_ret = 0;
	KUNIT_ASSERT_EQ(test, device_trust_test_driver_register(test, ctx), 0);

	other = kunit_kzalloc(test, sizeof(*other), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, other);
	other->name = "device-trust-scan-other";
	other->bus = ctx->dev.bus;
	other->probe = device_trust_test_probe;
	other->remove = device_trust_test_remove;
	other->probe_type = PROBE_FORCE_SYNCHRONOUS;
	other->suppress_bind_attrs = true;
	KUNIT_ASSERT_EQ(test, driver_register(other), 0);
	ret = kunit_add_action_or_reset(test,
					device_trust_test_other_driver_unregister, other);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* The first candidate is rejected; the scan must reach the second. */
	ctx->reject_driver = &ctx->drv;
	WRITE_ONCE(ctx->match_ret, 1);
	KUNIT_EXPECT_EQ(test, device_attach(&ctx->dev), 1);
	KUNIT_EXPECT_PTR_EQ(test, ctx->dev.driver, other);
	KUNIT_EXPECT_EQ(test, ctx->resolve_count, 2);
	KUNIT_EXPECT_EQ(test, ctx->probe_count, 1);
}

static struct kunit_case device_trust_test_cases[] = {
	KUNIT_CASE(device_trust_default_bind_test),
	KUNIT_CASE(device_trust_bus_adversary_bind_test),
	KUNIT_CASE(device_trust_default_pinned_test),
	KUNIT_CASE(device_trust_disabled_bind_test),
	KUNIT_CASE(device_trust_disabled_full_bind_test),
	KUNIT_CASE(device_trust_global_disabled_adversary_test),
	KUNIT_CASE(device_trust_global_disabled_full_test),
	KUNIT_CASE(device_trust_supplier_retry_test),
	KUNIT_CASE(device_trust_match_defer_authorize_test),
	KUNIT_CASE(device_trust_async_policy_test),
	KUNIT_CASE(device_trust_generic_adversary_bind_test),
	KUNIT_CASE(device_trust_no_iommu_bind_test),
	KUNIT_CASE(device_trust_explicit_policy_mismatch_test),
	KUNIT_CASE(device_trust_resolver_failure_test),
	KUNIT_CASE(device_trust_resolver_disabled_test),
	KUNIT_CASE(device_trust_probe_failure_test),
	KUNIT_CASE(device_trust_probe_defer_test),
	KUNIT_CASE(device_trust_dma_failure_test),
	KUNIT_CASE(device_trust_force_bind_guard_test),
	KUNIT_CASE(device_trust_legacy_force_bind_test),
	KUNIT_CASE(device_trust_busless_force_bind_test),
	KUNIT_CASE(device_trust_cmdline_policies_test),
	KUNIT_CASE(device_trust_cmdline_exact_match_test),
	KUNIT_CASE(device_trust_cmdline_last_match_test),
	KUNIT_CASE(device_trust_cmdline_nameless_test),
	KUNIT_CASE(device_trust_cmdline_validate_test),
	KUNIT_CASE(device_trust_cmdline_invalid_test),
	KUNIT_CASE(device_trust_boot_precedence_test),
	KUNIT_CASE(device_trust_global_busless_test),
	KUNIT_CASE(device_trust_driver_precedence_test),
	KUNIT_CASE(device_trust_claim_allowed_test),
	KUNIT_CASE(device_trust_driver_matching_test),
	KUNIT_CASE(device_trust_driver_user_precedence_test),
	KUNIT_CASE(device_trust_driver_rejected_write_test),
	KUNIT_CASE(device_trust_driver_authorize_test),
	KUNIT_CASE(device_trust_driver_resolver_failure_test),
	KUNIT_CASE(device_trust_claimed_policy_test),
	KUNIT_CASE(device_trust_try_attach_test),
	KUNIT_CASE(device_trust_scan_continues_test),
	{}
};

/* The fixtures set their own policy, which a live boot default would replace. */
static int device_trust_test_init(struct kunit *test)
{
	struct device_trust_test_stub *stub = device_trust_test_stub_alloc(test);
	struct device *dev = device_trust_test_pci_stub(stub, "device-trust-test",
							DEVICE_TRUST_POLICY_DEFAULT);

	device_trust_init(dev);
	if (dev->trust_policy != DEVICE_TRUST_POLICY_DEFAULT)
		kunit_skip(test, "device_trust.default= replaces the fixture policy");

	return 0;
}

static int device_trust_test_suite_init(struct kunit_suite *suite)
{
	int ret;

	ret = bus_register(&device_trust_test_plain_bus);
	if (ret)
		return ret;
	device_trust_test_plain_bus_registered = true;

	ret = bus_register(&device_trust_test_resolving_bus);
	if (ret) {
		device_trust_test_plain_bus_registered = false;
		bus_unregister(&device_trust_test_plain_bus);
		return ret;
	}
	device_trust_test_resolving_bus_registered = true;

	return 0;
}

static void device_trust_test_suite_exit(struct kunit_suite *suite)
{
	if (device_trust_test_resolving_bus_registered) {
		device_trust_test_resolving_bus_registered = false;
		bus_unregister(&device_trust_test_resolving_bus);
	}
	if (device_trust_test_plain_bus_registered) {
		device_trust_test_plain_bus_registered = false;
		bus_unregister(&device_trust_test_plain_bus);
	}
}

static struct kunit_suite device_trust_test_suite = {
	.name = "device-trust",
	.init = device_trust_test_init,
	.suite_init = device_trust_test_suite_init,
	.suite_exit = device_trust_test_suite_exit,
	.test_cases = device_trust_test_cases,
};

kunit_test_suite(device_trust_test_suite);

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");
MODULE_DESCRIPTION("KUnit tests for device trust");
MODULE_LICENSE("GPL");
