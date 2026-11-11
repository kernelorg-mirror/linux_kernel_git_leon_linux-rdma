// SPDX-License-Identifier: GPL-2.0

#include <kunit/platform_device.h>
#include <kunit/resource.h>
#include <kunit/test.h>

#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/sysfs.h>

#include "../base.h"

struct device_trust_test_sysfs {
	struct kobj_type type;
	struct sysfs_ops ops;
	const struct kobj_type *original;
};

static ssize_t device_trust_test_sysfs_store(struct kobject *kobj,
					     struct attribute *attr,
					     const char *buf, size_t count)
{
	const struct device_trust_test_sysfs *sysfs =
		container_of(kobj->ktype, struct device_trust_test_sysfs, type);

	if (!strcmp(attr->name, "trust_policy"))
		return -EPERM;
	return sysfs->original->sysfs_ops->store(kobj, attr, buf, count);
}

static void device_trust_test_sysfs_release(struct kobject *kobj)
{
	const struct device_trust_test_sysfs *sysfs =
		container_of(kobj->ktype, struct device_trust_test_sysfs, type);
	const struct kobj_type *original = sysfs->original;

	kobj->ktype = original;
	kfree(sysfs);
	original->release(kobj);
}

static int device_trust_test_isolate_sysfs(struct device *dev)
{
	struct device_trust_test_sysfs *sysfs;

	sysfs = kzalloc_obj(*sysfs);
	if (!sysfs)
		return -ENOMEM;
	sysfs->original = dev->kobj.ktype;
	sysfs->type = *sysfs->original;
	sysfs->ops = *sysfs->original->sysfs_ops;
	sysfs->ops.store = device_trust_test_sysfs_store;
	sysfs->type.sysfs_ops = &sysfs->ops;
	sysfs->type.release = device_trust_test_sysfs_release;
	dev->kobj.ktype = &sysfs->type;
	return 0;
}

struct device_trust_test_context {
	struct device dev;
	struct device_driver drv;

	enum device_trust_level resolve_level;
	enum device_trust_policy resolve_policy;
	enum device_trust_level configure_level;
	enum device_trust_level probe_level;
	enum device_trust_level probe_exit_level;
	enum device_trust_level remove_level;
	enum device_trust_level cleanup_level;
	const struct device_driver *resolve_driver;
	const struct device_driver *reject_driver;
	struct completion *released;
	struct completion *probe_entered;
	struct completion *probe_continue;

	int match_ret;
	int resolve_ret;
	int configure_ret;
	int probe_ret;
	unsigned int resolve_count;
	unsigned int configure_count;
	unsigned int probe_count;
	unsigned int remove_count;
	unsigned int cleanup_count;
	unsigned int release_count;
	bool probe_adversarial;
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

	if (dev->parent)
		device_lock_assert(dev->parent);
	ctx->cleanup_count++;
	ctx->cleanup_level = device_get_trust_level(dev);
}

static int device_trust_test_probe(struct device *dev)
{
	struct device_trust_test_context *ctx =
		to_device_trust_test_context(dev);

	if (dev->parent)
		device_lock_assert(dev->parent);
	ctx->probe_count++;
	ctx->probe_level = device_get_trust_level(dev);
	ctx->probe_adversarial = device_is_adversarial(dev);
	if (ctx->probe_entered) {
		complete(ctx->probe_entered);
		wait_for_completion(ctx->probe_continue);
	}
	ctx->probe_exit_level = device_get_trust_level(dev);
	return ctx->probe_ret;
}

static int device_trust_test_remove(struct device *dev)
{
	struct device_trust_test_context *ctx =
		to_device_trust_test_context(dev);

	if (dev->parent)
		device_lock_assert(dev->parent);
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

	if (ctx->device_registered)
		device_unregister(&ctx->dev);
	else
		put_device(&ctx->dev);
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

	driver_unregister(&ctx->drv);
}

static struct device_trust_test_context *
device_trust_test_device_alloc(struct kunit *test, const struct bus_type *bus,
			       enum device_trust_policy policy, struct device *parent)
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
	ctx->resolve_level = DEVICE_TRUST_UNRESTRICTED;
	ctx->drv.probe_type = PROBE_FORCE_SYNCHRONOUS;
	ctx->drv.suppress_bind_attrs = true;
	device_initialize(&ctx->dev);
	ctx->dev.bus = bus;
	ctx->dev.parent = parent;
	if (parent && bus == &device_trust_test_plain_bus)
		ctx->dev.type = &device_trust_test_child_type;
	ctx->dev.release = device_trust_test_release;
	ctx->dev.trust_policy = policy;

	ret = kunit_add_action_or_reset(test,
					device_trust_test_device_unregister, ctx);
	if (ret)
		return ERR_PTR(ret);

	ret = device_trust_test_isolate_sysfs(&ctx->dev);
	if (ret)
		return ERR_PTR(ret);

	ret = dev_set_name(&ctx->dev, "%s-%s",
			   bus ? bus->name : "device-trust-test-busless",
			   test->name);
	if (ret)
		return ERR_PTR(ret);

	return ctx;
}

static struct device_trust_test_context *
device_trust_test_device_register_parent(struct kunit *test,
						 const struct bus_type *bus,
						 enum device_trust_policy policy,
						 enum device_trust_policy boot_policy,
						 struct device *parent)
{
	struct device_trust_test_context *ctx;
	int ret;

	ctx = device_trust_test_device_alloc(test, bus, policy, parent);
	if (IS_ERR(ctx))
		return ctx;
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

static int device_trust_test_driver_register_named(struct kunit *test,
						   struct device_trust_test_context *ctx,
						   const char *name)
{
	int ret;

	ctx->drv.name = name;
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

static int device_trust_test_driver_register(struct kunit *test,
					     struct device_trust_test_context *ctx)
{
	return device_trust_test_driver_register_named(test, ctx, test->name);
}

static void device_trust_expect_policy_locked(struct kunit *test,
					      struct device *dev)
{
	enum device_trust_policy original = dev->trust_policy;
	enum device_trust_level active = device_get_trust_level(dev);
	enum device_trust_policy policy;

	for (policy = DEVICE_TRUST_POLICY_DEFAULT;
	     policy <= DEVICE_TRUST_POLICY_UNRESTRICTED; policy++) {
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
			DEVICE_TRUST_BLOCKED);
	KUNIT_EXPECT_EQ(test, device_get_committed_trust_level(&ctx->dev),
			DEVICE_TRUST_BLOCKED);

	ret = device_trust_test_driver_register(test, ctx);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_ASSERT_TRUE(test, device_is_bound(&ctx->dev));
	KUNIT_EXPECT_EQ(test, ctx->configure_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->configure_level, DEVICE_TRUST_UNRESTRICTED);
	KUNIT_EXPECT_EQ(test, ctx->probe_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->probe_level, DEVICE_TRUST_UNRESTRICTED);
	KUNIT_EXPECT_FALSE(test, ctx->probe_adversarial);
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&ctx->dev),
			DEVICE_TRUST_UNRESTRICTED);
	device_trust_expect_policy_locked(test, &ctx->dev);

	device_release_driver(&ctx->dev);
	KUNIT_EXPECT_EQ(test, ctx->remove_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->remove_level, DEVICE_TRUST_UNRESTRICTED);
	KUNIT_EXPECT_EQ(test, ctx->cleanup_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->cleanup_level, DEVICE_TRUST_UNRESTRICTED);
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&ctx->dev),
			DEVICE_TRUST_BLOCKED);
	KUNIT_EXPECT_EQ(test, device_get_committed_trust_level(&ctx->dev),
			DEVICE_TRUST_UNRESTRICTED);
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
			DEVICE_TRUST_BLOCKED);
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
	ctx->resolve_level = DEVICE_TRUST_UNRESTRICTED;
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
			DEVICE_TRUST_BLOCKED);
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
	KUNIT_ASSERT_EQ(test, ctx->dev.trust_policy, DEVICE_TRUST_POLICY_BLOCKED);

	ret = device_trust_test_driver_register(test, ctx);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = device_driver_attach(&ctx->drv, &ctx->dev);
	KUNIT_EXPECT_EQ(test, ret, -EPERM);
	KUNIT_EXPECT_FALSE(test, device_is_bound(&ctx->dev));
	KUNIT_EXPECT_EQ(test, ctx->configure_count, 0);
	KUNIT_EXPECT_EQ(test, ctx->probe_count, 0);
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&ctx->dev),
			DEVICE_TRUST_BLOCKED);
	KUNIT_EXPECT_EQ(test, device_get_committed_trust_level(&ctx->dev),
			DEVICE_TRUST_BLOCKED);
	KUNIT_EXPECT_TRUE(test, dev_can_match(&ctx->dev));
	KUNIT_EXPECT_EQ(test, device_trust_set_policy(&ctx->dev,
						      DEVICE_TRUST_POLICY_BLOCKED), 0);
	KUNIT_EXPECT_EQ(test, device_trust_set_policy(&ctx->dev,
						      DEVICE_TRUST_POLICY_DEFAULT), -EBUSY);

	KUNIT_ASSERT_EQ(test, device_trust_set_policy(&ctx->dev, policy), 0);
	KUNIT_EXPECT_EQ(test, ctx->dev.trust_policy, policy);
	device_trust_expect_policy_locked(test, &ctx->dev);
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&ctx->dev),
			DEVICE_TRUST_BLOCKED);
	KUNIT_EXPECT_EQ(test, device_get_committed_trust_level(&ctx->dev),
			DEVICE_TRUST_BLOCKED);

	KUNIT_ASSERT_EQ(test, device_driver_attach(&ctx->drv, &ctx->dev), 0);
	KUNIT_ASSERT_TRUE(test, device_is_bound(&ctx->dev));
	KUNIT_EXPECT_EQ(test, ctx->configure_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->configure_level, level);
	KUNIT_EXPECT_EQ(test, ctx->probe_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->probe_level, level);
	device_trust_expect_policy_locked(test, &ctx->dev);

	device_release_driver(&ctx->dev);
	KUNIT_EXPECT_EQ(test, ctx->cleanup_level, level);
	KUNIT_EXPECT_EQ(test, ctx->dev.trust_policy, policy);
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&ctx->dev),
			DEVICE_TRUST_BLOCKED);
	KUNIT_EXPECT_EQ(test, device_get_committed_trust_level(&ctx->dev),
			level);
	device_trust_expect_policy_locked(test, &ctx->dev);
}

static void device_trust_blocked_bind_test(struct kunit *test)
{
	device_trust_authorize_test(test, DEVICE_TRUST_POLICY_BLOCKED,
				    DEVICE_TRUST_POLICY_DEFAULT, DEVICE_TRUST_POLICY_ADVERSARY,
				    DEVICE_TRUST_ADVERSARY);
}

static void device_trust_blocked_unrestricted_bind_test(struct kunit *test)
{
	device_trust_authorize_test(test, DEVICE_TRUST_POLICY_BLOCKED,
				    DEVICE_TRUST_POLICY_DEFAULT, DEVICE_TRUST_POLICY_UNRESTRICTED,
				    DEVICE_TRUST_UNRESTRICTED);
}

static void device_trust_global_blocked_adversary_test(struct kunit *test)
{
	device_trust_authorize_test(test, DEVICE_TRUST_POLICY_ADVERSARY,
				    DEVICE_TRUST_POLICY_BLOCKED, DEVICE_TRUST_POLICY_ADVERSARY,
				    DEVICE_TRUST_ADVERSARY);
}

static void device_trust_global_blocked_unrestricted_test(struct kunit *test)
{
	device_trust_authorize_test(test, DEVICE_TRUST_POLICY_UNRESTRICTED,
				    DEVICE_TRUST_POLICY_BLOCKED, DEVICE_TRUST_POLICY_UNRESTRICTED,
				    DEVICE_TRUST_UNRESTRICTED);
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
						     DEVICE_TRUST_POLICY_BLOCKED);
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
						DEVICE_TRUST_POLICY_BLOCKED);
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
	int ret;

	ctx = device_trust_test_device_register(test, &device_trust_test_plain_bus,
						DEVICE_TRUST_POLICY_DEFAULT);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	ctx->drv.probe_type = PROBE_PREFER_ASYNCHRONOUS;

	KUNIT_ASSERT_EQ(test, device_trust_set_policy(&ctx->dev,
						      DEVICE_TRUST_POLICY_BLOCKED), 0);
	ret = device_trust_test_driver_register(test, ctx);
	wait_for_device_probe();
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_FALSE(test, device_is_bound(&ctx->dev));
	KUNIT_EXPECT_TRUE(test, dev_can_match(&ctx->dev));
	KUNIT_EXPECT_EQ(test, ctx->configure_count, 0);
	KUNIT_EXPECT_EQ(test, ctx->probe_count, 0);
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&ctx->dev),
			DEVICE_TRUST_BLOCKED);
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
			DEVICE_TRUST_BLOCKED);
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
	KUNIT_ASSERT_EQ(test, device_trust_test_isolate_sysfs(&pdev->dev), 0);
	KUNIT_ASSERT_EQ(test, device_set_driver_override(&pdev->dev, "none"), 0);
	pdev->dev.trust_policy = DEVICE_TRUST_POLICY_BLOCKED;
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
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&pdev->dev), DEVICE_TRUST_BLOCKED);
	KUNIT_ASSERT_EQ(test, device_driver_attach(&drv->driver, &pdev->dev), 0);
	KUNIT_EXPECT_TRUE(test, device_is_bound(&pdev->dev));
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
						      DEVICE_TRUST_POLICY_UNRESTRICTED), 0);
	KUNIT_ASSERT_EQ(test, device_trust_set_policy(&ctx->dev,
						      DEVICE_TRUST_POLICY_ADVERSARY), 0);
	KUNIT_ASSERT_EQ(test, device_trust_set_policy(&ctx->dev,
						      DEVICE_TRUST_POLICY_DEFAULT), 0);
	KUNIT_ASSERT_EQ(test, device_trust_set_policy(&ctx->dev,
						      DEVICE_TRUST_POLICY_BLOCKED), 0);
	KUNIT_ASSERT_EQ(test, device_trust_set_policy(&ctx->dev,
						      DEVICE_TRUST_POLICY_ADVERSARY), 0);
	KUNIT_EXPECT_EQ(test, device_driver_attach(&ctx->drv, &ctx->dev), error ?: -EPERM);
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
	device_trust_resolver_retry_test(test, -EAGAIN, DEVICE_TRUST_UNRESTRICTED);
}

static void device_trust_resolver_blocked_test(struct kunit *test)
{
	device_trust_resolver_retry_test(test, 0, DEVICE_TRUST_BLOCKED);
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
			DEVICE_TRUST_BLOCKED);
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
	ctx->match_ret = 0;

	ret = device_trust_test_driver_register(test, ctx);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_ASSERT_EQ(test, device_driver_attach(&ctx->drv, &ctx->dev), -EAGAIN);
	KUNIT_EXPECT_FALSE(test, device_is_bound(&ctx->dev));
	KUNIT_EXPECT_EQ(test, ctx->resolve_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->configure_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->probe_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->cleanup_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->cleanup_level, DEVICE_TRUST_ADVERSARY);
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&ctx->dev),
			DEVICE_TRUST_BLOCKED);
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
			DEVICE_TRUST_BLOCKED);
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
			DEVICE_TRUST_BLOCKED);
	KUNIT_EXPECT_EQ(test, device_get_committed_trust_level(&ctx->dev),
			DEVICE_TRUST_ADVERSARY);
	device_trust_expect_policy_locked(test, &ctx->dev);

	ctx->configure_ret = 0;
	ctx->resolve_level = DEVICE_TRUST_UNRESTRICTED;
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
		DEVICE_TRUST_POLICY_BLOCKED);
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
			DEVICE_TRUST_BLOCKED);
}

static void device_trust_legacy_force_bind_test(struct kunit *test)
{
	struct device_trust_test_context *ctx;
	int ret;

	ctx = device_trust_test_device_register(
		test, &device_trust_test_plain_bus,
		DEVICE_TRUST_POLICY_BLOCKED);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	ret = device_trust_test_driver_register(test, ctx);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_ASSERT_EQ(test, device_trust_set_policy(&ctx->dev,
						      DEVICE_TRUST_POLICY_UNRESTRICTED), 0);

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
			DEVICE_TRUST_UNRESTRICTED);

	device_release_driver(&ctx->dev);
	KUNIT_EXPECT_EQ(test, ctx->remove_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->remove_level, DEVICE_TRUST_UNRESTRICTED);
	KUNIT_EXPECT_EQ(test, ctx->cleanup_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->cleanup_level, DEVICE_TRUST_UNRESTRICTED);
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&ctx->dev),
			DEVICE_TRUST_BLOCKED);
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
			DEVICE_TRUST_UNRESTRICTED);

	device_release_driver(&ctx->dev);
	KUNIT_EXPECT_EQ(test, ctx->remove_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->remove_level, DEVICE_TRUST_UNRESTRICTED);
	KUNIT_EXPECT_EQ(test, ctx->cleanup_count, 0);
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&ctx->dev),
			DEVICE_TRUST_BLOCKED);
}

static const struct bus_type device_trust_test_pci_bus = { .name = "pci" };
static const struct bus_type device_trust_test_usb_bus = { .name = "usb" };
static const struct bus_type device_trust_test_platform_bus = { .name = "platform" };

struct device_trust_test_stub {
	struct device_driver drv;
	struct driver_private driver_private;
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
	stub->driver_private.kobj.name = stub->drv.name;
	stub->drv.p = &stub->driver_private;
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
		"pci:0000:01:00.0=adversary,usb:1-1=unrestricted,usb:1-2=blocked,platform:i8042=default";
	static const struct {
		const struct bus_type *bus;
		const char *name;
		enum device_trust_policy policy;
	} cases[] = {
		{ &device_trust_test_pci_bus, "0000:01:00.0", DEVICE_TRUST_POLICY_ADVERSARY },
		{ &device_trust_test_usb_bus, "1-1", DEVICE_TRUST_POLICY_UNRESTRICTED },
		{ &device_trust_test_usb_bus, "1-2", DEVICE_TRUST_POLICY_BLOCKED },
		{ &device_trust_test_platform_bus, "i8042", DEVICE_TRUST_POLICY_DEFAULT },
	};
	struct device_trust_test_stub *stub = device_trust_test_stub_alloc(test);
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		enum device_trust_policy policy = DEVICE_TRUST_POLICY_BLOCKED;
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
		"pcie:0000:01:00.0=unrestricted",
		"pc:0000:01:00.0=unrestricted",
		"usb:0000:01:00.0=unrestricted",
		"pci:0000:01:00.01=unrestricted",
		"pci:0000:01:00=unrestricted",
		"pci:0000:01:00.1=unrestricted",
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
		"pci:0000:01:00.0=blocked,usb:1-1=unrestricted,pci:0000:01:00.0=unrestricted,usb:1-2=blocked";
	static const char defaults[] =
		"pci:0000:01:00.0=blocked,pci:0000:01:00.0=default";
	struct device_trust_test_stub *stub = device_trust_test_stub_alloc(test);
	struct device *dev = device_trust_test_pci_stub(stub, "0000:01:00.0",
							DEVICE_TRUST_POLICY_DEFAULT);
	enum device_trust_policy policy = DEVICE_TRUST_POLICY_ADVERSARY;
	int ret;

	ret = device_trust_parse_cmdline(options, dev, &policy);
	KUNIT_ASSERT_EQ(test, ret, 1);
	KUNIT_EXPECT_EQ(test, policy, DEVICE_TRUST_POLICY_UNRESTRICTED);

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

	ret = device_trust_parse_cmdline("pci:0000:01:00.0=unrestricted", dev, &policy);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, policy, DEVICE_TRUST_POLICY_ADVERSARY);
}

static void device_trust_cmdline_validate_test(struct kunit *test)
{
	static const char valid[] = "pci:0000:01:00.0=adversary,usb:1-2=blocked";
	static const char invalid[] = "pci:0000:01:00.0=adversary,usb:1-2=invalid";

	KUNIT_EXPECT_EQ(test, device_trust_parse_cmdline(valid, NULL, NULL), 0);
	KUNIT_EXPECT_EQ(test, device_trust_parse_cmdline(invalid, NULL, NULL), -EINVAL);
}

static void device_trust_cmdline_invalid_test(struct kunit *test)
{
	static const char * const options[] = {
		"",
		",pci:0000:01:00.0=unrestricted",
		"pci:0000:01:00.0=unrestricted,",
		"pci:0000:01:00.0=unrestricted,,usb:1-2=blocked",
		":0000:01:00.0=unrestricted",
		"pci:=unrestricted",
		"pci:0000:01:00.0=",
		"pci=unrestricted",
		"pci=bad:0000:01:00.0=unrestricted",
		"pci:0000:01:00.0",
		"pci:0000:01:00.0=unknown",
		"pci:0000:01:00.0=unrestricted=blocked",
		"pc i:0000:01:00.0=unrestricted",
		"pci:0000:01:00.0 =unrestricted",
		"pci:0000:01:00.0= unrestricted",
		"pci:0000:01:00.0=unrestricted\n",
		"pci:0000:01:00.0\t=unrestricted",
		"pci:0000:01:00.0\001=unrestricted",
		"p\"ci:0000:01:00.0=unrestricted",
		"pci:0000:01:00.0=\"unrestricted\"",
		"pci:0000:01:00.0=unrestricted,usb:1-2=unknown",
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
		[DEVICE_TRUST_POLICY_BLOCKED] = "pci:0000:01:00.0=blocked",
		[DEVICE_TRUST_POLICY_ADVERSARY] = "pci:0000:01:00.0=adversary",
		[DEVICE_TRUST_POLICY_UNRESTRICTED] = "pci:0000:01:00.0=unrestricted",
	};
	struct device_trust_test_stub *stub = device_trust_test_stub_alloc(test);
	unsigned int initial, global, override;

	for (initial = DEVICE_TRUST_POLICY_DEFAULT;
	     initial <= DEVICE_TRUST_POLICY_UNRESTRICTED; initial++) {
		for (global = DEVICE_TRUST_POLICY_DEFAULT;
		     global <= DEVICE_TRUST_POLICY_UNRESTRICTED; global++) {
			struct device *dev = device_trust_test_pci_stub(stub, "0000:01:00.0",
									initial);
			enum device_trust_policy expected = global ?: initial;

			device_trust_apply_boot_policy(dev, global, NULL);
			KUNIT_EXPECT_EQ(test, dev->trust_policy, expected);
			device_trust_apply_boot_policy(dev, global,
						       "pci:0000:02:00.0=unrestricted");
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
							  DEVICE_TRUST_POLICY_UNRESTRICTED);

	device_trust_apply_boot_policy(dev, DEVICE_TRUST_POLICY_BLOCKED,
				       "pci:0000:01:00.0=unrestricted");
	KUNIT_EXPECT_EQ(test, dev->trust_policy, DEVICE_TRUST_POLICY_BLOCKED);
}

static void device_trust_driver_precedence_test(struct kunit *test)
{
	static const char * const driver_rules[] = {
		"pci:test=default", "pci:test=blocked",
		"pci:test=adversary", "pci:test=unrestricted",
	};
	static const char * const device_rules[] = {
		NULL, "pci:0000:01:00.0=default", "pci:0000:01:00.0=blocked",
		"pci:0000:01:00.0=adversary", "pci:0000:01:00.0=unrestricted",
	};
	struct device_trust_test_stub *stub = device_trust_test_stub_alloc(test);
	unsigned int initial, global, driver, device;
	struct device *dev;

	for (initial = DEVICE_TRUST_POLICY_DEFAULT;
	     initial <= DEVICE_TRUST_POLICY_UNRESTRICTED; initial++) {
		for (global = DEVICE_TRUST_POLICY_DEFAULT;
		     global <= DEVICE_TRUST_POLICY_UNRESTRICTED; global++) {
			for (driver = 0; driver < ARRAY_SIZE(driver_rules); driver++) {
				for (device = 0; device < ARRAY_SIZE(device_rules); device++) {
					dev = device_trust_test_pci_stub(stub, "0000:01:00.0",
									 initial);

					device_trust_apply_boot_policy(dev, global,
								       device_rules[device]);
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
				}
			}
		}
	}
}

static void device_trust_driver_matching_test(struct kunit *test)
{
	static const char * const unmatched[] = {
		NULL, "usb:test=blocked", "pc:test=blocked", "pcie:test=blocked",
		"pci:tes=blocked", "pci:test1=blocked", "pci:te*=blocked",
		"pci:test=blocked,pci:other=invalid", "pci:test=blocked,",
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
					 "pci:test=blocked,pci:test=adversary");
	device_unlock(dev);
	KUNIT_EXPECT_EQ(test, dev->trust_policy, DEVICE_TRUST_POLICY_ADVERSARY);
}

static void device_trust_driver_quoted_name_test(struct kunit *test)
{
	static const char * const args[] = {
		"device_trust.driver=\"pci:test driver=adversary\"",
		"\"device_trust.driver=pci:test driver=adversary\"",
		"device_trust.driver=\"pci:other=unrestricted,pci:test driver=adversary\"",
	};
	struct device_trust_test_stub *stub = device_trust_test_stub_alloc(test);
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(args); i++) {
		struct device *dev = device_trust_test_pci_stub(stub, NULL,
							    DEVICE_TRUST_POLICY_DEFAULT);
		char *arg, *param, *value;

		stub->drv.name = "test driver";
		stub->driver_private.kobj.name = stub->drv.name;
		dev->p = &stub->private;
		device_trust_init_state(dev);
		arg = kunit_kstrdup(test, args[i], GFP_KERNEL);
		KUNIT_ASSERT_NOT_NULL(test, arg);
		KUNIT_EXPECT_STREQ(test, next_arg(arg, &param, &value), "");
		KUNIT_ASSERT_STREQ(test, param, "device_trust.driver");
		KUNIT_ASSERT_NOT_NULL(test, value);
		KUNIT_EXPECT_EQ(test, device_trust_parse_driver_cmdline(value, NULL, NULL), 0);
		device_lock(dev);
		device_trust_apply_driver_policy(dev, &stub->drv, value);
		device_unlock(dev);
		KUNIT_EXPECT_EQ(test, dev->trust_policy, DEVICE_TRUST_POLICY_ADVERSARY);
	}
}

static void device_trust_driver_invalid_name_test(struct kunit *test)
{
	static const char * const options[] = {
		"pc i:test driver=unrestricted",
		"pci:test\tdriver=unrestricted",
		"pci:test\ndriver=unrestricted",
		"pci:test\"driver=unrestricted",
		"pci:test driver= unrestricted",
		"pci:test driver=unrestricted=blocked",
		"pci:test driver=unrestricted,pci:other=invalid",
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(options); i++)
		KUNIT_EXPECT_EQ_MSG(test,
				    device_trust_parse_driver_cmdline(options[i], NULL, NULL),
				    -EINVAL, "case %u", i);
}

static void device_trust_driver_sysfs_name_test(struct kunit *test)
{
	const char *rule = "device-trust-test-plain:device-trust!slash=adversary";
	const char *raw_rule = "device-trust-test-plain:device-trust/slash=unrestricted";
	struct device_trust_test_context *ctx;
	enum device_trust_policy policy;

	ctx = device_trust_test_device_register(test, &device_trust_test_plain_bus,
						DEVICE_TRUST_POLICY_DEFAULT);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	ctx->match_ret = 0;
	KUNIT_ASSERT_EQ(test, device_trust_test_driver_register_named(test, ctx,
								      "device-trust/slash"), 0);
	KUNIT_EXPECT_STREQ(test, kobject_name(&ctx->drv.p->kobj), "device-trust!slash");
	KUNIT_ASSERT_EQ(test, device_trust_parse_driver_cmdline(rule, &ctx->drv, &policy), 1);
	KUNIT_EXPECT_EQ(test, policy, DEVICE_TRUST_POLICY_ADVERSARY);
	KUNIT_EXPECT_EQ(test, device_trust_parse_driver_cmdline(raw_rule, &ctx->drv, &policy), 0);
	device_lock(&ctx->dev);
	device_trust_apply_driver_policy(&ctx->dev, &ctx->drv, rule);
	device_unlock(&ctx->dev);
	KUNIT_EXPECT_EQ(test, ctx->dev.trust_policy, DEVICE_TRUST_POLICY_ADVERSARY);
}

static void device_trust_driver_user_precedence_test(struct kunit *test)
{
	struct device_trust_test_stub *stub = device_trust_test_stub_alloc(test);
	enum device_trust_policy policy;

	for (policy = DEVICE_TRUST_POLICY_DEFAULT;
	     policy <= DEVICE_TRUST_POLICY_UNRESTRICTED; policy++) {
		struct device *dev = device_trust_test_pci_stub(stub, NULL,
								policy);

		dev->p = &stub->private;
		device_trust_init_state(dev);
		KUNIT_ASSERT_EQ(test, device_trust_set_policy(dev, policy), 0);
		device_lock(dev);
		device_trust_apply_driver_policy(dev, &stub->drv, "pci:test=blocked");
		device_trust_apply_driver_policy(dev, &stub->drv, "pci:test=unrestricted");
		device_unlock(dev);
		KUNIT_EXPECT_EQ(test, dev->trust_policy, policy);
	}
}

static void device_trust_driver_rejected_write_test(struct kunit *test)
{
	struct device_trust_test_stub *stub = device_trust_test_stub_alloc(test);
	struct device *dev = device_trust_test_pci_stub(stub, NULL,
							DEVICE_TRUST_POLICY_BLOCKED);

	dev->p = &stub->private;
	device_trust_init_state(dev);
	KUNIT_ASSERT_EQ(test, device_trust_set_policy(dev, DEVICE_TRUST_POLICY_DEFAULT),
			-EBUSY);
	device_lock(dev);
	device_trust_apply_driver_policy(dev, &stub->drv, "pci:test=unrestricted");
	device_unlock(dev);
	KUNIT_EXPECT_EQ(test, dev->trust_policy, DEVICE_TRUST_POLICY_UNRESTRICTED);
}

static void device_trust_driver_authorize_test(struct kunit *test)
{
	struct driver_private private = { .kobj.name = "test" };
	struct driver_private other_private = { .kobj.name = "other" };
	const struct device_driver drv = {
		.bus = &device_trust_test_plain_bus,
		.name = "test",
		.p = &private,
	};
	struct device_trust_test_context *ctx;
	const struct device_driver other = {
		.bus = &device_trust_test_plain_bus,
		.name = "other",
		.p = &other_private,
	};
	int ret;

	ctx = device_trust_test_device_register(
		test, &device_trust_test_plain_bus, DEVICE_TRUST_POLICY_DEFAULT);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	device_lock(&ctx->dev);
	device_trust_apply_driver_policy(&ctx->dev, &drv,
					 "device-trust-test-plain:test=blocked");
	device_unlock(&ctx->dev);
	KUNIT_ASSERT_EQ(test, device_trust_test_driver_register(test, ctx), 0);
	KUNIT_EXPECT_FALSE(test, device_is_bound(&ctx->dev));
	KUNIT_EXPECT_EQ(test, ctx->configure_count, 0);
	KUNIT_EXPECT_EQ(test, ctx->probe_count, 0);

	device_lock(&ctx->dev);
	device_trust_apply_driver_policy(&ctx->dev, &other,
					 "device-trust-test-plain:other=unrestricted");
	device_unlock(&ctx->dev);
	KUNIT_EXPECT_EQ(test, ctx->dev.trust_policy, DEVICE_TRUST_POLICY_BLOCKED);
	KUNIT_ASSERT_EQ(test, device_trust_set_policy(&ctx->dev,
						     DEVICE_TRUST_POLICY_ADVERSARY), 0);
	device_lock(&ctx->dev);
	device_trust_apply_driver_policy(&ctx->dev, &drv,
					 "device-trust-test-plain:test=unrestricted");
	device_unlock(&ctx->dev);
	ret = device_attach(&ctx->dev);
	KUNIT_ASSERT_EQ(test, ret, 1);
	KUNIT_EXPECT_EQ(test, ctx->probe_level, DEVICE_TRUST_ADVERSARY);

	device_release_driver(&ctx->dev);
	device_lock(&ctx->dev);
	device_trust_apply_driver_policy(&ctx->dev, &drv,
					 "device-trust-test-plain:test=unrestricted");
	device_unlock(&ctx->dev);
	KUNIT_EXPECT_EQ(test, ctx->dev.trust_policy, DEVICE_TRUST_POLICY_ADVERSARY);
	device_trust_expect_policy_locked(test, &ctx->dev);
}

static void device_trust_driver_resolver_failure_test(struct kunit *test)
{
	struct driver_private private = { .kobj.name = "test" };
	const struct device_driver drv = {
		.bus = &device_trust_test_resolving_bus,
		.name = "test",
		.p = &private,
	};
	struct device_trust_test_context *ctx;

	ctx = device_trust_test_device_register(
		test, &device_trust_test_resolving_bus, DEVICE_TRUST_POLICY_BLOCKED);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	device_lock(&ctx->dev);
	device_trust_apply_driver_policy(&ctx->dev, &drv,
					 "device-trust-test-resolving:test=unrestricted");
	device_unlock(&ctx->dev);
	ctx->resolve_ret = -EIO;
	KUNIT_ASSERT_EQ(test, device_trust_test_driver_register(test, ctx), 0);
	KUNIT_EXPECT_FALSE(test, device_is_bound(&ctx->dev));
	KUNIT_EXPECT_EQ(test, ctx->resolve_policy, DEVICE_TRUST_POLICY_UNRESTRICTED);
	KUNIT_EXPECT_EQ(test, ctx->configure_count, 0);

	device_lock(&ctx->dev);
	device_trust_apply_driver_policy(&ctx->dev, &drv,
					 "device-trust-test-resolving:test=blocked");
	device_unlock(&ctx->dev);
	KUNIT_EXPECT_EQ(test, ctx->dev.trust_policy, DEVICE_TRUST_POLICY_UNRESTRICTED);
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
						      DEVICE_TRUST_POLICY_BLOCKED), -EBUSY);
	KUNIT_EXPECT_EQ(test, device_trust_set_policy(&ctx->dev,
						      DEVICE_TRUST_POLICY_DEFAULT), 0);
	KUNIT_EXPECT_EQ(test, ctx->dev.trust_policy, DEVICE_TRUST_POLICY_DEFAULT);

	device_lock(&ctx->dev);
	ctx->dev.driver = NULL;
	device_unlock(&ctx->dev);
	KUNIT_EXPECT_EQ(test, device_trust_set_policy(&ctx->dev,
						      DEVICE_TRUST_POLICY_BLOCKED), 0);
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

static void device_trust_early_claim_test(struct kunit *test,
					 enum device_trust_policy policy, bool device_override)
{
	static const char * const policies[] = {
		"default", "blocked", "adversary", "unrestricted",
	};
	struct device_trust_test_context *ctx;
	enum device_trust_level level;
	char *driver_rule, *device_rule;
	size_t driver_len, device_len;
	bool admitted;
	int ret, probe_ret = 0;

	ctx = device_trust_test_device_alloc(test, &device_trust_test_plain_bus,
						DEVICE_TRUST_POLICY_BLOCKED, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	ctx->match_ret = 0;
	KUNIT_ASSERT_EQ(test, device_trust_test_driver_register(test, ctx), 0);
	KUNIT_ASSERT_PTR_EQ(test, ctx->dev.p, NULL);
	device_lock(&ctx->dev);
	ret = device_trust_prepare(&ctx->dev, &ctx->drv);
	device_unlock(&ctx->dev);
	KUNIT_ASSERT_EQ(test, ret, -EPERM);
	KUNIT_ASSERT_NOT_NULL(test, ctx->dev.p);

	driver_len = strlen(ctx->drv.bus->name) + strlen(ctx->drv.name) +
		strlen(policies[policy]) + 3;
	device_len = strlen(ctx->dev.bus->name) + strlen(dev_name(&ctx->dev)) +
		sizeof(":=unrestricted");
	driver_rule = kunit_kmalloc(test, driver_len, GFP_KERNEL);
	device_rule = kunit_kmalloc(test, device_len, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, driver_rule);
	KUNIT_ASSERT_NOT_NULL(test, device_rule);
	snprintf(driver_rule, driver_len, "%s:%s=%s", ctx->drv.bus->name,
		 ctx->drv.name, policies[policy]);
	snprintf(device_rule, device_len, "%s:%s=unrestricted", ctx->dev.bus->name,
		 dev_name(&ctx->dev));
	device_lock(&ctx->dev);
	if (device_override) {
		device_trust_apply_boot_policy(&ctx->dev, DEVICE_TRUST_POLICY_DEFAULT,
					       device_rule);
		device_trust_init_state(&ctx->dev);
	}
	device_trust_apply_driver_policy(&ctx->dev, &ctx->drv, driver_rule);
	ret = device_trust_prepare(&ctx->dev, &ctx->drv);
	if (!ret)
		probe_ret = ctx->drv.probe(&ctx->dev);
	device_unlock(&ctx->dev);

	if (device_override)
		policy = DEVICE_TRUST_POLICY_UNRESTRICTED;
	admitted = policy != DEVICE_TRUST_POLICY_BLOCKED;
	level = !admitted ? DEVICE_TRUST_BLOCKED :
		policy == DEVICE_TRUST_POLICY_ADVERSARY ? DEVICE_TRUST_ADVERSARY :
		DEVICE_TRUST_UNRESTRICTED;
	KUNIT_ASSERT_EQ(test, ret, admitted ? 0 : -EPERM);
	KUNIT_ASSERT_EQ(test, probe_ret, 0);
	KUNIT_EXPECT_FALSE(test, device_is_registered(&ctx->dev));
	KUNIT_EXPECT_EQ(test, ctx->probe_count, admitted ? 1 : 0);
	if (admitted)
		KUNIT_EXPECT_EQ(test, ctx->probe_level, level);
	KUNIT_EXPECT_EQ(test, device_get_committed_trust_level(&ctx->dev), level);

	ret = device_add(&ctx->dev);
	if (!ret)
		ctx->device_registered = true;
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, ctx->dev.trust_policy, policy);
	KUNIT_EXPECT_EQ(test, ctx->dev.p->trust_state,
			admitted ? DEVICE_TRUST_COMMITTED : DEVICE_TRUST_WAITING);
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&ctx->dev), level);
	KUNIT_EXPECT_EQ(test, device_get_committed_trust_level(&ctx->dev), level);
	KUNIT_EXPECT_FALSE(test, device_is_bound(&ctx->dev));
	if (admitted) {
		device_lock(&ctx->dev);
		ctx->dev.driver = &ctx->drv;
		ret = device_bind_driver(&ctx->dev);
		if (ret)
			ctx->dev.driver = NULL;
		device_unlock(&ctx->dev);
		KUNIT_ASSERT_EQ(test, ret, 0);
	}
	KUNIT_EXPECT_EQ(test, device_is_bound(&ctx->dev), admitted);
	KUNIT_EXPECT_EQ(test, ctx->probe_count, admitted ? 1 : 0);
	KUNIT_EXPECT_EQ(test, ctx->configure_count, 0);
}

static void device_trust_early_adversary_test(struct kunit *test)
{
	device_trust_early_claim_test(test, DEVICE_TRUST_POLICY_ADVERSARY, false);
}

static void device_trust_early_unrestricted_test(struct kunit *test)
{
	device_trust_early_claim_test(test, DEVICE_TRUST_POLICY_UNRESTRICTED, false);
}

static void device_trust_early_blocked_test(struct kunit *test)
{
	device_trust_early_claim_test(test, DEVICE_TRUST_POLICY_BLOCKED, false);
}

static void device_trust_early_device_override_test(struct kunit *test)
{
	device_trust_early_claim_test(test, DEVICE_TRUST_POLICY_ADVERSARY, true);
}

static struct kunit_case device_trust_test_cases[] = {
	KUNIT_CASE(device_trust_default_bind_test),
	KUNIT_CASE(device_trust_bus_adversary_bind_test),
	KUNIT_CASE(device_trust_default_pinned_test),
	KUNIT_CASE(device_trust_blocked_bind_test),
	KUNIT_CASE(device_trust_blocked_unrestricted_bind_test),
	KUNIT_CASE(device_trust_global_blocked_adversary_test),
	KUNIT_CASE(device_trust_global_blocked_unrestricted_test),
	KUNIT_CASE(device_trust_supplier_retry_test),
	KUNIT_CASE(device_trust_match_defer_authorize_test),
	KUNIT_CASE(device_trust_async_policy_test),
	KUNIT_CASE(device_trust_generic_adversary_bind_test),
	KUNIT_CASE(device_trust_no_iommu_bind_test),
	KUNIT_CASE(device_trust_resolver_failure_test),
	KUNIT_CASE(device_trust_resolver_blocked_test),
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
	KUNIT_CASE(device_trust_driver_matching_test),
	KUNIT_CASE(device_trust_driver_quoted_name_test),
	KUNIT_CASE(device_trust_driver_invalid_name_test),
	KUNIT_CASE(device_trust_driver_sysfs_name_test),
	KUNIT_CASE(device_trust_driver_user_precedence_test),
	KUNIT_CASE(device_trust_driver_rejected_write_test),
	KUNIT_CASE(device_trust_driver_authorize_test),
	KUNIT_CASE(device_trust_driver_resolver_failure_test),
	KUNIT_CASE(device_trust_claimed_policy_test),
	KUNIT_CASE(device_trust_scan_continues_test),
	KUNIT_CASE(device_trust_early_adversary_test),
	KUNIT_CASE(device_trust_early_unrestricted_test),
	KUNIT_CASE(device_trust_early_blocked_test),
	KUNIT_CASE(device_trust_early_device_override_test),
	{}
};

static struct device_trust_test_context *
device_trust_unrestricted_test_register(struct kunit *test, const struct bus_type *bus,
					struct device *parent)
{
	struct device_trust_test_context *ctx;
	int ret;

	ctx = device_trust_test_device_register_parent(test, bus,
						       DEVICE_TRUST_POLICY_DEFAULT,
						       DEVICE_TRUST_POLICY_DEFAULT, parent);
	if (IS_ERR(ctx))
		return ctx;
	ctx->match_ret = 0;
	ret = device_trust_test_driver_register(test, ctx);
	if (ret)
		return ERR_PTR(ret);
	return ctx;
}

#if IS_BUILTIN(CONFIG_DM_KUNIT_TEST)
static bool device_trust_test_parse_boot_rules(struct kunit *test,
					       const char *cmdline, bool *driver_rules,
					       enum device_trust_policy *default_policy)
{
	static const char * const policies[] = {
		"default", "blocked", "adversary", "unrestricted",
	};
	enum device_trust_policy policy = DEVICE_TRUST_POLICY_BLOCKED;
	char *args, *param, *value;
	int parsed;
	bool configured = false;

	*driver_rules = false;
	args = kunit_kstrdup(test, cmdline, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, args);
	while (*args) {
		args = next_arg(args, &param, &value);
		if (!value && !strcmp(param, "--"))
			break;
		if (parameq(param, "device_trust") ||
		    parameqn(param, "device_trust.", strlen("device_trust.")))
			configured = true;
		if (!value)
			continue;
		if (parameq(param, "device_trust.default")) {
			parsed = match_string(policies, ARRAY_SIZE(policies), value);
			if (parsed >= 0)
				policy = parsed;
		} else if (parameq(param, "device_trust.driver") &&
			   device_trust_parse_driver_cmdline(value, NULL, NULL) >= 0) {
			*driver_rules = true;
		}
	}
	if (default_policy)
		*default_policy = configured ? policy : DEVICE_TRUST_POLICY_DEFAULT;
	return configured;
}

static void device_trust_boot_separator_test(struct kunit *test)
{
	static const struct {
		const char *cmdline;
		enum device_trust_policy policy;
		bool configured;
	} cases[] = {
		{ "device_trust.default=unrestricted --=ignored device_trust.default=blocked",
		  DEVICE_TRUST_POLICY_BLOCKED, true },
		{ "device_trust.default=unrestricted --= device_trust.default=blocked",
		  DEVICE_TRUST_POLICY_BLOCKED, true },
		{ "device_trust.default=unrestricted -- device_trust.default=blocked",
		  DEVICE_TRUST_POLICY_UNRESTRICTED, true },
		{ "-- device_trust.default=unrestricted", DEVICE_TRUST_POLICY_DEFAULT, false },
		{ "--=ignored device_trust.default=unrestricted",
		  DEVICE_TRUST_POLICY_UNRESTRICTED, true },
	};
	enum device_trust_policy policy;
	bool configured, driver_rules;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		configured = device_trust_test_parse_boot_rules(test, cases[i].cmdline,
							       &driver_rules, &policy);
		KUNIT_EXPECT_EQ_MSG(test, configured, cases[i].configured, "case %u", i);
		KUNIT_EXPECT_EQ_MSG(test, policy, cases[i].policy, "case %u", i);
		KUNIT_EXPECT_FALSE(test, driver_rules);
	}
}
#endif

static bool device_trust_unrestricted_test_boot_rules(struct kunit *test,
						      bool *driver_rules,
						      enum device_trust_policy *default_policy)
{
#if IS_BUILTIN(CONFIG_DM_KUNIT_TEST)
	return device_trust_test_parse_boot_rules(test, saved_command_line,
						  driver_rules, default_policy);
#else
	kunit_skip(test, "boot policy coverage requires built-in tests");
	return false;
#endif
}

static bool device_trust_unrestricted_test_allowed(struct kunit *test,
						   struct device *dev)
{
	enum device_trust_policy default_policy;
	bool driver_rules;

	if (device_trust_unrestricted_test_boot_rules(test, &driver_rules, &default_policy) &&
	    default_policy != DEVICE_TRUST_POLICY_UNRESTRICTED)
		return false;
	if (dev->trust_policy != DEVICE_TRUST_POLICY_DEFAULT &&
	    dev->trust_policy != DEVICE_TRUST_POLICY_UNRESTRICTED)
		return false;
	return !driver_rules || dev->p->trust_policy_override;
}

static int device_trust_test_attach_unrestricted(struct device_trust_test_context *ctx)
{
	struct device *dev = &ctx->dev;
	struct device *parent = dev->parent;
	int ret;

	if (parent)
		device_lock(parent);
	device_lock(dev);
	ret = device_driver_attach_unrestricted(&ctx->drv, dev);
	device_unlock(dev);
	if (parent)
		device_unlock(parent);
	return ret;
}

static void device_trust_unrestricted_boot_policy_test(struct kunit *test)
{
#if IS_BUILTIN(CONFIG_DM_KUNIT_TEST)
	struct device_trust_test_context *ctx;
	enum device_trust_policy policy;
	bool allowed;
	int ret;

	ctx = device_trust_unrestricted_test_register(test, &device_trust_test_plain_bus, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	policy = ctx->dev.trust_policy;
	allowed = device_trust_unrestricted_test_allowed(test, &ctx->dev);

	ret = device_trust_test_attach_unrestricted(ctx);
	KUNIT_ASSERT_EQ(test, ret, allowed ? 0 : -EPERM);
	KUNIT_EXPECT_EQ(test, device_is_bound(&ctx->dev), allowed);
	KUNIT_EXPECT_EQ(test, ctx->probe_count, allowed ? 1 : 0);
	KUNIT_EXPECT_EQ(test, ctx->configure_count, 0);
	KUNIT_EXPECT_EQ(test, ctx->dev.trust_policy, policy);
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&ctx->dev),
			allowed ? DEVICE_TRUST_UNRESTRICTED : DEVICE_TRUST_BLOCKED);
	KUNIT_EXPECT_EQ(test, device_get_committed_trust_level(&ctx->dev),
			allowed ? DEVICE_TRUST_UNRESTRICTED : DEVICE_TRUST_BLOCKED);
	if (!allowed)
		KUNIT_EXPECT_PTR_EQ(test, ctx->dev.driver, NULL);
#else
	kunit_skip(test, "boot policy coverage requires built-in tests");
#endif
}

static void device_trust_unrestricted_attach_test(struct kunit *test)
{
	struct device_trust_test_context *ctx;
	struct device *parent;
	int ret;

	parent = root_device_register(test->name);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, parent);
	ret = kunit_add_action_or_reset(test,
					device_trust_test_parent_unregister, parent);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ctx = device_trust_unrestricted_test_register(test, &device_trust_test_plain_bus, parent);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	if (!device_trust_unrestricted_test_allowed(test, &ctx->dev))
		kunit_skip(test, "boot policy disallows unrestricted-only attachment");

	ret = device_trust_test_attach_unrestricted(ctx);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_TRUE(test, device_is_bound(&ctx->dev));
	KUNIT_EXPECT_PTR_EQ(test, ctx->dev.driver, &ctx->drv);
	KUNIT_EXPECT_EQ(test, ctx->probe_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->probe_level, DEVICE_TRUST_UNRESTRICTED);
	KUNIT_EXPECT_EQ(test, ctx->configure_count, 0);
	KUNIT_EXPECT_EQ(test, device_trust_test_attach_unrestricted(ctx), -EBUSY);
	KUNIT_EXPECT_EQ(test, ctx->probe_count, 1);

	device_lock(parent);
	device_release_driver(&ctx->dev);
	device_unlock(parent);
	KUNIT_EXPECT_EQ(test, ctx->remove_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->remove_level, DEVICE_TRUST_UNRESTRICTED);
	KUNIT_EXPECT_EQ(test, ctx->cleanup_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->cleanup_level, DEVICE_TRUST_UNRESTRICTED);
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&ctx->dev), DEVICE_TRUST_BLOCKED);
	KUNIT_EXPECT_EQ(test, device_get_committed_trust_level(&ctx->dev),
			DEVICE_TRUST_UNRESTRICTED);
	KUNIT_ASSERT_EQ(test, device_trust_test_attach_unrestricted(ctx), 0);
	KUNIT_EXPECT_EQ(test, ctx->probe_count, 2);
	KUNIT_EXPECT_EQ(test, ctx->configure_count, 0);
}

struct device_trust_registration_test {
	struct notifier_block notifier;
	struct device_trust_test_context *ctx;
	int result;
	bool notified;
};

static int device_trust_test_notify_add(struct notifier_block *notifier,
					unsigned long action, void *data)
{
	struct device_trust_registration_test *registration =
		container_of(notifier, struct device_trust_registration_test, notifier);
	struct device_trust_test_context *ctx = registration->ctx;

	if (action != BUS_NOTIFY_ADD_DEVICE || data != &ctx->dev)
		return NOTIFY_DONE;
	registration->result = device_driver_attach_unrestricted(&ctx->drv, &ctx->dev);
	registration->notified = true;
	return NOTIFY_OK;
}

static void device_trust_unrestricted_registration_test(struct kunit *test)
{
	struct device_trust_registration_test registration = {
		.notifier.notifier_call = device_trust_test_notify_add,
	};
	struct device_trust_test_context *ctx;
	bool allowed;
	int ret;

	ctx = device_trust_test_device_alloc(test, &device_trust_test_plain_bus,
					     DEVICE_TRUST_POLICY_DEFAULT, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	KUNIT_ASSERT_PTR_EQ(test, ctx->dev.p, NULL);
	device_release_driver(&ctx->dev);
	KUNIT_EXPECT_PTR_EQ(test, ctx->dev.p, NULL);
	KUNIT_EXPECT_PTR_EQ(test, ctx->dev.driver, NULL);
	KUNIT_EXPECT_EQ(test, ctx->remove_count, 0);
	ctx->match_ret = 0;
	KUNIT_ASSERT_EQ(test, device_trust_test_driver_register(test, ctx), 0);
	registration.ctx = ctx;
	KUNIT_ASSERT_EQ(test, bus_register_notifier(ctx->dev.bus, &registration.notifier), 0);
	ret = device_add(&ctx->dev);
	if (!ret)
		ctx->device_registered = true;
	bus_unregister_notifier(ctx->dev.bus, &registration.notifier);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_ASSERT_TRUE(test, registration.notified);
	KUNIT_EXPECT_EQ(test, registration.result, -EAGAIN);
	KUNIT_EXPECT_EQ(test, ctx->probe_count, 0);
	KUNIT_EXPECT_FALSE(test, device_is_bound(&ctx->dev));
	allowed = device_trust_unrestricted_test_allowed(test, &ctx->dev);
	KUNIT_EXPECT_EQ(test, device_trust_test_attach_unrestricted(ctx), allowed ? 0 : -EPERM);
	KUNIT_EXPECT_EQ(test, ctx->probe_count, allowed ? 1 : 0);
}

static void device_trust_unrestricted_test_release_resource(void *data)
{
	struct device_trust_test_context *ctx = data;

	ctx->release_count++;
}

static int device_trust_unrestricted_test_probe(struct device *dev)
{
	struct device_trust_test_context *ctx = to_device_trust_test_context(dev);
	int ret;

	ret = devm_add_action(dev, device_trust_unrestricted_test_release_resource, ctx);
	if (ret)
		return ret;
	dev_set_drvdata(dev, ctx);
	return device_trust_test_probe(dev);
}

enum device_trust_test_operation {
	DEVICE_TRUST_TEST_UNRESTRICTED_ATTACH,
	DEVICE_TRUST_TEST_ATTACH,
	DEVICE_TRUST_TEST_SCAN,
	DEVICE_TRUST_TEST_UNBIND,
	DEVICE_TRUST_TEST_REMOVE,
	DEVICE_TRUST_TEST_LOCK,
};

struct device_trust_test_worker {
	struct device_trust_test_context *ctx;
	struct task_struct *task;
	struct completion started;
	struct completion done;
	struct completion *resume;
	enum device_trust_test_operation operation;
	int result;
};

struct device_trust_test_race {
	struct device_trust_test_context *ctx;
	struct completion entered;
	struct completion resume;
	struct device_trust_test_worker workers[2];
};

static int device_trust_test_worker(void *data)
{
	struct device_trust_test_worker *worker = data;
	struct device_trust_test_context *ctx = worker->ctx;

	if (worker->operation == DEVICE_TRUST_TEST_LOCK)
		device_lock(&ctx->dev);
	complete(&worker->started);
	switch (worker->operation) {
	case DEVICE_TRUST_TEST_UNRESTRICTED_ATTACH:
		worker->result = device_driver_attach_unrestricted(&ctx->drv, &ctx->dev);
		break;
	case DEVICE_TRUST_TEST_ATTACH:
		worker->result = device_driver_attach(&ctx->drv, &ctx->dev);
		break;
	case DEVICE_TRUST_TEST_SCAN:
		worker->result = device_attach(&ctx->dev);
		break;
	case DEVICE_TRUST_TEST_UNBIND:
		device_release_driver(&ctx->dev);
		worker->result = 0;
		break;
	case DEVICE_TRUST_TEST_REMOVE:
		device_del(&ctx->dev);
		ctx->device_registered = false;
		worker->result = 0;
		break;
	case DEVICE_TRUST_TEST_LOCK:
		wait_for_completion(worker->resume);
		device_unlock(&ctx->dev);
		worker->result = 0;
		break;
	}
	complete(&worker->done);
	return 0;
}

static void device_trust_test_race_stop(void *data)
{
	struct device_trust_test_race *race = data;
	unsigned int i;

	complete_all(&race->resume);
	for (i = 0; i < ARRAY_SIZE(race->workers); i++) {
		if (!race->workers[i].task)
			continue;
		kthread_stop(race->workers[i].task);
		put_task_struct(race->workers[i].task);
	}
}

static struct device_trust_test_race *device_trust_test_race_alloc(struct kunit *test)
{
	struct device_trust_test_context *ctx;
	struct device_trust_test_race *race;

	ctx = device_trust_unrestricted_test_register(test, &device_trust_test_plain_bus, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	if (!device_trust_unrestricted_test_allowed(test, &ctx->dev))
		kunit_skip(test, "boot policy disallows unrestricted-only attachment");
	race = kunit_kzalloc(test, sizeof(*race), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, race);
	race->ctx = ctx;
	init_completion(&race->entered);
	init_completion(&race->resume);
	ctx->probe_entered = &race->entered;
	ctx->probe_continue = &race->resume;
	ctx->drv.probe = device_trust_unrestricted_test_probe;
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test,
							device_trust_test_race_stop, race), 0);
	return race;
}

static int device_trust_test_start_worker(struct device_trust_test_race *race,
					  unsigned int index,
					  enum device_trust_test_operation operation)
{
	struct device_trust_test_worker *worker = &race->workers[index];
	struct task_struct *task;

	worker->ctx = race->ctx;
	worker->operation = operation;
	worker->resume = &race->resume;
	init_completion(&worker->started);
	init_completion(&worker->done);
	task = kthread_create(device_trust_test_worker, worker, "device-trust-race");
	if (IS_ERR(task))
		return PTR_ERR(task);
	get_task_struct(task);
	worker->task = task;
	wake_up_process(task);
	return 0;
}

static bool device_trust_test_wait_for_contention(struct device_trust_test_worker *worker)
{
	unsigned long deadline = jiffies + 5 * HZ;

	do {
		if (completion_done(&worker->done))
			return false;
		/* These workers only sleep on driver_lock after taking the device lock. */
		if (READ_ONCE(worker->task->__state) == TASK_UNINTERRUPTIBLE &&
		    mutex_is_locked(&worker->ctx->dev.mutex))
			return true;
		usleep_range(1000, 2000);
	} while (time_before(jiffies, deadline));
	return false;
}

static void device_trust_unrestricted_concurrent_test(struct kunit *test,
						      enum device_trust_test_operation operation)
{
	struct device_trust_test_race *race = device_trust_test_race_alloc(test);
	struct device_trust_test_context *ctx = race->ctx;
	bool unbind = operation != DEVICE_TRUST_TEST_SCAN;

	KUNIT_ASSERT_EQ(test,
		device_trust_test_start_worker(race, 0,
					       DEVICE_TRUST_TEST_UNRESTRICTED_ATTACH), 0);
	KUNIT_ASSERT_NE(test, wait_for_completion_timeout(&race->entered, 5 * HZ), 0UL);
	KUNIT_ASSERT_EQ(test, device_trust_test_start_worker(race, 1, operation), 0);
	KUNIT_ASSERT_NE(test, wait_for_completion_timeout(&race->workers[1].started, 5 * HZ), 0UL);
	KUNIT_ASSERT_TRUE(test, device_trust_test_wait_for_contention(&race->workers[1]));
	KUNIT_EXPECT_FALSE(test, device_is_bound(&ctx->dev));
	KUNIT_EXPECT_TRUE(test, device_is_registered(&ctx->dev));
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&ctx->dev), DEVICE_TRUST_UNRESTRICTED);
	KUNIT_EXPECT_EQ(test, ctx->release_count, 0);
	KUNIT_EXPECT_EQ(test, ctx->remove_count, 0);

	complete(&race->resume);
	KUNIT_ASSERT_NE(test, wait_for_completion_timeout(&race->workers[0].done, 5 * HZ), 0UL);
	KUNIT_ASSERT_NE(test, wait_for_completion_timeout(&race->workers[1].done, 5 * HZ), 0UL);
	KUNIT_EXPECT_EQ(test, race->workers[0].result, 0);
	KUNIT_EXPECT_EQ(test, race->workers[1].result, unbind ? 0 : 1);
	KUNIT_EXPECT_EQ(test, ctx->probe_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->probe_exit_level, DEVICE_TRUST_UNRESTRICTED);
	KUNIT_EXPECT_EQ(test, ctx->release_count, unbind ? 1 : 0);
	KUNIT_EXPECT_EQ(test, ctx->remove_count, unbind ? 1 : 0);
	KUNIT_EXPECT_EQ(test, device_is_bound(&ctx->dev), !unbind);
	KUNIT_EXPECT_EQ(test, device_is_registered(&ctx->dev),
			operation != DEVICE_TRUST_TEST_REMOVE);
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&ctx->dev),
			unbind ? DEVICE_TRUST_BLOCKED : DEVICE_TRUST_UNRESTRICTED);
}

static void device_trust_unrestricted_scan_race_test(struct kunit *test)
{
	device_trust_unrestricted_concurrent_test(test, DEVICE_TRUST_TEST_SCAN);
}

static void device_trust_unrestricted_unbind_race_test(struct kunit *test)
{
	device_trust_unrestricted_concurrent_test(test, DEVICE_TRUST_TEST_UNBIND);
}

static void device_trust_unrestricted_remove_race_test(struct kunit *test)
{
	device_trust_unrestricted_concurrent_test(test, DEVICE_TRUST_TEST_REMOVE);
}

static void device_trust_unrestricted_device_lock_test(struct kunit *test)
{
	struct device_trust_test_race *race = device_trust_test_race_alloc(test);
	struct device_trust_test_context *ctx = race->ctx;

	ctx->probe_entered = NULL;
	ctx->probe_continue = NULL;
	KUNIT_ASSERT_EQ(test, device_trust_test_start_worker(race, 0, DEVICE_TRUST_TEST_LOCK), 0);
	KUNIT_ASSERT_NE(test, wait_for_completion_timeout(&race->workers[0].started, 5 * HZ), 0UL);
	KUNIT_ASSERT_EQ(test,
		device_trust_test_start_worker(race, 1,
					       DEVICE_TRUST_TEST_UNRESTRICTED_ATTACH), 0);
	KUNIT_ASSERT_NE(test, wait_for_completion_timeout(&race->workers[1].done, 5 * HZ), 0UL);
	KUNIT_EXPECT_EQ(test, race->workers[1].result, 0);
	KUNIT_EXPECT_EQ(test, ctx->probe_count, 1);
	KUNIT_EXPECT_TRUE(test, device_is_bound(&ctx->dev));
	complete(&race->resume);
	KUNIT_ASSERT_NE(test, wait_for_completion_timeout(&race->workers[0].done, 5 * HZ), 0UL);
}

static void device_trust_unrestricted_busy_probe_test(struct kunit *test)
{
	struct device_trust_test_race *race = device_trust_test_race_alloc(test);
	struct device_trust_test_context *ctx = race->ctx;

	KUNIT_ASSERT_EQ(test, device_trust_test_start_worker(race, 0, DEVICE_TRUST_TEST_ATTACH), 0);
	KUNIT_ASSERT_NE(test, wait_for_completion_timeout(&race->entered, 5 * HZ), 0UL);
	KUNIT_EXPECT_EQ(test, device_driver_attach_unrestricted(&ctx->drv, &ctx->dev), -EBUSY);
	KUNIT_EXPECT_FALSE(test, device_is_bound(&ctx->dev));
	KUNIT_EXPECT_EQ(test, ctx->release_count, 0);
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&ctx->dev), DEVICE_TRUST_UNRESTRICTED);
	complete(&race->resume);
	KUNIT_ASSERT_NE(test, wait_for_completion_timeout(&race->workers[0].done, 5 * HZ), 0UL);
	KUNIT_EXPECT_EQ(test, race->workers[0].result, 0);
	KUNIT_EXPECT_EQ(test, ctx->probe_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->probe_exit_level, DEVICE_TRUST_UNRESTRICTED);
	KUNIT_EXPECT_EQ(test, ctx->release_count, 0);
	KUNIT_EXPECT_TRUE(test, device_is_bound(&ctx->dev));
}

static void device_trust_unrestricted_probe_failure_test(struct kunit *test)
{
	static const int errors[] = { -EIO, -EPROBE_DEFER };
	static const int expected[] = { -EIO, -EAGAIN };
	struct device_trust_test_context *ctx;
	int i;

	ctx = device_trust_unrestricted_test_register(test, &device_trust_test_plain_bus, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	if (!device_trust_unrestricted_test_allowed(test, &ctx->dev))
		kunit_skip(test, "boot policy disallows unrestricted-only attachment");
	ctx->drv.probe = device_trust_unrestricted_test_probe;

	for (i = 0; i < ARRAY_SIZE(errors); i++) {
		ctx->probe_ret = errors[i];
		KUNIT_ASSERT_EQ(test, device_trust_test_attach_unrestricted(ctx),
				expected[i]);
		KUNIT_EXPECT_FALSE(test, device_is_bound(&ctx->dev));
		KUNIT_EXPECT_PTR_EQ(test, ctx->dev.driver, NULL);
		KUNIT_EXPECT_PTR_EQ(test, dev_get_drvdata(&ctx->dev), NULL);
		KUNIT_EXPECT_EQ(test, ctx->probe_level, DEVICE_TRUST_UNRESTRICTED);
		KUNIT_EXPECT_EQ(test, ctx->probe_count, i + 1);
		KUNIT_EXPECT_EQ(test, ctx->release_count, i + 1);
		KUNIT_EXPECT_EQ(test, device_get_trust_level(&ctx->dev),
				DEVICE_TRUST_BLOCKED);
		KUNIT_EXPECT_EQ(test, device_get_committed_trust_level(&ctx->dev),
				DEVICE_TRUST_UNRESTRICTED);
	}
	KUNIT_EXPECT_EQ(test, ctx->configure_count, 0);
	KUNIT_EXPECT_EQ(test, ctx->cleanup_count, 0);
	KUNIT_EXPECT_EQ(test, ctx->remove_count, 0);
	ctx->probe_ret = 0;
	KUNIT_ASSERT_EQ(test, device_trust_test_attach_unrestricted(ctx), 0);
	KUNIT_EXPECT_PTR_EQ(test, dev_get_drvdata(&ctx->dev), ctx);
	device_release_driver(&ctx->dev);
	KUNIT_EXPECT_EQ(test, ctx->release_count, ARRAY_SIZE(errors) + 1);
	KUNIT_EXPECT_EQ(test, ctx->remove_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->remove_level, DEVICE_TRUST_UNRESTRICTED);
}

static void device_trust_unrestricted_policy_test(struct kunit *test)
{
	struct device_trust_test_context *ctx;
	enum device_trust_policy default_policy;
	enum device_trust_state state;
	bool driver_rules, override;

	if (!device_trust_unrestricted_test_boot_rules(test, &driver_rules, &default_policy) ||
	    default_policy != DEVICE_TRUST_POLICY_UNRESTRICTED)
		kunit_skip(test, "requires device_trust.default=unrestricted");
	ctx = device_trust_unrestricted_test_register(test, &device_trust_test_plain_bus, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	state = ctx->dev.p->trust_state;
	override = ctx->dev.p->trust_policy_override;
	device_lock(&ctx->dev);
	device_trust_expect_policy_locked(test, &ctx->dev);
	device_unlock(&ctx->dev);
	KUNIT_EXPECT_EQ(test, ctx->dev.p->trust_state, state);
	KUNIT_EXPECT_EQ(test, (bool)ctx->dev.p->trust_policy_override, override);
	KUNIT_EXPECT_EQ(test, ctx->probe_count, 0);
}

static void device_trust_sysfs_boot_policy_test(struct kunit *test)
{
	struct device_trust_test_context *ctx;
	struct device_attribute *attr = NULL;
	struct attribute **attrs;
	enum device_trust_policy policy, target, default_policy;
	const char *value;
	bool configured, driver_rules, allowed, override;
	ssize_t ret;

	configured = device_trust_unrestricted_test_boot_rules(test, &driver_rules,
							     &default_policy);
	ctx = device_trust_unrestricted_test_register(test, &device_trust_test_plain_bus, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	policy = ctx->dev.trust_policy;
	override = ctx->dev.p->trust_policy_override;
	for (attrs = device_trust_attr_group.attrs; *attrs; attrs++) {
		if (!strcmp((*attrs)->name, "trust_policy")) {
			attr = container_of(*attrs, struct device_attribute, attr);
			break;
		}
	}
	KUNIT_ASSERT_NOT_NULL(test, attr);
	if (policy == DEVICE_TRUST_POLICY_ADVERSARY) {
		target = DEVICE_TRUST_POLICY_UNRESTRICTED;
		value = "unrestricted";
	} else {
		target = DEVICE_TRUST_POLICY_ADVERSARY;
		value = "adversary";
	}
	allowed = configured && default_policy != DEVICE_TRUST_POLICY_UNRESTRICTED;
	ret = attr->store_const(&ctx->dev, attr, value, strlen(value));
	KUNIT_ASSERT_EQ(test, ret, allowed ? (ssize_t)strlen(value) : -EBUSY);
	KUNIT_EXPECT_EQ(test, ctx->dev.trust_policy, allowed ? target : policy);
	KUNIT_EXPECT_EQ(test, (bool)ctx->dev.p->trust_policy_override,
			allowed ? true : override);
	KUNIT_EXPECT_EQ(test, ctx->probe_count, 0);

	if (!configured) {
		KUNIT_ASSERT_EQ(test, policy, DEVICE_TRUST_POLICY_DEFAULT);
		ret = attr->store_const(&ctx->dev, attr, "default", 7);
		KUNIT_EXPECT_EQ(test, ret, 7);
		KUNIT_EXPECT_EQ(test, (bool)ctx->dev.p->trust_policy_override, override);
		/* Existing bus authorization remains available on legacy boots. */
		KUNIT_ASSERT_EQ(test, device_trust_set_policy(&ctx->dev,
							      DEVICE_TRUST_POLICY_BLOCKED), 0);
		KUNIT_ASSERT_EQ(test, device_trust_set_policy(&ctx->dev,
							      DEVICE_TRUST_POLICY_UNRESTRICTED), 0);
		KUNIT_EXPECT_EQ(test, ctx->dev.p->trust_state, DEVICE_TRUST_AUTHORIZED);
	}
}

static void device_trust_legacy_bus_policy_test(struct kunit *test)
{
	struct device_trust_test_context *ctx;
	bool driver_rules;
	int ret;

	if (device_trust_unrestricted_test_boot_rules(test, &driver_rules, NULL))
		kunit_skip(test, "requires a legacy boot without device trust options");
	ctx = device_trust_test_device_register(test, &device_trust_test_plain_bus,
						DEVICE_TRUST_POLICY_ADVERSARY);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	ctx->match_ret = 0;
	ret = device_trust_test_driver_register(test, ctx);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_ASSERT_EQ(test, ctx->dev.trust_policy, DEVICE_TRUST_POLICY_ADVERSARY);
	KUNIT_EXPECT_EQ(test, device_trust_test_attach_unrestricted(ctx), -EPERM);
	KUNIT_EXPECT_EQ(test, ctx->probe_count, 0);
	KUNIT_ASSERT_EQ(test, device_driver_attach(&ctx->drv, &ctx->dev), 0);
	KUNIT_EXPECT_EQ(test, ctx->probe_level, DEVICE_TRUST_ADVERSARY);
}

static void device_trust_boot_default_test(struct kunit *test)
{
	struct device_trust_test_stub *stub = device_trust_test_stub_alloc(test);
	enum device_trust_policy expected, initial;
	struct device *dev;
	bool configured, driver_rules;

	configured = device_trust_unrestricted_test_boot_rules(test, &driver_rules, &expected);
	KUNIT_EXPECT_EQ(test, device_trust_enabled(), configured);
	dev = device_trust_test_stub_reset(stub, NULL, NULL, DEVICE_TRUST_POLICY_DEFAULT);
	for (initial = DEVICE_TRUST_POLICY_DEFAULT;
	     initial <= DEVICE_TRUST_POLICY_UNRESTRICTED; initial++) {
		dev->trust_policy = initial;
		device_trust_init(dev);
		KUNIT_EXPECT_EQ(test, dev->trust_policy,
				expected == DEVICE_TRUST_POLICY_DEFAULT ? initial : expected);
	}
}

static struct kunit_case device_trust_unrestricted_test_cases[] = {
#if IS_BUILTIN(CONFIG_DM_KUNIT_TEST)
	KUNIT_CASE(device_trust_boot_separator_test),
#endif
	KUNIT_CASE(device_trust_boot_default_test),
	KUNIT_CASE(device_trust_sysfs_boot_policy_test),
	KUNIT_CASE(device_trust_legacy_bus_policy_test),
	KUNIT_CASE(device_trust_unrestricted_boot_policy_test),
	KUNIT_CASE(device_trust_unrestricted_attach_test),
	KUNIT_CASE(device_trust_unrestricted_registration_test),
	KUNIT_CASE(device_trust_unrestricted_scan_race_test),
	KUNIT_CASE(device_trust_unrestricted_unbind_race_test),
	KUNIT_CASE(device_trust_unrestricted_remove_race_test),
	KUNIT_CASE(device_trust_unrestricted_device_lock_test),
	KUNIT_CASE(device_trust_unrestricted_busy_probe_test),
	KUNIT_CASE(device_trust_unrestricted_probe_failure_test),
	KUNIT_CASE(device_trust_unrestricted_policy_test),
	{}
};

static int device_trust_test_init(struct kunit *test)
{
	if (device_trust_enabled())
		kunit_skip(test, "live boot policy can replace fixture policies");

	return 0;
}

static int device_trust_test_bus_register(const struct bus_type *bus)
{
	static const struct attribute probe = { .name = "drivers_probe" };
	static const struct attribute autoprobe = { .name = "drivers_autoprobe" };
	struct kobject *kobj;
	int ret;

	ret = bus_register(bus);
	if (ret)
		return ret;

	/* Exclude userspace changes to probe scheduling before creating fixtures. */
	kobj = &bus_get_kset(bus)->kobj;
	sysfs_remove_file(kobj, &probe);
	sysfs_remove_file(kobj, &autoprobe);
	to_subsys_private(kobj)->drivers_autoprobe = 1;
	return 0;
}

static int device_trust_test_suite_init(struct kunit_suite *suite)
{
	int ret;

	ret = device_trust_test_bus_register(&device_trust_test_plain_bus);
	if (ret)
		return ret;

	ret = device_trust_test_bus_register(&device_trust_test_resolving_bus);
	if (ret) {
		bus_unregister(&device_trust_test_plain_bus);
		return ret;
	}

	return 0;
}

static void device_trust_test_suite_exit(struct kunit_suite *suite)
{
	bus_unregister(&device_trust_test_resolving_bus);
	bus_unregister(&device_trust_test_plain_bus);
}

static struct kunit_suite device_trust_test_suite = {
	.name = "device-trust",
	.init = device_trust_test_init,
	.suite_init = device_trust_test_suite_init,
	.suite_exit = device_trust_test_suite_exit,
	.test_cases = device_trust_test_cases,
};

static struct kunit_suite device_trust_unrestricted_test_suite = {
	.name = "device-trust-unrestricted",
	.suite_init = device_trust_test_suite_init,
	.suite_exit = device_trust_test_suite_exit,
	.test_cases = device_trust_unrestricted_test_cases,
};

kunit_test_suites(&device_trust_test_suite, &device_trust_unrestricted_test_suite);

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");
MODULE_DESCRIPTION("KUnit tests for device trust");
MODULE_LICENSE("GPL");
