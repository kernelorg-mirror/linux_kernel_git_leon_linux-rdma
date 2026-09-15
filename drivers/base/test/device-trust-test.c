// SPDX-License-Identifier: GPL-2.0

#include <kunit/resource.h>
#include <kunit/test.h>

#include <linux/device.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/module.h>

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

	int resolve_ret;
	int configure_ret;
	int probe_ret;
	unsigned int resolve_count;
	unsigned int configure_count;
	unsigned int probe_count;
	unsigned int remove_count;
	unsigned int cleanup_count;
	bool probe_adversarial;
	bool released;
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
	return 1;
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

static bool device_trust_test_plain_bus_registered;
static bool device_trust_test_resolving_bus_registered;

static void device_trust_test_release(struct device *dev)
{
	struct device_trust_test_context *ctx =
		to_device_trust_test_context(dev);

	ctx->released = true;
}

static void device_trust_test_device_unregister(void *data)
{
	struct device_trust_test_context *ctx = data;

	if (!ctx->device_initialized)
		return;

	ctx->device_initialized = false;
	if (ctx->device_registered) {
		ctx->device_registered = false;
		device_unregister(&ctx->dev);
	} else {
		put_device(&ctx->dev);
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
device_trust_test_device_register(struct kunit *test,
				  const struct bus_type *bus,
				  enum device_trust_policy policy)
{
	struct device_trust_test_context *ctx;
	int ret;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	ctx->resolve_level = DEVICE_TRUST_FULL;
	device_initialize(&ctx->dev);
	ctx->dev.bus = bus;
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

	ret = device_add(&ctx->dev);
	if (ret)
		return ERR_PTR(ret);
	ctx->device_registered = true;

	return ctx;
}

static int device_trust_test_driver_register(struct kunit *test,
					     struct device_trust_test_context *ctx)
{
	int ret;

	ctx->drv.name = test->name;
	ctx->drv.bus = ctx->dev.bus ?: &device_trust_test_plain_bus;
	ctx->drv.probe = device_trust_test_probe;
	ctx->drv.remove = device_trust_test_remove;

	ret = driver_register(&ctx->drv);
	if (ret)
		return ret;
	ctx->driver_registered = true;

	return kunit_add_action_or_reset(test,
					 device_trust_test_driver_unregister, ctx);
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

	device_release_driver(&ctx->dev);
	KUNIT_EXPECT_EQ(test, ctx->remove_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->remove_level, DEVICE_TRUST_FULL);
	KUNIT_EXPECT_EQ(test, ctx->cleanup_count, 1);
	KUNIT_EXPECT_EQ(test, ctx->cleanup_level, DEVICE_TRUST_FULL);
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&ctx->dev),
			DEVICE_TRUST_DISABLED);
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

static void device_trust_disabled_bind_test(struct kunit *test)
{
	struct device_trust_test_context *ctx;
	int ret;

	ctx = device_trust_test_device_register(
		test, &device_trust_test_plain_bus,
		DEVICE_TRUST_POLICY_DISABLED);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	ret = device_trust_test_driver_register(test, ctx);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = device_driver_attach(&ctx->drv, &ctx->dev);
	KUNIT_EXPECT_EQ(test, ret, -EPERM);
	KUNIT_EXPECT_FALSE(test, device_is_bound(&ctx->dev));
	KUNIT_EXPECT_EQ(test, ctx->configure_count, 0);
	KUNIT_EXPECT_EQ(test, ctx->probe_count, 0);
	KUNIT_EXPECT_EQ(test, device_get_trust_level(&ctx->dev),
			DEVICE_TRUST_DISABLED);
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

	device_lock(&ctx->dev);
	ctx->dev.trust_policy = DEVICE_TRUST_POLICY_FULL;
	ctx->dev.driver = &ctx->drv;
	ret = device_bind_driver(&ctx->dev);
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

static struct kunit_case device_trust_test_cases[] = {
	KUNIT_CASE(device_trust_default_bind_test),
	KUNIT_CASE(device_trust_bus_adversary_bind_test),
	KUNIT_CASE(device_trust_disabled_bind_test),
	KUNIT_CASE(device_trust_generic_adversary_bind_test),
	KUNIT_CASE(device_trust_explicit_policy_mismatch_test),
	KUNIT_CASE(device_trust_probe_failure_test),
	KUNIT_CASE(device_trust_probe_defer_test),
	KUNIT_CASE(device_trust_dma_failure_test),
	KUNIT_CASE(device_trust_force_bind_guard_test),
	KUNIT_CASE(device_trust_legacy_force_bind_test),
	KUNIT_CASE(device_trust_busless_force_bind_test),
	{}
};

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
	.suite_init = device_trust_test_suite_init,
	.suite_exit = device_trust_test_suite_exit,
	.test_cases = device_trust_test_cases,
};

kunit_test_suite(device_trust_test_suite);

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");
MODULE_DESCRIPTION("KUnit tests for device trust");
MODULE_LICENSE("GPL");
