# JavaHook

#### 介绍

`head-only`，学习的副产物。不完整，只有拦截功能。

#### 使用

    android::JavaHook hooker("com/bzi_han/test/MainActivity", "TestMethod", "(Ljava/lang/String;)V");
    auto result = hooker.Enable(
        +[](jmethodID *thisMethod, void **args, size_t argsSize, void *artThreadSelf, jvalue *result, const char *shorty) -> void *
        {
            Log("target method has been blocked.");

            return nullptr;
        });

    Log("hook method 'TestMethod' %s", result ? "succeeded" : "failed");