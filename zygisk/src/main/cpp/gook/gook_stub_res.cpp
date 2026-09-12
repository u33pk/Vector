// SPDX-License-Identifier: GPL-3.0-or-later
// P12 W2 适配层桩:resources_hook 与 native_api(bridge)属层级 B(Xposed
// 模块原生 API + 资源钩子可不做,research-lsplant §4);Context::InitHooks
// 的 RegisterResourcesHook/RegisterNativeApiBridge 调用以空实现承接,
// HookBridge 照常注册。
#include <jni.h>

namespace vector::native::jni {

void RegisterResourcesHook(JNIEnv *) {}
void RegisterNativeApiBridge(JNIEnv *) {}

}  // namespace vector::native::jni
