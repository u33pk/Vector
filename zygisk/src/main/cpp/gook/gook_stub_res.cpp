// SPDX-License-Identifier: GPL-3.0-or-later
// 适配层桩:仅 native_api(bridge) 仍为桩(Xposed 模块原生 API 的
// lsplant hook DSL 需 CI 级 clang,本地面编不动);resources_hook 自
// P14 起真入编,RegisterResourcesHook 由 resources_hook.cpp 提供。
#include <jni.h>

namespace vector::native::jni {

void RegisterNativeApiBridge(JNIEnv *) {}

}  // namespace vector::native::jni
