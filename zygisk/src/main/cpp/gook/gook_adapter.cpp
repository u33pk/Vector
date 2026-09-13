// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * gook_adapter.cpp - P12 W2:Vector 适配层(libvector_gook.so)。
 *
 * zygisk::ModuleBase 生命周期 → OnProcessReady(JNIEnv*, const lsp_bridge*)
 * 薄适配(lsp-bridge-abi.md §2 v1)。注入走 gooki daemon 链(MODULE_LOAD/
 * dlopen/门铃 CALL_NATIVE,后期注入模型,proc_args 由 host 填充)。
 *
 * 红线(abi §5):本适配层与 kaemon 之间只经动态符号(libgklsp.so C 导出)
 * 与 lsp_bridge ABI 交互,不静态链接衍生。Vector native 静态库(context/
 * hook_bridge/elf/native_api)与注入方式解耦,原样复用。
 *
 * 门链(与 gklsp hooktest 同级回证):ghost dex(host dex-deliver)→
 * Context::LoadDex → InitArtHooker(InitInfo 六字段 = libgklsp 回调,
 * 替换 Dobby HookInline 与 ElfSymbolCache)→ InitHooks(MakeDexFileTrusted +
 * HookBridge 注册)→ lsplant::Hook(Objects.toString × gk.VHook)。
 * host VERIFY 期望 "VHOOK:<arg>"。
 */
#include <android/log.h>
#include <dlfcn.h>
#include <cstring>
#include <jni.h>
#include <pthread.h>

#include <map>
#include <memory>
#include <span>
#include <string>
#include <string_view>

#include <lsplant.hpp>

#include "core/config_bridge.h"
#include "core/context.h"
#include "lsp_bridge.h"

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "VGOOK", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "VGOOK", __VA_ARGS__)

using namespace vector::native;

/* ---- libgklsp.so C 导出面(dlsym;六字段与数据页读的宿主侧承载) ---- */
struct GklspFace {
    int (*bridge_attach)(uint64_t api_va) = nullptr;
    void *(*inline_hooker)(void *, void *) = nullptr;
    int (*inline_unhooker)(void *) = nullptr;
    void *(*sym_resolve)(const char *, uint32_t) = nullptr;
    void *(*sym_resolve_prefix)(const char *, uint32_t) = nullptr;
    void *(*mem_alloc)(const void *, uint32_t) = nullptr;
    void (*mem_recycle)(void *) = nullptr;
    void *(*jni_env)(void) = nullptr;
    int (*wait_ghost_dex)(uint64_t *, uint32_t *, uint64_t *, int) = nullptr;
    void (*publish)(int, uint64_t) = nullptr;

    bool ok() const {
        return bridge_attach && inline_hooker && inline_unhooker && sym_resolve &&
               sym_resolve_prefix && mem_alloc && mem_recycle && jni_env &&
               wait_ghost_dex && publish;
    }
};
static GklspFace g_gk;
static JavaVM *g_vm;
static const struct lsp_bridge *g_bridge;
static uint64_t g_bridge_va;

/* P13 W2:层级 B 接线(gook_tierb.cpp;scope 模式时由 on_process_ready
 * 在 InitHooks 后调用)。 */
int tierb_run(JNIEnv *env, jobject fw_loader, const struct lsp_bridge *bridge,
              uint64_t bridge_va);

/* 桥页 +0x100 = libgklsp C 导出函数指针表(10×u64;host 代 dlsym ——
 * 适配层运行在 app 主线程 namespace,无法 dlopen/RTLD_NOLOAD 到 daemon
 * 声明域装载的 libgklsp,vec_r0 实录;符号面由 host 解析后随桥页传递)。 */
static bool gk_bridge_load(uint64_t bridge_va) {
    if (g_gk.ok()) return true;
    uint64_t *tbl = (uint64_t *)(bridge_va + 0x100);
    g_gk.bridge_attach = (int (*)(uint64_t))tbl[0];
    g_gk.inline_hooker = (void *(*)(void *, void *))tbl[1];
    g_gk.inline_unhooker = (int (*)(void *))tbl[2];
    g_gk.sym_resolve = (void *(*)(const char *, uint32_t))tbl[3];
    g_gk.sym_resolve_prefix = (void *(*)(const char *, uint32_t))tbl[4];
    g_gk.mem_alloc = (void *(*)(const void *, uint32_t))tbl[5];
    g_gk.mem_recycle = (void (*)(void *))tbl[6];
    g_gk.jni_env = (void *(*)(void))tbl[7];
    g_gk.wait_ghost_dex = (int (*)(uint64_t *, uint32_t *, uint64_t *, int))tbl[8];
    g_gk.publish = (void (*)(int, uint64_t))tbl[9];
    if (!g_gk.ok()) {
        LOGE("bridge face table incomplete");
        return false;
    }
    return true;
}

/* ---- ConfigBridge(无 vectord:obfmap 供给恒等条目 —— 设备 vector.dex
 * 未混淆且 mapping.txt 锚定 XResources 保名,resources_hook 的
 * initXResourcesNative 按前缀 key "android.content.res.XRes" 直查即得
 * 原名;map 空则该 native 静默返 false,资源钩子降级) ---- */
namespace {
class GookConfigBridge final : public ConfigBridge {
public:
    static void install() { instance_ = std::make_unique<GookConfigBridge>(); }
    std::map<std::string, std::string> &obfuscation_map() override { return map_; }
    void obfuscation_map(std::map<std::string, std::string> m) override {
        map_ = std::move(m);
    }

private:
    std::map<std::string, std::string> map_{
        {"android.content.res.XRes", "android.content.res.XRes"}};
};

/* ---- Context 实现:LoadDex 与 VectorModule 同体(ghost dex 非持有) ---- */
class GookContext final : public Context {
public:
    static GookContext *install() {
        auto inst = std::make_unique<GookContext>();
        GookContext *raw = inst.get();
        instance_ = std::move(inst);
        return raw;
    }

    void LoadDex(JNIEnv *env, PreloadedDex &&dex) override {
        LOGI("LoadDex size=%zu addr=%p", dex.size(), dex.data());
        auto classloader_class = lsplant::JNI_FindClass(env, "java/lang/ClassLoader");
        if (!classloader_class) {
            LOGE("FindClass ClassLoader failed");
            return;
        }
        auto getsyscl_mid = lsplant::JNI_GetStaticMethodID(
            env, classloader_class.get(), "getSystemClassLoader",
            "()Ljava/lang/ClassLoader;");
        auto system_classloader = lsplant::JNI_CallStaticObjectMethod(
            env, classloader_class.get(), getsyscl_mid);
        if (!system_classloader) {
            LOGE("getSystemClassLoader failed");
            return;
        }
        auto byte_buffer_class = lsplant::JNI_FindClass(env, "java/nio/ByteBuffer");
        if (!byte_buffer_class) {
            LOGE("FindClass ByteBuffer failed");
            return;
        }
        auto dex_buffer = lsplant::ScopedLocalRef(
            env, env->NewDirectByteBuffer(dex.data(), (jlong)dex.size()));
        if (!dex_buffer) {
            LOGE("NewDirectByteBuffer(ghost dex) failed");
            return;
        }
        auto in_memory_cl_class =
            lsplant::JNI_FindClass(env, "dalvik/system/InMemoryDexClassLoader");
        if (!in_memory_cl_class) {
            LOGE("FindClass InMemoryDexClassLoader failed");
            return;
        }
        auto init_mid = lsplant::JNI_GetMethodID(
            env, in_memory_cl_class.get(), "<init>",
            "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
        if (!init_mid) {
            LOGE("GetMethodID <init> failed");
            return;
        }
        auto new_cl = lsplant::ScopedLocalRef(
            env, env->NewObject(in_memory_cl_class.get(), init_mid, dex_buffer.get(),
                                system_classloader.get()));
        if (env->ExceptionCheck() || !new_cl) {
            env->ExceptionClear();
            LOGE("new InMemoryDexClassLoader failed");
            return;
        }
        inject_class_loader_ = env->NewGlobalRef(new_cl.get());
        LOGI("framework classloader created (ghost dex)");
    }

    int on_process_ready(JNIEnv *env, const struct lsp_bridge *bridge);

    void SetupEntryClass(JNIEnv *env) override {
        /* gate 期 entry = gk.VHook(FindAndCall 未用,仅占位语义);
         * 层级 B 轮换真实 framework dex entry。 */
        auto cls = FindClassFromLoader(env, inject_class_loader_, "gk.VHook");
        if (!cls) {
            LOGE("SetupEntryClass: gk.VHook not found");
            return;
        }
        entry_class_ = (jclass)env->NewGlobalRef(cls.get());
    }
};
}  // namespace

/* ---- lsp_bridge 面导出(host dlsym 后填进 bridge struct) ---- */
extern "C" __attribute__((visibility("default"))) void *gk_bridge_get_jni_env(void) {
    return g_gk.jni_env ? g_gk.jni_env() : nullptr;
}

extern "C" __attribute__((visibility("default"))) int gk_bridge_set_option(
    uint32_t opt) {
    /* v1:仅 DLCLOSE_MODULE_LIBRARY 同语义 —— gook 轨道 ghost 装载不可见,
     * "不卸载"反向确认恒 0;未知码拒(-1)。 */
    return opt == LSP_BRIDGE_OPT_DLCLOSE_MODULE_LIBRARY ? 0 : -1;
}

/* ---- OnProcessReady 主链(GookContext 成员:访问基类 protected 面) ---- */
int GookContext::on_process_ready(JNIEnv *env, const struct lsp_bridge *bridge) {
    /* abi §2:字符串生命周期 = 注入器侧缓冲,返回前自拷贝。 */
    std::string nice_name =
        bridge->proc_args.nice_name ? bridge->proc_args.nice_name : "";
    std::string app_data_dir =
        bridge->proc_args.app_data_dir ? bridge->proc_args.app_data_dir : "";
    LOGI("OnProcessReady uid=%u nice=%s dir=%s system=%u late=%u",
         bridge->proc_args.uid, nice_name.c_str(), app_data_dir.c_str(),
         bridge->proc_args.is_system, bridge->proc_args.is_late_inject);

    /* 1) ghost dex(host dex-deliver 发布 DEX_*;≤15s 有界等)。 */
    uint64_t dex_base = 0, dex_seq = 0;
    uint32_t dex_size = 0;
    if (g_gk.wait_ghost_dex(&dex_base, &dex_size, &dex_seq, 15000) != 0) {
        LOGE("ghost dex slot empty (host 未 dex-deliver?)");
        return -8;
    }
    LOGI("ghost dex base=%llx size=%u seq=%llu",
         (unsigned long long)dex_base, dex_size, (unsigned long long)dex_seq);


    /* 3) dex 装载 + LSPlant Init(六字段 = libgklsp 回调)。 */
    LoadDex(env, PreloadedDex((void *)(uintptr_t)dex_base, dex_size));
    if (!GetCurrentClassLoader()) return -4;
    if (env->ExceptionCheck()) env->ExceptionClear();

    lsplant::InitInfo info;
    info.inline_hooker = [](void *target, void *replace) -> void * {
        return g_gk.inline_hooker(target, replace);
    };
    info.inline_unhooker = [](void *target) -> bool {
        return g_gk.inline_unhooker(target) != 0;
    };
    info.art_symbol_resolver = [](std::string_view name) -> void * {
        return g_gk.sym_resolve(name.data(), (uint32_t)name.size());
    };
    info.art_symbol_prefix_resolver = [](std::string_view name) -> void * {
        return g_gk.sym_resolve_prefix(name.data(), (uint32_t)name.size());
    };
    info.generated_class_name = "Vector_";
    info.generated_source_name = "gook";
    info.executable_memory_allocator =
        [](std::span<const uint8_t> data) -> void * {
        return g_gk.mem_alloc(data.data(), (uint32_t)data.size());
    };
    info.executable_memory_recycler = [](void *memory) {
        g_gk.mem_recycle(memory);
    };
    InitArtHooker(env, info);
    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
        LOGE("pending exception after InitArtHooker");
        return -3;
    }

    /* 4) dex 特权提升 + JNI 桥注册(HookBridge/Resources/NativeApi)。 */
    InitHooks(env);
    if (env->ExceptionCheck()) env->ExceptionClear();

    /* 4.5 P13 W2:层级 B —— 桥页 +0x150 存在 'GVK1' magic(host 侧
     * --scope 全链)则切换真 framework 链:桥 dex 装载 → hook
     * getLegacyModules/getModules → forkCommon 驱动(Vector 原生装载
     * 循环跑,模块经 hook 供给)。否则维持 P12 probe 闭环。 */
    {
        uint32_t magic = 0;
        uint64_t bdva = 0;
        memcpy(&bdva, (const void *)(uintptr_t)(g_bridge_va + 0x150), 8);
        memcpy(&magic, (const void *)(uintptr_t)(g_bridge_va + 0x150 + 12), 4);
        LOGI("tierb probe: magic=%#x bdva=%llx bva=%llx", magic,
             (unsigned long long)bdva, (unsigned long long)g_bridge_va);
        if (magic == 0x314B5647) {
            LOGI("tier-B mode (scope cfg present)");
            return tierb_run(env, GetCurrentClassLoader(), bridge, g_bridge_va);
        }
    }

    /* 5) 回证:hook Objects.toString → gk.VHook.callback(经本进程六字段
     * 链装出的 hook)。host VERIFY 期望 "VHOOK:<arg>"。 */
    SetupEntryClass(env);
    jclass objects = env->FindClass("java/util/Objects");
    jmethodID tostr = env->GetStaticMethodID(
        objects, "toString", "(Ljava/lang/Object;)Ljava/lang/String;");
    jobject target_m = env->ToReflectedMethod(objects, tostr, JNI_TRUE);
    auto vhook_cls = FindClassFromLoader(env, GetCurrentClassLoader(), "gk.VHook");
    if (!vhook_cls || !target_m) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        LOGE("probe setup failed (VHook/target)");
        return -5;
    }
    jmethodID vctor = env->GetMethodID(vhook_cls.get(), "<init>", "()V");
    jobject hooker_obj = env->NewObject(vhook_cls.get(), vctor);
    jmethodID vcb = env->GetMethodID(vhook_cls.get(), "callback",
                                     "([Ljava/lang/Object;)Ljava/lang/Object;");
    jobject cb_m = env->ToReflectedMethod(vhook_cls.get(), vcb, JNI_FALSE);
    if (!hooker_obj || !cb_m) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return -6;
    }
    jobject backup_m = lsplant::Hook(env, target_m, hooker_obj, cb_m);
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (!backup_m) {
        LOGE("lsplant::Hook(via gooki six fields) returned null");
        return -7;
    }
    LOGI("probe hook installed backup=%p", backup_m);
    return 0;
}

static void *vgook_worker(void *) {
    JNIEnv *env = nullptr;
    if (g_vm->AttachCurrentThread(&env, nullptr) != JNI_OK || !env) {
        LOGE("worker AttachCurrentThread failed");
        g_gk.publish(-100, 0);
        return nullptr;
    }
    // Context/ConfigBridge 单例先于主链(InitHooks 的 JNI 桥经 GetInstance
    // 消费);成员函数访问基类 protected 面。
    GookConfigBridge::install();
    auto *c = GookContext::install();
    int rc = c->on_process_ready(env, g_bridge);
    g_vm->DetachCurrentThread();
    g_gk.publish(rc, 0);
    return nullptr;
}

/* ---- 入口(host CALL_NATIVE;api_va=gk_host_api v2,bridge_va=ghost 页) ---- */
extern "C" __attribute__((visibility("default"))) int gk_vector_entry(
    uint64_t api_va, uint64_t bridge_va, uint64_t) {
    if (!gk_bridge_load(bridge_va)) return -1;
    int ba = g_gk.bridge_attach(api_va);
    if (ba != 0) {
        LOGE("entry: bridge_attach=%d", ba);
        return -1;
    }
    JNIEnv *env = (JNIEnv *)g_gk.jni_env();
    if (!env) {
        LOGE("entry: jni_env null (bridge ok)");
        return -2;
    }
    if (g_vm == nullptr && env->GetJavaVM(&g_vm) != JNI_OK) return -2;
    g_bridge = (const struct lsp_bridge *)bridge_va;
    g_bridge_va = bridge_va;
    if (!g_bridge || g_bridge->version != LSP_BRIDGE_VERSION) {
        LOGE("lsp_bridge version mismatch (%u)", g_bridge ? g_bridge->version : 0);
        return -10;
    }
    static pthread_t th;
    if (pthread_create(&th, nullptr, vgook_worker, nullptr) != 0) return -101;
    pthread_detach(th);
    return 0;
}
