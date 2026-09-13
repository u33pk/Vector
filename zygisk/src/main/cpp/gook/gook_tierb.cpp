// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * gook_tierb.cpp - P13 W2:层级 B 接线(native 配置消费 + framework 驱动)。
 *
 * 由 gook_adapter.cpp 在 InitArtHooker/InitHooks 完成后调用 tierb_run:
 * ① 桥页 +0x150 magic('GVK1')判定 scope 模式;
 * ② 装载 gook_bridge.dex(parent = framework loader);
 * ③ RegisterNatives 绑定 nativeProvideLegacyModules/Modules(本文件);
 * ④ lsplant::Hook VectorServiceClient.getLegacyModules/getModules
 *   (hooker 对象/回调 = gk.VectorGook;Vector 原生装载循环照跑);
 * ⑤ 反射调 org.matrix.vector.core.Main.forkCommon(false, true,
 *   niceName, appDir, null) —— binder=null 时 VectorServiceClient
 *   全链容忍(Main.kt:32-79/VectorServiceClient.kt:25-66 实证);
 * ⑥ initXResources 自带 try-catch(Throwable)+disableResources 门
 *   (XposedBridge.java:65-101),ResourcesHook 桩缺席优雅降级。
 *
 * R8 混淆名(锚定本地 mapping.txt == 设备 vector.dex md5 b911da81):
 *   VectorServiceClient -> p3(getLegacyModules -> g / getModules -> b)
 *   LoadedModule -> x0(字段 packageName->a appId->b versionCode->c
 *     apkPath->d code->e applicationInfo->f service->g)
 *   ModuleCode -> a1(preLoadedDexes->a moduleClassNames->b
 *     moduleLibraryNames->c legacy->d targetApiVersion->e
 *     autoHotReload->f exceptionPassthrough->g)
 *   Main -> 原名(forkCommon keep 规则)
 * 配置块布局(host gook-core/src/vector.rs 同源):
 *   +0x150: u64 bridge_dex_va; u32 size; u32 magic 'GVK1'
 *   +0x200: u32 magic 'GVC1'; u32 n; ×n{apk[96],entries[256],
 *           n_dex u32, flags u32(bit0=legacy), dex_va[4]×u64,
 *           dex_size[4]×u32}(@384B/条)
 */
#include <android/log.h>
#include <jni.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "lsp_bridge.h"
#include <sys/ioctl.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <lsplant.hpp>

#include "core/context.h"

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "VGOOK", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "VGOOK", __VA_ARGS__)

using namespace vector::native;

/* ---- 配置块读取(桥页 = 注入器侧缓冲,进程内直接可读) ---- */
static const uint8_t *g_cfg;   /* 桥页基址(gook_adapter 转交) */

/* 单条记录实际跨度 408B:apk[96]+entries[256]+n_dex(4)+flags(4)
 * +dex_va[4]×8+dex_size[4]×4。初版 384 是算错 —— n≥2 时第 i 条的
 * dex_size 会落在第 i+1 条的 apk 槽内(宿主端 vector.rs 已同修)。 */
static const uint8_t *cfg_module(size_t i) {
    return g_cfg + 0x200 + 8 + i * 408;
}

/* str: 桥页 NUL 终结定长字段 */
static std::string cfg_str(const uint8_t *p, size_t cap) {
    size_t n = 0;
    while (n < cap && p[n]) n++;
    return std::string((const char *)p, n);
}

/* ---- ashmem: ghost dex → SharedMemory ---- */
static jobject ghost_to_shared_memory(JNIEnv *env, uint64_t va, uint32_t size,
                                      const char *name) {
    /* memfd(Android 11+ SharedMemory 标准路径;NDK 无 sys/ashmem.h) */
    /* bionic 头在 API<29 目标下不导出 wrapper,直落 syscall(236) */
    int fd = (int)syscall(SYS_memfd_create, name, 0);
    if (fd < 0) {
        LOGE("memfd_create failed %s", name);
        return nullptr;
    }
    if (ftruncate(fd, size) != 0) {
        close(fd);
        LOGE("ftruncate failed %s", name);
        return nullptr;
    }
    void *m = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (m == MAP_FAILED) {
        close(fd);
        LOGE("ashmem mmap failed %s", name);
        return nullptr;
    }
    memcpy(m, (const void *)(uintptr_t)va, size);
    munmap(m, size);

    /* FileDescriptor: new + fid descriptor(int, private;JNI 可直取) */
    jclass fdc = env->FindClass("java/io/FileDescriptor");
    if (!fdc) { close(fd); return nullptr; }
    jobject fdo = env->NewObject(fdc,
        env->GetMethodID(fdc, "<init>", "()V"));
    if (!fdo) { close(fd); return nullptr; }
    jfieldID fid = env->GetFieldID(fdc, "descriptor", "I");
    if (!fid) { close(fd); return nullptr; }
    env->SetIntField(fdo, fid, fd);

    jclass smc = (jclass)env->FindClass("android/os/SharedMemory");
    if (!smc) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        LOGE("FindClass SharedMemory null");
        close(fd);
        return nullptr;
    }
    jmethodID from_fd = env->GetStaticMethodID(smc, "fromFd",
        "(Ljava/io/FileDescriptor;)Landroid/os/SharedMemory;");
    if (!from_fd) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        /* 备选:fromFd(FileDescriptor, String)(部分版本重载) */
        from_fd = env->GetStaticMethodID(smc, "fromFd",
            "(Ljava/io/FileDescriptor;Ljava/lang/String;)Landroid/os/SharedMemory;");
        if (from_fd) {
            jobject sm2 = env->CallStaticObjectMethod(smc, from_fd, fdo,
                env->NewStringUTF(name));
            if (!env->ExceptionCheck()) {
                /* 走重载出口(fd 所有权同样移交) */
                return sm2;
            }
            env->ExceptionClear();
        }
        LOGE("SharedMemory.fromFd missing (API<29?)");
        close(fd);
        return nullptr;
    }
    jobject sm = env->CallStaticObjectMethod(smc, from_fd, fdo);
    if (env->ExceptionCheck()) { env->ExceptionClear(); close(fd); return nullptr; }
    /* fd 所有权移交 SharedMemory;不 close(进程存活期持有,量级 =
     * 模块 dex 数,可接受)。 */
    return sm;
}

/* ---- 反射构造 ModuleCode/LoadedModule ----
 * AIDL parcelable:public 字段;JNI GetFieldID 对 private 亦有效。 */
static jobject build_module_code(JNIEnv *env, jobject loader,
                                 const uint8_t *rec) {
    uint32_t n_dex;
    memcpy(&n_dex, rec + 96 + 256, 4);
    if (n_dex > 4) n_dex = 4;

    auto load = [&](const char *name) -> jclass {
        jclass s = env->FindClass("java/lang/String");
        jstring cn = env->NewStringUTF(name);
        jmethodID mid = env->GetMethodID(
            env->GetObjectClass(loader), "loadClass",
            "(Ljava/lang/String;)Ljava/lang/Class;");
        jobject c = env->CallObjectMethod(loader, mid, cn);
        if (env->ExceptionCheck()) { env->ExceptionClear(); return nullptr; }
        return (jclass)c;
    };
    jclass code_c = load("a1");  /* ModuleCode(R8) */
    if (!code_c) return nullptr;

    jobjectArray dexes = env->NewObjectArray(n_dex,
        (jclass)env->FindClass("android/os/SharedMemory"), nullptr);
    for (uint32_t i = 0; i < n_dex; i++) {
        uint64_t va; uint32_t sz;
        memcpy(&va, rec + 96 + 256 + 8 + i * 8, 8);
        memcpy(&sz, rec + 96 + 256 + 8 + 32 + i * 4, 4);
        static uint32_t sm_seq;
        char nm[32];
        snprintf(nm, sizeof(nm), "gvk%u_%u", sm_seq++, i);
        jobject sm = ghost_to_shared_memory(env, va, sz, nm);
        if (!sm) return nullptr;
        env->SetObjectArrayElement(dexes, i, sm);
    }
    jobject dex_list = env->CallStaticObjectMethod(
        (jclass)env->FindClass("java/util/Arrays"),
        env->GetStaticMethodID((jclass)env->FindClass("java/util/Arrays"),
            "asList", "([Ljava/lang/Object;)Ljava/util/List;"),
        dexes);

    jobject code = env->AllocObject(code_c);
    auto set = [&](const char *n, const char *sig, jobject v) {
        env->SetObjectField(code, env->GetFieldID(code_c, n, sig), v);
    };
    set("a", "Ljava/util/List;", dex_list);              /* preLoadedDexes */
    /* moduleClassNames = entries(逗号分隔)→ List<String> */
    std::string entries = cfg_str(rec + 96, 256);
    /* entries 拆分由 ArrayList 逐个 add */
    jobject name_list = env->NewObject(
        (jclass)env->FindClass("java/util/ArrayList"),
        env->GetMethodID((jclass)env->FindClass("java/util/ArrayList"),
                         "<init>", "()V"));
    jclass alc = (jclass)env->FindClass("java/util/ArrayList");
    jmethodID add = env->GetMethodID(alc, "add", "(Ljava/lang/Object;)Z");
    {
        size_t pos = 0;
        while (pos < entries.size()) {
            size_t comma = entries.find(',', pos);
            if (comma == std::string::npos) comma = entries.size();
            jstring s = env->NewStringUTF(entries.substr(pos, comma - pos).c_str());
            env->CallBooleanMethod(name_list, add, s);
            pos = comma + 1;
        }
    }
    set("b", "Ljava/util/List;", name_list);              /* moduleClassNames */
    jobject empty_list = env->NewObject(alc, env->GetMethodID(alc, "<init>", "()V"));
    set("c", "Ljava/util/List;", empty_list);             /* moduleLibraryNames */

    /* 标量字段(R8 名) */
    env->SetBooleanField(code, env->GetFieldID(code_c, "d", "Z"), JNI_TRUE);  /* legacy */
    env->SetIntField(code, env->GetFieldID(code_c, "e", "I"), 100); /* targetApiVersion
                                     <102: blockLegacyApi=false, legacy API 可用 */
    env->SetBooleanField(code, env->GetFieldID(code_c, "f", "Z"), JNI_FALSE); /* autoHotReload */
    env->SetBooleanField(code, env->GetFieldID(code_c, "g", "Z"), JNI_FALSE); /* exceptionPassthrough */
    return code;
}

static jobject build_loaded_module(JNIEnv *env, jobject loader,
                                   const uint8_t *rec, jobject code) {
    auto load = [&](const char *name) -> jclass {
        jmethodID mid = env->GetMethodID(
            env->GetObjectClass(loader), "loadClass",
            "(Ljava/lang/String;)Ljava/lang/Class;");
        jstring cn = env->NewStringUTF(name);
        jobject c = env->CallObjectMethod(loader, mid, cn);
        if (env->ExceptionCheck()) { env->ExceptionClear(); return nullptr; }
        return (jclass)c;
    };
    jclass lm_c = load("x0");  /* LoadedModule(R8) */
    if (!lm_c) return nullptr;
    jobject lm = env->AllocObject(lm_c);
    auto set = [&](const char *n, const char *sig, jobject v) {
        env->SetObjectField(lm, env->GetFieldID(lm_c, n, sig), v);
    };
    /* schema:apk[96] 槽 = host 侧 package 声明(vector.rs publish);
     * packageName 与 apkPath 同值(apkPath 仅作标识字符串,无 native
     * 模块时不被打开)。 */
    std::string pkg = cfg_str(rec, 96);
    set("a", "Ljava/lang/String;", env->NewStringUTF(pkg.c_str()));  /* packageName */
    set("d", "Ljava/lang/String;", env->NewStringUTF(pkg.c_str()));  /* apkPath(标识) */
    set("e", "La1;", code);                                          /* code */
    env->SetIntField(lm, env->GetFieldID(lm_c, "b", "I"), 0);        /* appId */
    env->SetLongField(lm, env->GetFieldID(lm_c, "c", "J"), 0);       /* versionCode */
    /* applicationInfo/service = null(VectorModuleManager 容忍:
     * VectorContext 直接持有;现代 API getModuleApplicationInfo 返 null) */
    return lm;
}

/* ---- RegisterNatives 目标(桥 dex gk.VectorGook) ---- */
static jobject native_provide(JNIEnv *env, jclass, jobjectArray, bool legacy) {
    if (!g_cfg) {
        LOGE("provide: no cfg");
        return nullptr;
    }
    uint32_t n;
    memcpy(&n, g_cfg + 0x200 + 4, 4);
    if (n > 8) n = 8;
    /* loader = 本类 VectorGook 的 classloader(桥 dex loader,parent =
     * framework loader,LoadedModule/ModuleCode/SharedMemory 可见) */
    jclass self = env->FindClass("gk/VectorGook");
    jobject loader = nullptr;
    {
        jclass clc = env->FindClass("java/lang/Class");
        jmethodID gcl = env->GetMethodID(clc, "getClassLoader",
            "()Ljava/lang/ClassLoader;");
        loader = env->CallObjectMethod(self, gcl);
        if (env->ExceptionCheck()) { env->ExceptionClear(); }
    }
    jobject list = env->NewObject(
        (jclass)env->FindClass("java/util/ArrayList"),
        env->GetMethodID((jclass)env->FindClass("java/util/ArrayList"),
                         "<init>", "()V"));
    jclass alc = (jclass)env->FindClass("java/util/ArrayList");
    jmethodID add = env->GetMethodID(alc, "add", "(Ljava/lang/Object;)Z");
    for (uint32_t i = 0; i < n; i++) {
        const uint8_t *rec = cfg_module(i);
        uint32_t flags;
        memcpy(&flags, rec + 96 + 256 + 4, 4);
        bool is_legacy = flags & 1;
        if (is_legacy != legacy) continue;
        jobject code = build_module_code(env, loader, rec);
        if (!code) { LOGE("build_module_code %u failed", i); continue; }
        jobject lm = build_loaded_module(env, loader, rec, code);
        if (!lm) { LOGE("build_loaded_module %u failed", i); continue; }
        env->CallBooleanMethod(list, add, lm);
    }
    LOGI("provide: %d modules (legacy=%d)", (int)env->CallIntMethod(
        list, env->GetMethodID(alc, "size", "()I")), (int)legacy);
    return list;
}

static jobject nProvideLegacy(JNIEnv *env, jclass c, jobjectArray a) {
    return native_provide(env, c, a, true);
}
static jobject nProvideModules(JNIEnv *env, jclass c, jobjectArray a) {
    return native_provide(env, c, a, false);
}

/* P13:替换 XposedInit.loadLegacyModules() —— 绕开 SharedMemory.fromFd
 * (hidden API,untrusted_app 被 enforcement 拦截,w12 实证):直接用
 * VectorModuleClassLoader(R8 名 c3)的 ByteBuffer 构造器 + 自实现
 * initModule 循环(IXposedHookLoadPackage/hookLoadPackage 全公开 API,
 * de.robv keep 原名)。**不调 backup**:原方法内部走 getLegacyModules
 * (可能已被 R8 内联),备份调用仅为空循环冗余。 */
static jobject nLoadAll(JNIEnv *env, jclass c, jobjectArray a) {
    (void)c;
    (void)a;
    if (!g_cfg) return nullptr;
    uint32_t n = 0;
    memcpy(&n, g_cfg + 0x200 + 4, 4);
    if (n > 8) n = 8;
    LOGI("loadAll: %u modules", n);
    LOGI("loadAll: step1 XposedBridge FindClass...");

    /* framework loader:经主链寄存(此处从 hook 的接收者反查不可行,
     * 由 XposedBridge 类的 loader 取 —— de.robv 原名)。 */
    jclass xb = env->FindClass("de/robv/android/xposed/XposedBridge");
    if (!xb || env->ExceptionCheck()) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        LOGE("loadAll: XposedBridge not found");
        return nullptr;
    }
    jclass clc = env->FindClass("java/lang/Class");
    jmethodID gcl = env->GetMethodID(clc, "getClassLoader",
        "()Ljava/lang/ClassLoader;");
    jobject fw_loader = env->CallObjectMethod(xb, gcl);
    LOGI("loadAll: step2 fw_loader=%p", fw_loader);
    /* loadClass 在 ClassLoader 上(不在 Class 上),签名
     * (Ljava/lang/String;)Ljava/lang/Class;。此前类与返回类型各错一处:
     * 类错 → 恒 null → CallObjectMethod(mid=null) = checked-JNI FATAL
     * abort 杀进程(p18w4 实录,即 w15/w16"挂死"真身)。 */
    jclass clc_loader = env->FindClass("java/lang/ClassLoader");
    jmethodID lc = clc_loader ? env->GetMethodID(clc_loader, "loadClass",
        "(Ljava/lang/String;)Ljava/lang/Class;") : nullptr;
    if (!lc) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        LOGE("loadAll: ClassLoader.loadClass not found");
        return nullptr;
    }
    auto load = [&](const char *name) -> jclass {
        jobject o = env->CallObjectMethod(fw_loader, lc,
            env->NewStringUTF(name));
        if (!o || env->ExceptionCheck()) {
            if (env->ExceptionCheck()) env->ExceptionClear();
            return nullptr;
        }
        return (jclass)o;
    };
    /* 混淆类统一经 fw_loader.loadClass(FindClass 走调用者 loader 不行)。 */
    auto load_obf = [&](const char *name) -> jclass {
        jobject o = env->CallObjectMethod(fw_loader, lc,
            env->NewStringUTF(name));
        if (!o || env->ExceptionCheck()) {
            if (env->ExceptionCheck()) env->ExceptionClear();
            return nullptr;
        }
        return (jclass)o;
    };
    LOGI("loadAll: step3 loading c3...");
    jclass c3 = load_obf("c3");   /* VectorModuleClassLoader(R8) */
    if (!c3) { LOGE("loadAll: c3 not found"); return nullptr; }
    LOGI("loadAll: step4 c3=%p", c3);
    jmethodID c3ctor = env->GetMethodID(c3, "<init>",
        "([Ljava/nio/ByteBuffer;Ljava/lang/String;Ljava/lang/ClassLoader;"
        "Ljava/lang/String;Z)V");
    if (!c3ctor) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        LOGE("loadAll: c3 <init> not found");
        return nullptr;
    }
    LOGI("loadAll: step5 ctor ok");
    jclass xilp = env->FindClass("de/robv/android/xposed/IXposedHookLoadPackage");
    if (!xilp) { LOGE("loadAll: IXposedHookLoadPackage not found"); return nullptr; }
    jclass wrapper_c = env->FindClass(
        "de/robv/android/xposed/callbacks/XC_LoadPackage$XC_LoadPackage$Wrapper");
    /* Wrapper 实际路径:de.robv.android.xposed.IXposedHookLoadPackage$Wrapper */
    if (!wrapper_c || env->ExceptionCheck()) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        wrapper_c = env->FindClass("de/robv/android/xposed/IXposedHookLoadPackage$Wrapper");
    }
    if (!wrapper_c) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        LOGE("loadAll: Wrapper not found");
        return nullptr;
    }

    jclass bbc = env->FindClass("java/nio/ByteBuffer");
    jobjectArray bufarr = nullptr;
    uint32_t ok_ct = 0;

    for (uint32_t i = 0; i < n; i++) {
        const uint8_t *rec = cfg_module(i);
        uint32_t n_dex;
        memcpy(&n_dex, rec + 96 + 256, 4);
        if (n_dex > 4) n_dex = 4;
        std::string pkg = cfg_str(rec, 96);
        std::string entries = cfg_str(rec + 96, 256);

        /* dex → DirectByteBuffer(ghost va 进程内可读,零拷贝) */
        LOGI("loadAll: s5a module %u pkg=%s dex=%u entries=%s",
             i, pkg.c_str(), n_dex, entries.c_str());
        bufarr = env->NewObjectArray(n_dex, bbc, nullptr);
        for (uint32_t j = 0; j < n_dex; j++) {
            uint64_t va; uint32_t sz;
            memcpy(&va, rec + 96 + 256 + 8 + j * 8, 8);
            memcpy(&sz, rec + 96 + 256 + 8 + 32 + j * 4, 4);
            LOGI("loadAll: s5b NDBB i=%u j=%u va=%llx sz=%u",
                 i, j, (unsigned long long)va, sz);
            jobject bb = env->NewDirectByteBuffer((void *)(uintptr_t)va, sz);
            /* 不解引用 ghost va(坏 va 由 dex verify 路径 SIGSEGV +
             * tombstone 显形);只校验 JNI 包装的一致性。 */
            if (bb && ((uintptr_t)env->GetDirectBufferAddress(bb) !=
                           (uintptr_t)va ||
                       (uint64_t)env->GetDirectBufferCapacity(bb) != sz))
                LOGE("loadAll: NDBB mismatch i=%u j=%u", i, j);
            env->SetObjectArrayElement(bufarr, j, bb);
        }
        jobject dexlist = env->CallStaticObjectMethod(
            env->FindClass("java/util/Arrays"),
            env->GetStaticMethodID(env->FindClass("java/util/Arrays"),
                "asList", "([Ljava/lang/Object;)Ljava/util/List;"),
            bufarr);
        /* VectorModuleClassLoader 构造器还要求 dex list?否 —— 构造器第
         * 一参是数组;先建 loader,再逐 entry 装载。 */
        LOGI("loadAll: step6 NewObject loader (dex validate)...");
        jobject mcl = env->NewObject(c3, c3ctor, bufarr,
            env->NewStringUTF(""),      /* librarySearchPath:无 native 模块 */
            fw_loader, env->NewStringUTF(pkg.c_str()), JNI_FALSE);
        LOGI("loadAll: step7 loader=%p", mcl);
        if (!mcl || env->ExceptionCheck()) {
            if (env->ExceptionCheck()) { env->ExceptionDescribe(); env->ExceptionClear(); }
            LOGE("loadAll: module %u loader failed", i);
            continue;
        }
        /* 保活 loader(模块类须存活) */
        static jobject keep[8];
        keep[i] = env->NewGlobalRef(mcl);

        jmethodID mcl_load = env->GetMethodID(
            env->GetObjectClass(mcl), "loadClass",
            "(Ljava/lang/String;)Ljava/lang/Class;");
        /* entries 逗号拆分逐个装载(复刻 XposedInit.initModule 语义)。 */
        size_t pos = 0;
        while (pos < entries.size()) {
            size_t comma = entries.find(',', pos);
            if (comma == std::string::npos) comma = entries.size();
            std::string cn = entries.substr(pos, comma - pos);
            pos = comma + 1;
            jstring jcn = env->NewStringUTF(cn.c_str());
            LOGI("loadAll: s8 loadClass %s", cn.c_str());
            jclass mod_c = (jclass)env->CallObjectMethod(mcl, mcl_load, jcn);
            if (!mod_c || env->ExceptionCheck()) {
                if (env->ExceptionCheck()) env->ExceptionDescribe();
                env->ExceptionClear();
                LOGE("loadAll: %s not loadable", cn.c_str());
                continue;
            }
            if (!env->IsAssignableFrom(mod_c, xilp)) {
                LOGE("loadAll: %s not IXposedHookLoadPackage", cn.c_str());
                continue;
            }
            jmethodID mctor = env->GetMethodID(mod_c, "<init>", "()V");
            if (!mctor) {
                if (env->ExceptionCheck()) env->ExceptionClear();
                LOGE("loadAll: %s no <init>()V", cn.c_str());
                continue;
            }
            jobject inst = env->NewObject(mod_c, mctor);
            if (!inst || env->ExceptionCheck()) {
                if (env->ExceptionCheck()) env->ExceptionDescribe();
                env->ExceptionClear();
                LOGE("loadAll: %s newInstance failed", cn.c_str());
                continue;
            }
            jmethodID w_ctor = env->GetMethodID(wrapper_c, "<init>",
                "(Lde/robv/android/xposed/IXposedHookLoadPackage;)V");
            if (!w_ctor) {
                if (env->ExceptionCheck()) env->ExceptionClear();
                LOGE("loadAll: Wrapper <init> mid not found");
                continue;
            }
            jobject wparam = env->NewObject(wrapper_c, w_ctor, inst);
            /* hookLoadPackage(Wrapper) —— 注册进 XposedBridge 回调集。
             * 签名必须是 XC_LoadPackage;用 Object 查不到 → GetStaticMethodID
             * 返 null 且留 pending NoSuchMethodError,不清除则下一个 JNI
             * 调用 = "No pending exception expected" abort(p18w9 实录)。 */
            jmethodID hlp = env->GetStaticMethodID(xb, "hookLoadPackage",
                "(Lde/robv/android/xposed/callbacks/XC_LoadPackage;)V");
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (hlp) {
                env->CallStaticVoidMethod(xb, hlp, wparam);
                if (env->ExceptionCheck()) {
                    env->ExceptionDescribe();
                    env->ExceptionClear();
                }
            }
            LOGI("loadAll: %s registered (hookLoadPackage)", cn.c_str());
            /* late-inject 语义:app 已完全启动,LoadedApk 构造 hook 成过去
             * 时,框架唯一分发点(LoadedApkCreateCLHooker)不会再触发 ——
             * 合成 LoadPackageParam 直接派发一次,让模块真的完成 hook
             * 注册;这正是门禁要回证的路径。 */
            jclass lpp_c = env->FindClass(
                "de/robv/android/xposed/callbacks/XC_LoadPackage$LoadPackageParam");
            if (!lpp_c || env->ExceptionCheck()) {
                if (env->ExceptionCheck()) env->ExceptionClear();
                LOGE("loadAll: LoadPackageParam not found");
                continue;
            }
            jclass cow_c = env->FindClass("java/util/concurrent/CopyOnWriteArraySet");
            jmethodID cow_ctor = cow_c ? env->GetMethodID(cow_c, "<init>", "()V") : nullptr;
            jmethodID lpp_ctor = lpp_c ? env->GetMethodID(lpp_c, "<init>",
                "(Ljava/util/concurrent/CopyOnWriteArraySet;)V") : nullptr;
            if (!cow_ctor || !lpp_ctor) {
                if (env->ExceptionCheck()) env->ExceptionClear();
                LOGE("loadAll: LoadPackageParam ctor mid missing");
                continue;
            }
            jobject cow = env->NewObject(cow_c, cow_ctor);
            jobject lpp = env->NewObject(lpp_c, lpp_ctor, cow);
            if (!lpp || env->ExceptionCheck()) {
                if (env->ExceptionCheck()) env->ExceptionDescribe();
                env->ExceptionClear();
                LOGE("loadAll: LoadPackageParam ctor failed");
                continue;
            }
            /* 字段查找失败同样会留 pending exception —— 逐个清除。 */
            jfieldID f;
            if ((f = env->GetFieldID(lpp_c, "packageName", "Ljava/lang/String;")) != nullptr)
                env->SetObjectField(lpp, f, env->NewStringUTF(pkg.c_str()));
            else if (env->ExceptionCheck()) env->ExceptionClear();
            if ((f = env->GetFieldID(lpp_c, "processName", "Ljava/lang/String;")) != nullptr)
                env->SetObjectField(lpp, f, env->NewStringUTF(pkg.c_str()));
            else if (env->ExceptionCheck()) env->ExceptionClear();
            if ((f = env->GetFieldID(lpp_c, "classLoader", "Ljava/lang/ClassLoader;")) != nullptr)
                env->SetObjectField(lpp, f, mcl);
            else if (env->ExceptionCheck()) env->ExceptionClear();
            if ((f = env->GetFieldID(lpp_c, "isFirstApplication", "Z")) != nullptr)
                env->SetBooleanField(lpp, f, JNI_FALSE);
            else if (env->ExceptionCheck()) env->ExceptionClear();
            jmethodID hlp_m = env->GetMethodID(xilp, "handleLoadPackage",
                "(Lde/robv/android/xposed/callbacks/XC_LoadPackage$LoadPackageParam;)V");
            if (!hlp_m) {
                if (env->ExceptionCheck()) env->ExceptionClear();
                LOGE("loadAll: handleLoadPackage mid not found");
                continue;
            }
            LOGI("loadAll: s9 dispatch handleLoadPackage %s", cn.c_str());
            env->CallVoidMethod(inst, hlp_m, lpp);
            if (env->ExceptionCheck()) {
                env->ExceptionDescribe();
                env->ExceptionClear();
                LOGE("loadAll: %s handleLoadPackage threw", cn.c_str());
                continue;
            }
            ok_ct++;
            LOGI("loadAll: %s dispatched ok", cn.c_str());
        }
    }
    LOGI("loadAll done: ok=%u/%u", ok_ct, n);
    return nullptr;
}

/* ---- 层级 B 主链(adapter 调;bridge_va = 桥页) ----
 * 返回 0 = 成功;非 0 = 失败码(adapter publish)。 */
int tierb_run(JNIEnv *env, jobject fw_loader, const struct lsp_bridge *bridge,
              uint64_t bridge_va) {
    (void)bridge;
    g_cfg = (const uint8_t *)bridge_va;

    /* ① 桥 dex InMemoryDexClassLoader(parent = framework loader)。 */
    uint64_t bd_va;
    uint32_t bd_size;
    {
        const uint8_t *h = g_cfg + 0x150;
        memcpy(&bd_va, h, 8);
        memcpy(&bd_size, h + 8, 4);
        if (*(const uint32_t *)(h + 12) != 0x314B5647 || !bd_va || !bd_size) {
            LOGE("tierb: no bridge dex");
            return -11;
        }
    }
    jclass imcl = env->FindClass("dalvik/system/InMemoryDexClassLoader");
    if (!imcl) { LOGE("tierb: FindClass IMCL"); return -3; }
    jmethodID init_mid = env->GetMethodID(imcl, "<init>",
        "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    jobject buf = env->NewDirectByteBuffer((void *)(uintptr_t)bd_va, bd_size);
    jobject bridge_loader = env->NewObject(imcl, init_mid, buf, fw_loader);
    if (!bridge_loader || env->ExceptionCheck()) {
        if (env->ExceptionCheck()) { env->ExceptionDescribe(); env->ExceptionClear(); }
        LOGE("tierb: bridge loader");
        return -3;
    }
    LOGI("t: bridge loader ok");
    /* 保活 */
    static jobject g_bridge_loader;
    g_bridge_loader = env->NewGlobalRef(bridge_loader);

    jmethodID load_mid = env->GetMethodID(imcl, "loadClass",
        "(Ljava/lang/String;)Ljava/lang/Class;");
    LOGI("t: loadClass VectorGook...");
    jstring vgn = env->NewStringUTF("gk.VectorGook");
    jclass vg = (jclass)env->CallObjectMethod(bridge_loader, load_mid, vgn);
    if (!vg || env->ExceptionCheck()) {
        if (env->ExceptionCheck()) { env->ExceptionDescribe(); env->ExceptionClear(); }
        LOGE("tierb: loadClass gk.VectorGook");
        return -3;
    }

    LOGI("t: VectorGook class=%p", vg);
    /* ② RegisterNatives(native 实现在本 .so,直接绑)。 */
    JNINativeMethod mns[] = {
        {(char *)"nativeProvideLegacyModules",
         (char *)"([Ljava/lang/Object;)Ljava/lang/Object;",
         (void *)nLoadAll},
        {(char *)"nativeProvideModules",
         (char *)"([Ljava/lang/Object;)Ljava/lang/Object;",
         (void *)nProvideModules},
    };
    LOGI("t: registering natives");
    if (env->RegisterNatives(vg, mns, 2) != JNI_OK) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        LOGE("tierb: RegisterNatives");
        return -3;
    }

    /* ③ hook XposedInit.loadLegacyModules(keep 类,方法原名保留;
     * callback 直接执行装载循环 —— 原方法内部走 getLegacyModules,
     * R8 可能内联调用点致 hook 失效,故不 hook 供数方法)。 */
    jmethodID ctor = env->GetMethodID(vg, "<init>", "()V");
    jobject hooker_obj = env->NewObject(vg, ctor);
    jmethodID cb_l = env->GetMethodID(vg, "loadAll",
        "([Ljava/lang/Object;)Ljava/lang/Object;");
    jobject cb_lm = env->ToReflectedMethod(vg, cb_l, JNI_FALSE);
    /* XposedInit 在 framework loader(de.robv keep 原名)。 */
    jobject xi_cls = env->CallObjectMethod(fw_loader, load_mid,
        env->NewStringUTF("de.robv.android.xposed.XposedInit"));
    if (!xi_cls || env->ExceptionCheck()) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        LOGE("tierb: XposedInit not found");
        return -3;
    }
    jclass xi = (jclass)xi_cls;
    jmethodID llm = env->GetStaticMethodID(xi, "loadLegacyModules", "()V");
    if (!llm) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        LOGE("tierb: loadLegacyModules not found");
        return -3;
    }
    jobject target_l = env->ToReflectedMethod(xi, llm, JNI_TRUE);
    jobject backup = lsplant::Hook(env, target_l, hooker_obj, cb_lm);
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (!backup) {
        LOGE("tierb: hook loadLegacyModules failed");
        return -3;
    }
    LOGI("t: hook loadLegacyModules done backup=%p", backup);

    LOGI("t: hooks done, finding Main");
    /* ④ forkCommon(isSystem=false, isLateInject=true, niceName, appDir,
     *    binder=null)。 */
    jclass main_c = (jclass)env->CallObjectMethod(bridge_loader, load_mid,
        env->NewStringUTF("org.matrix.vector.core.Main"));
    if (!main_c || env->ExceptionCheck()) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        LOGE("tierb: Main not found");
        return -3;
    }
    jmethodID fc = env->GetStaticMethodID(main_c, "forkCommon",
        "(ZZLjava/lang/String;Ljava/lang/String;Landroid/os/IBinder;)V");
    if (!fc) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        LOGE("tierb: forkCommon not found");
        return -3;
    }
    const char *nn = bridge->proc_args.nice_name ? bridge->proc_args.nice_name : "unknown";
    const char *ad = bridge->proc_args.app_data_dir ? bridge->proc_args.app_data_dir : "";
    LOGI("t: calling forkCommon...");
    /* binder 参数是 Kotlin 非空类型(传 null = 入口 NPE)——传本地空壳
     * Binder:asInterface 走 Proxy,后续 transact 无远端失败,全部被
     * VectorServiceClient 的 runCatching 吞成空列表(容忍性实证)。 */
    jclass bcls = env->FindClass("android/os/Binder");
    jobject fake_binder = env->NewObject(bcls,
        env->GetMethodID(bcls, "<init>", "()V"));
    env->CallStaticVoidMethod(main_c, fc, JNI_FALSE, JNI_TRUE,
                              env->NewStringUTF(nn), env->NewStringUTF(ad),
                              fake_binder);
    if (env->ExceptionCheck()) {
        jthrowable ex = env->ExceptionOccurred();
        env->ExceptionClear();
        jclass tlc = env->FindClass("java/lang/Throwable");
        jmethodID tostr = env->GetMethodID(tlc, "toString", "()Ljava/lang/String;");
        jstring msg = (jstring)env->CallObjectMethod(ex, tostr);
        const char *m = msg ? env->GetStringUTFChars(msg, nullptr) : nullptr;
        LOGE("tierb: forkCommon threw: %s", m ? m : "(null)");
        if (m) env->ReleaseStringUTFChars(msg, m);
        jmethodID gst = env->GetMethodID(tlc, "getStackTrace",
            "()[Ljava/lang/StackTraceElement;");
        auto frames = (jobjectArray)env->CallObjectMethod(ex, gst);
        if (frames && !env->ExceptionCheck()) {
            jsize n = env->GetArrayLength(frames);
            if (n > 8) n = 8;
            jclass stec = env->FindClass("java/lang/StackTraceElement");
            jmethodID s2s = env->GetMethodID(stec, "toString", "()Ljava/lang/String;");
            for (jsize i = 0; i < n; i++) {
                jstring f = (jstring)env->CallObjectMethod(
                    env->GetObjectArrayElement(frames, i), s2s);
                const char *fs = f ? env->GetStringUTFChars(f, nullptr) : nullptr;
                LOGE("  at %s", fs ? fs : "?");
                if (fs) env->ReleaseStringUTFChars(f, fs);
            }
        }
        return -3;
    }
    LOGI("tierb: forkCommon done (modules provisioned via hook)");
    return 0;
}
