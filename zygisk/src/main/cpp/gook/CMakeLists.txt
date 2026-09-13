# libvector_gook.so —— P12 W2 Vector 适配层(gook 注入轨道)
# 复用 Vector native 静态库(context/hook_bridge/elf/native_api);LSPlant
# 动态链 lsplant-gook 预构建 liblsplant.so(LGPL 分发形态);libgklsp.so 经
# dlsym 动态消费(abi §5 红线:不静态衍生 kaemon 代码)。
# 裁剪说明:不走 Vector external 全量(其 lsplant 子树用 C++20 modules,
# 且我们不需要 lsplant_static/dex_builder)——xz/fmt 手工定义,dobby 单独
# 引入(native_api 面用);resources_hook.cpp 以桩替换(资源钩子属层级 B,
# research-lsplant §4 "资源钩子可不做")。
# 外部变量:-DVECTOR_ROOT=<Vector 仓根>
#          -DLSPLANT_ROOT_GOOK=<lsplant-gook/lsplant/src/main/jni>
#          -DKAEMON_INCLUDE_GOOK=<kaemon/include>
cmake_minimum_required(VERSION 3.10)
project(vector_gook)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(VECTOR_ROOT "" CACHE PATH "Vector 仓根")
set(LSPLANT_ROOT_GOOK "" CACHE PATH "lsplant-gook/lsplant/src/main/jni")
set(KAEMON_INCLUDE_GOOK "" CACHE PATH "kaemon/include")

# xz-embedded(elf_image .gnu_debugdata 解压)
set(XZ_SOURCES xz_crc32.c xz_crc64.c xz_dec_lzma2.c xz_dec_stream.c)
list(TRANSFORM XZ_SOURCES PREPEND ${VECTOR_ROOT}/external/xz-embedded/linux/lib/xz/)
add_library(xz_static STATIC ${XZ_SOURCES})
target_compile_options(xz_static PRIVATE -DXZ_USE_CRC64)
target_include_directories(xz_static PUBLIC
    ${VECTOR_ROOT}/external/xz-embedded/linux/include
    PRIVATE ${VECTOR_ROOT}/external/xz-embedded/userspace
            ${VECTOR_ROOT}/external/xz-embedded/linux/include/linux)

# fmt header-only(logging.h)
add_library(fmt-header-only INTERFACE)
target_include_directories(fmt-header-only INTERFACE ${VECTOR_ROOT}/external/fmt/include)
target_compile_definitions(fmt-header-only INTERFACE
    FMT_USE_LOCALE=0 FMT_USE_FLOAT=0 FMT_USE_DOUBLE=0
    FMT_USE_LONG_DOUBLE=0 FMT_USE_BITINT=0)

# dobby(native_api 面的原生 hook;非 InitInfo 承载)
add_subdirectory(${VECTOR_ROOT}/external/dobby dobby-build)

# dex_builder(resources_hook buildDummyClassLoader 现场造 dex 用;经典
# include 路径 —— .ixx modules 仅 lsplant 自家 CMake 用,Android.mk 同款
# 源集纯 .cc 编译,与 P12 裁剪动机(cxx modules)不冲突)
set(DB_ROOT ${LSPLANT_ROOT_GOOK}/external/dex_builder)
add_library(dex_builder_static STATIC
    ${DB_ROOT}/dex_builder.cc
    ${DB_ROOT}/dex_helper.cc
    ${DB_ROOT}/slicer/reader.cc
    ${DB_ROOT}/slicer/writer.cc
    ${DB_ROOT}/slicer/dex_ir.cc
    ${DB_ROOT}/slicer/common.cc
    ${DB_ROOT}/slicer/dex_format.cc
    ${DB_ROOT}/slicer/dex_utf8.cc
    ${DB_ROOT}/slicer/dex_bytecode.cc
    ${DB_ROOT}/slicer/sha1.cpp)
target_include_directories(dex_builder_static PUBLIC ${DB_ROOT}/include)
target_include_directories(dex_builder_static PUBLIC ${DB_ROOT}/external/parallel_hashmap)
target_link_libraries(dex_builder_static PUBLIC z log)

# Vector native 静态库(去 native_api 面 —— Xposed 模块原生 API 的
# lsplant hook DSL 需 CI 级 clang 模板行为,本地面以桩承接;
# resources_hook.cpp 自 P14 起入编 —— 资源钩子真实现)
file(GLOB NATIVE_GOOK_SOURCES
    ${VECTOR_ROOT}/native/src/*.cpp
    ${VECTOR_ROOT}/native/src/*/*.cpp)
list(FILTER NATIVE_GOOK_SOURCES EXCLUDE REGEX "native_api(\\.cpp|_bridge\\.cpp)$")
add_library(native_gook STATIC ${NATIVE_GOOK_SOURCES})
target_compile_definitions(native_gook PRIVATE VERSION_CODE=1 VERSION_NAME="gook-p14" FMT_HEADER_ONLY=1)
target_include_directories(native_gook
    PUBLIC ${VECTOR_ROOT}/native/include ${LSPLANT_ROOT_GOOK}/include
    PRIVATE ${VECTOR_ROOT}/native/src
            ${LSPLANT_ROOT_GOOK}/external/dex_builder/include
            ${LSPLANT_ROOT_GOOK}/external/dex_builder/external/parallel_hashmap)
target_compile_options(native_gook PRIVATE
    -Wno-c99-extensions -Wno-extra-semi
    -Wno-gnu-flexible-array-initializer
    -Wno-gnu-string-literal-operator-template
    -Wno-gnu-zero-variadic-macro-arguments
    -Wno-variadic-macros -Wno-zero-length-array)
target_link_libraries(native_gook PUBLIC dobby_static xz_static log fmt-header-only dex_builder_static)

add_library(lsplant_gook SHARED IMPORTED)
set_target_properties(lsplant_gook PROPERTIES
    IMPORTED_LOCATION ${LSPLANT_ROOT_GOOK}/build/liblsplant.so)

add_library(vector_gook SHARED gook_adapter.cpp)
target_include_directories(vector_gook PRIVATE
    ${VECTOR_ROOT}/native/include ${KAEMON_INCLUDE_GOOK} ${LSPLANT_ROOT_GOOK}/include)
target_link_libraries(vector_gook PRIVATE native_gook lsplant_gook log)
target_compile_definitions(vector_gook PRIVATE FMT_HEADER_ONLY=1)
target_link_options(vector_gook PRIVATE -static-libstdc++)

# 原生 API 桥桩(resources_hook 已真入编,RegisterResourcesHook 由
# resources_hook.cpp 提供;native_api 面仍在桩上)
target_sources(vector_gook PRIVATE gook_stub_res.cpp gook_tierb.cpp)
