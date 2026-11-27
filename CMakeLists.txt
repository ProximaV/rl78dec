cmake_minimum_required(VERSION 3.20)

if(NOT PROJECT_NAME)
    project(rl78dec LANGUAGES CXX)
    enable_testing()
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(RL78DEC_CORE_SOURCES
    src/core/isa.cpp
    src/core/sfr.cpp
    src/core/loader.cpp
    src/core/database.cpp
    src/core/switch_table.cpp
    src/core/decoder.cpp
    src/core/ir.cpp
    src/core/lifter.cpp
    src/core/cfg.cpp
    src/core/frame.cpp
    src/core/spill.cpp
    src/core/opt.cpp
    src/core/abi.cpp
    src/core/vars.cpp
    src/core/structure.cpp
    src/core/ctree.cpp
    src/core/cgen.cpp
    src/core/highlight.cpp
    src/core/user_data.cpp
    src/core/pipeline.cpp
)

add_library(rl78dec_core STATIC ${RL78DEC_CORE_SOURCES})

target_include_directories(rl78dec_core
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

if(WIN32)
    target_compile_definitions(rl78dec_core PUBLIC _CRT_SECURE_NO_WARNINGS NOMINMAX)
endif()

if(MSVC)
    target_compile_options(rl78dec_core PRIVATE /W3 /EHsc /MP)
    target_compile_options(rl78dec_core PRIVATE $<$<CONFIG:Release>:/O2 /Oi /Ot>)
else()
    target_compile_options(rl78dec_core PRIVATE -Wall -Wextra -O3)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/cli/main.cpp")
    add_executable(rl78dec_cli src/cli/main.cpp)
    target_link_libraries(rl78dec_cli PRIVATE rl78dec_core)
    if(MSVC)
        target_compile_options(rl78dec_cli PRIVATE /W3 /EHsc /MP)
    endif()
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/ctests/rl78dec_tests.cpp")
    add_executable(rl78dec_tests ctests/rl78dec_tests.cpp)
    target_link_libraries(rl78dec_tests PRIVATE rl78dec_core)
    if(MSVC)
        target_compile_options(rl78dec_tests PRIVATE /W3 /EHsc /MP)
    endif()
    add_test(NAME rl78dec_tests COMMAND rl78dec_tests)
endif()

# Resolve IDA 9.5 SDK root (note: plugin dir may be a junction from idasdk92, so check ida-sdk/src explicitly)
set(_DEFAULT_IDA_SDK_DIR "")
if(DEFINED IDASDK AND EXISTS "${IDASDK}/include/ida.hpp" AND EXISTS "${IDASDK}/lib/x64_win_64/ida.lib")
    set(_DEFAULT_IDA_SDK_DIR "${IDASDK}")
elseif(DEFINED ENV{IDASDK} AND EXISTS "$ENV{IDASDK}/include/ida.hpp" AND EXISTS "$ENV{IDASDK}/lib/x64_win_64/ida.lib")
    set(_DEFAULT_IDA_SDK_DIR "$ENV{IDASDK}")
elseif(DEFINED IDA_SDK_DIR AND EXISTS "${IDA_SDK_DIR}/include/ida.hpp")
    set(_DEFAULT_IDA_SDK_DIR "${IDA_SDK_DIR}")
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../include/ida.hpp" AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../lib/x64_win_64/ida.lib")
    get_filename_component(_DEFAULT_IDA_SDK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
elseif(EXISTS "C:/Users/Proxima/source/repos/ida-sdk/src/include/ida.hpp" AND EXISTS "C:/Users/Proxima/source/repos/ida-sdk/src/lib/x64_win_64/ida.lib")
    set(_DEFAULT_IDA_SDK_DIR "C:/Users/Proxima/source/repos/ida-sdk/src")
endif()
set(IDA_SDK_DIR "${_DEFAULT_IDA_SDK_DIR}" CACHE PATH "Path to IDA SDK src directory")

set(_IDA_LIB_PATH "")
if(EXISTS "${IDA_SDK_DIR}/lib/x64_win_64/ida.lib")
    set(_IDA_LIB_PATH "${IDA_SDK_DIR}/lib/x64_win_64/ida.lib")
elseif(EXISTS "${IDA_SDK_DIR}/lib/x64_win_vc_64/ida.lib")
    set(_IDA_LIB_PATH "${IDA_SDK_DIR}/lib/x64_win_vc_64/ida.lib")
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/ida/plugin.cpp" AND
   (TARGET idasdk::plugin OR (EXISTS "${IDA_SDK_DIR}/include/ida.hpp" AND _IDA_LIB_PATH)))
    set(RL78DEC_IDA_SOURCES
        src/ida/plugin.cpp
        src/ida/ida_provider.cpp
        src/ida/summary_cache.cpp
        src/ida/db.cpp
        src/ida/merge.cpp
        src/ida/api_dispatch.cpp
        src/ida/idc_funcs.cpp
        src/ida/view.cpp
    )

    add_library(rl78dec SHARED ${RL78DEC_IDA_SOURCES})
    set_target_properties(rl78dec PROPERTIES
        PREFIX ""
        OUTPUT_NAME "rl78dec"
    )
    target_compile_definitions(rl78dec PRIVATE RL78DEC_BUILDING_DLL)
    if(TARGET idasdk::plugin)
        target_link_libraries(rl78dec PRIVATE rl78dec_core idasdk::plugin)
    else()
        target_include_directories(rl78dec PRIVATE "${IDA_SDK_DIR}/include")
        target_compile_definitions(rl78dec PRIVATE
            __NT__ __EA64__ __X64__ __IDP__
            USE_DANGEROUS_FUNCTIONS USE_STANDARD_FILE_FUNCTIONS
            _CRT_SECURE_NO_WARNINGS NOMINMAX
        )
        target_link_libraries(rl78dec PRIVATE rl78dec_core "${_IDA_LIB_PATH}")
    endif()

    if(MSVC)
        target_compile_options(rl78dec PRIVATE /W3 /EHsc /MP $<$<CONFIG:Release>:/O2 /Oi /Ot>)
        target_link_options(rl78dec PRIVATE $<$<CONFIG:Release>:/PDBALTPATH:%_PDB%>)
    endif()

    if(WIN32 AND DEFINED ENV{APPDATA})
        set(_IDA_USER_PLUGINS "$ENV{APPDATA}/Hex-Rays/IDA Pro/plugins")
        add_custom_target(rl78dec_deploy
            DEPENDS rl78dec
            COMMAND "${CMAKE_COMMAND}" -E make_directory "${_IDA_USER_PLUGINS}"
            COMMAND "${CMAKE_COMMAND}" -E rm -f "${_IDA_USER_PLUGINS}/rl78dec_plugin.py"
            COMMAND "${CMAKE_COMMAND}" -E rm -rf "${_IDA_USER_PLUGINS}/rl78dec"
            COMMAND "${CMAKE_COMMAND}" -E copy_if_different "$<TARGET_FILE:rl78dec>" "${_IDA_USER_PLUGINS}/rl78dec.dll"
            COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/python_sdk/rl78dec_hexrays_bridge.py" "${_IDA_USER_PLUGINS}/rl78dec_hexrays_bridge.py"
            COMMAND "${CMAKE_COMMAND}" -E copy_directory "${CMAKE_CURRENT_SOURCE_DIR}/python_sdk/rl78dec" "${_IDA_USER_PLUGINS}/rl78dec"
            COMMENT "Deploying native rl78dec.dll + Python SDK to ${_IDA_USER_PLUGINS}"
        )
    endif()
endif()
