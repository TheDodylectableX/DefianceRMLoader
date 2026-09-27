# ---------------------------------------------------------------------------------------
cmake_minimum_required(VERSION 3.20)
project(DefianceRMLoader CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# -- Include MinHook via FetchContent ---------------------------------------------------
include(FetchContent)
FetchContent_Declare(
        minhook
        GIT_REPOSITORY https://github.com/TsudaKageyu/minhook.git
        GIT_TAG        master
)
FetchContent_MakeAvailable(minhook)

# -- Our ASI target --------------------------------------------------------------------
add_library(DefianceRMLoader SHARED
        src/DLLMain.cpp
        src/Hooks.cpp
        src/Version.rc
)

target_include_directories(DefianceRMLoader PRIVATE
        src/
        ${minhook_SOURCE_DIR}/include
)

target_link_libraries(DefianceRMLoader PRIVATE
        minhook
        kernel32 # CreateFileW, AllocConsole, etc.
        user32   # MessageBoxA (For debug stuff)
)

# -- MSVC Specific: Suppress the "entry point must be _DllMainCRTStartup" warning and make sure we get a clean ASI without the CRT nagging us
target_compile_options(DefianceRMLoader PRIVATE
        /W3      # Warning level 3, Reasonable
        /WX-     # Don't treat warnings as errors yet (We're exploring)
        /EHsc    # Enable C++ exceptions
)

# -- Output the ASI directly into a "deploy" folder for convenience ---------------------
set_target_properties(DefianceRMLoader PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/deploy
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/deploy
        SUFFIX ".asi"
)
# ---------------------------------------------------------------------------------------
