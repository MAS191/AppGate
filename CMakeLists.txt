cmake_minimum_required(VERSION 3.15)
project(AppGate)
set(CMAKE_CXX_STANDARD 17)
add_executable(AppGate
    main.cpp
    ProcessManager.cpp
    FirewallManager.cpp
    Utils.cpp
    InstalledAppsManager.cpp
)
# Link Windows libs
target_link_libraries(AppGate
    ws2_32 iphlpapi fwpuclnt psapi shlwapi shell32 ole32 version
)
