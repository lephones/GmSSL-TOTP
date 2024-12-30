cmake_minimum_required(VERSION 3.22.1)
set(CMAKE_BUILD_TYPE Debug)  # 确保构建类型是 Debug
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")  # 启用调试符号

project("gmssl-totp")

include_directories(${CMAKE_SOURCE_DIR}/../include/gmssl ${CMAKE_SOURCE_DIR}/include)


# 设置静态库的实际路径
set_target_properties(
        gmssl PROPERTIES
        IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/libs/libgmssl.a
)

add_library(
        gmssl STATIC
        IMPORTED
)

# 添加源文件到项目中
add_library(gmssl-totp src/sm3_dpwd.cpp src/sm4_dpwd.cpp)

# link
target_link_libraries(${CMAKE_PROJECT_NAME}
        # List libraries link to the target library
        gmssl)