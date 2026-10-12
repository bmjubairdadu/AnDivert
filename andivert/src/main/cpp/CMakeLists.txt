cmake_minimum_required(VERSION 3.22.1)
project(andivert C)

add_library(andivert SHARED
    andivert.c
    ad_packet.c
    ad_filter.c
    ad_checksum.c
    ad_ring.c
    ad_forward.c
    ad_log.c
    ad_jni.c
)

target_include_directories(andivert PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(andivert PRIVATE -O2 -Wall -Wextra)
target_link_libraries(andivert log)
