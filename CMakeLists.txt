cmake_minimum_required(VERSION 3.10)
project(Nier)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED True)

if(CMAKE_C_COMPILER_ID STREQUAL "GNU" OR CMAKE_C_COMPILER_ID STREQUAL "Clang")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wl,-z,relro,-z,now -O2")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE -fPIC")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie")
endif()

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    include_directories(${OPENSSL_INCLUDE_DIR})
else()
    message(FATAL_ERROR "OpenSSL not found!")
endif()

find_library(MOSQUITTO_LIB mosquitto)
if(MOSQUITTO_LIB)
    find_path(MOSQUITTO_INCLUDE mosquitto.h)
    if(MOSQUITTO_INCLUDE)
        include_directories(${MOSQUITTO_INCLUDE})
    endif()
else()
    message(FATAL_ERROR "Mosquitto library not found!")
endif()

file(GLOB RASPB_NIER_SOURCES
    "${PROJECT_SOURCE_DIR}/src/RASPB-NIER/*.c"
)

add_executable(nier ${RASPB_NIER_SOURCES})

target_include_directories(nier PUBLIC
    "${PROJECT_SOURCE_DIR}/src/RASPB-NIER"
)

target_link_libraries(nier
    m
    sqlite3
    pthread
    ${OPENSSL_LIBRARIES}
    ${MOSQUITTO_LIB}
)

set_target_properties(nier PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}"
)
