cmake_minimum_required(VERSION 3.10)
project(Nier C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -fstack-protector-all -D_FORTIFY_SOURCE=2 -O2 -fPIE -fPIC")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie -z relro -z now")

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(CJSON libcjson)
endif()

if(NOT CJSON_FOUND)
    find_library(CJSON_LIB 
        NAMES cjson libcjson
        PATHS /usr/lib /usr/local/lib /opt/local/lib
    )
    find_path(CJSON_INCLUDE_DIR
        NAMES cJSON.h
        PATHS /usr/include /usr/local/include /opt/local/include
        PATH_SUFFIXES cjson
    )
    
    if(CJSON_LIB AND CJSON_INCLUDE_DIR)
        set(CJSON_FOUND TRUE)
        set(CJSON_LIBRARIES ${CJSON_LIB})
        set(CJSON_INCLUDE_DIRS ${CJSON_INCLUDE_DIR})
    endif()
endif()

if(NOT CJSON_FOUND)
    message(FATAL_ERROR "cJSON library not found. Please install libcjson-dev or equivalent package.")
endif()

include_directories(${CJSON_INCLUDE_DIRS})

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    include_directories(${OPENSSL_INCLUDE_DIR})
else()
    message(FATAL_ERROR "OpenSSL not found.")
endif()

find_library(MOSQUITTO_LIB mosquitto PATHS /usr/lib)
if(MOSQUITTO_LIB)
    find_path(MOSQUITTO_INCLUDE mosquitto.h PATHS /usr/include)
    if(MOSQUITTO_INCLUDE)
        include_directories(${MOSQUITTO_INCLUDE})
    else()
        message(FATAL_ERROR "mosquitto.h not found.")
    endif()
else()
    message(FATAL_ERROR "Mosquitto library not found.")
endif()

find_package(CURL REQUIRED)
if(CURL_FOUND)
    include_directories(${CURL_INCLUDE_DIRS})
else()
    message(FATAL_ERROR "libcurl not found. Please install libcurl-dev or equivalent package.")
endif()

find_library(AVCODEC_LIB avcodec PATHS /usr/lib /usr/local/lib /opt/local/lib)
find_library(AVFORMAT_LIB avformat PATHS /usr/lib /usr/local/lib /opt/local/lib)
find_library(AVUTIL_LIB avutil PATHS /usr/lib /usr/local/lib /opt/local/lib)

if(AVCODEC_LIB AND AVFORMAT_LIB AND AVUTIL_LIB)
    message(STATUS "FFmpeg libraries found.")
    include_directories(/usr/include /usr/local/include)
else()
    message(FATAL_ERROR "FFmpeg libraries not found. Please install FFmpeg development packages.")
endif()

include_directories(SYSTEM /path/to/mongoose)

file(GLOB RASPB_NIER_SOURCES "${PROJECT_SOURCE_DIR}/src/RASPB-NIER/*.c")
add_executable(nier ${RASPB_NIER_SOURCES})
target_include_directories(nier PUBLIC "${PROJECT_SOURCE_DIR}/src/RASPB-NIER")
target_link_libraries(nier 
    m 
    sqlite3 
    pthread 
    ${OPENSSL_LIBRARIES} 
    ${MOSQUITTO_LIB} 
    ${CJSON_LIBRARIES} 
    ${CURL_LIBRARIES} 
    ${AVCODEC_LIB} 
    ${AVFORMAT_LIB} 
    ${AVUTIL_LIB}
)
set_target_properties(nier PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}")
