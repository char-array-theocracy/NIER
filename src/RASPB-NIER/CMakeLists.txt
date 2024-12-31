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
    message(STATUS "OpenSSL found: ${OPENSSL_VERSION}")
    include_directories(${OPENSSL_INCLUDE_DIR})
else()
    message(FATAL_ERROR "OpenSSL not found!")
endif()

find_library(MOSQUITTO_LIB mosquitto)
if(MOSQUITTO_LIB)
    message(STATUS "Mosquitto library found: ${MOSQUITTO_LIB}")
    # Optionally add an include path if required
    find_path(MOSQUITTO_INCLUDE mosquitto.h)
    if(MOSQUITTO_INCLUDE)
        message(STATUS "Mosquitto include directory: ${MOSQUITTO_INCLUDE}")
        include_directories(${MOSQUITTO_INCLUDE})
    else()
        message(WARNING "Mosquitto include directory not found!")
    endif()
else()
    message(FATAL_ERROR "Mosquitto library not found!")
endif()

add_executable(nier main.c mongoose.c NIER.c cJSON.c)

include_directories(${CMAKE_SOURCE_DIR})

target_link_libraries(nier
    m
    sqlite3
    pthread
    ${OPENSSL_LIBRARIES}
    ${MOSQUITTO_LIB} 
)

set_target_properties(nier PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/..)

add_custom_command(
    TARGET nier
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/Debug
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:nier> ${CMAKE_BINARY_DIR}/Debug/outDebug
    COMMENT "Copying the executable to /build/Debug/outDebug"
)
