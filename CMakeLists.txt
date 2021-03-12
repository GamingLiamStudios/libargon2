cmake_minimum_required(VERSION 3.9)
project(argon2 LANGUAGES C)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${PROJECT_NAME})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${PROJECT_NAME})

option(${BUILD_SHARED_LIBS} "Build libraries as shared libraries" ON)
option(USE_THREADS "Enables use of parallelism" ON)

set(SOURCE_FILES
    src/argon2.c
    src/core.c 
    src/blake2/blake2b.c 
    src/thread.c 
    src/encoding.c
)

# Compile Architecture Testing
set(CMAKE_TRY_COMPILE_TARGET_TYPE "STATIC_LIBRARY")
if(MSVC)
    message(WARNING "MSVC Not Tested")
    # Some Weird hack to get '-march=native' in msvc
    set(ARCH "native" CACHE STRING "Architecture to tell compiler to optimize for (/arch)")

    set(TARCH ${ARCH})
    if(ARCH EQUAL "native")
        set(TARCH "AVX512")
    endif()
    try_compile(OPTTEST ${CMAKE_BINARY_DIR} "${CMAKE_SOURCE_DIR}/src/opt.c" 
        CMAKE_FLAGS "-DCMAKE_C_FLAGS=${CMAKE_C_FLAGS} /arch:${TARCH}"
        "-DINCLUDE_DIRECTORIES=${CMAKE_SOURCE_DIR}/src;${CMAKE_SOURCE_DIR}/include"
        C_STANDARD 90 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
    )
    if(NOT OPTTEST AND ARCH EQUAL "native")
        set(ARCH "AVX2")
        try_compile(OPTTEST ${CMAKE_BINARY_DIR} "${CMAKE_SOURCE_DIR}/src/opt.c" 
            CMAKE_FLAGS "-DCMAKE_C_FLAGS=${CMAKE_C_FLAGS} /arch:${ARCH}"
            "-DINCLUDE_DIRECTORIES=${CMAKE_SOURCE_DIR}/src;${CMAKE_SOURCE_DIR}/include"
            C_STANDARD 90 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
        )
        if(NOT OPTTEST)
            message(STATUS "Building without optimizations")
            set(SOURCE_FILES ${SOURCE_FILES} src/ref.c)
        else()
            message(STATUS "Building with optimizations for ${ARCH}")
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /arch:${ARCH}")
            set(SOURCE_FILES ${SOURCE_FILES} src/opt.c)
        endif()
    elseif(NOT OPTTEST)
        message(STATUS "Building without optimizations")
        set(SOURCE_FILES ${SOURCE_FILES} src/ref.c)
    else()
        message(STATUS "Building with optimizations for ${TARCH}")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /arch:${TARCH}")
        set(SOURCE_FILES ${SOURCE_FILES} src/opt.c)
    endif()
else()
    set(ARCH "native" CACHE STRING "Architecture to tell compiler to optimize for (-march)")

    try_compile(OPTTEST ${CMAKE_BINARY_DIR} "${CMAKE_SOURCE_DIR}/src/opt.c" 
        CMAKE_FLAGS "-DCMAKE_C_FLAGS=${CMAKE_C_FLAGS} -march=${ARCH}"
        "-DINCLUDE_DIRECTORIES=${CMAKE_SOURCE_DIR}/src;${CMAKE_SOURCE_DIR}/include"
        C_STANDARD 90 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
    )
    if(NOT OPTTEST)
        message(STATUS "Building without optimizations")
        set(SOURCE_FILES ${SOURCE_FILES} src/ref.c)
    else()
        message(STATUS "Building with optimizations for ${ARCH}")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=${ARCH}")
        set(SOURCE_FILES ${SOURCE_FILES} src/opt.c)
    endif()
endif()


add_library(${PROJECT_NAME} ${SOURCE_FILES})

target_compile_features(${PROJECT_NAME} PRIVATE c_std_90)

target_include_directories(${PROJECT_NAME} PUBLIC "include")
target_include_directories(${PROJECT_NAME} PRIVATE "src")

if(USE_THREADS)
    set(THREADS_PREFER_PTHREAD_FLAG ON)
    find_package(Threads REQUIRED)

    target_link_libraries(${PROJECT_NAME} PRIVATE Threads::Threads)
else()
    target_compile_definitions(${PROJECT_NAME} PRIVATE ARGON2_NO_THREADS)
endif()
