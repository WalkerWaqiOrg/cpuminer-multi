cmake_minimum_required(VERSION 3.5)

project(minerd)

set(JANSSON_INCLUDES ${PROJECT_SOURCE_DIR}/compat/jansson)

#install(FILES example-cfg.json nomacro.pl)

add_subdirectory(compat)

include_directories(${JANSSON_INCLUDES})
include_directories(${PROJECT_SOURCE_DIR})

set(minerd_SOURCES elist.h
		  miner.h
		  compat.h
		  cpu-miner.c
		  rrhash.c
		  rpc/server_stub.c rpc/rpcserver.c rpc/mybind.c
		  util.c
		  # sha2.c
		  # scrypt.c
		  keccak.c
		  # heavy.c
		  quark.c
		  # skein.c
		  ink.c
		  blake.c
		  cryptonight.c
		  fresh.c
		  x11.c
		  x13.c
		  x14.c
		  x15.c
		  sha3/sph_keccak.c
		  sha3/sph_hefty1.c
		  sha3/sph_groestl.c
		  sha3/sph_skein.c
		  sha3/sph_bmw.c
		  sha3/sph_jh.c
		  sha3/sph_shavite.c
		  sha3/sph_blake.c
		  sha3/sph_luffa.c
		  sha3/sph_cubehash.c
		  sha3/sph_simd.c
		  sha3/sph_echo.c
		  sha3/sph_hamsi.c
		  sha3/sph_fugue.c
		  sha3/sph_shabal.c
		  sha3/sph_whirlpool.c
		  crypto/oaes_lib.c
		  crypto/c_keccak.c
		  crypto/c_groestl.c
		  crypto/c_blake256.c
		  crypto/c_jh.c
		  crypto/c_skein.c
		  crypto/hash.c
		  crypto/aesb.c
		  external.c

          #sha2-x86.S scrypt-x86.S aesb-x86.S crypto/aesb-x86-impl.c
          #sha2-x64.S scrypt-x64.S aesb-x64.S
          #sha2-arm.S scrypt-arm.S aesb-arm.S crypto/aesb-x86-impl.c
)

set(CMAKE_C_FLAGS "-pthread -Ofast -fuse-linker-plugin -fno-strict-aliasing")

#  -flto

#add_custom_target(jasson ${JANSSON_INCLUDES}/libjansson.a)
add_executable(minerd ${minerd_SOURCES})


find_package(CURL REQUIRED)
include_directories(${CURL_INCLUDE_DIR})
target_link_libraries(minerd ${CURL_LIBRARY})

target_link_libraries(minerd ${JANSSON_INCLUDES}/libjansson.a)

#add_dependencies(minerd jasson)


#target_link_libraries(minerd "-lpthread")
#target_link_libraries(minerd "-lws2_32")
