cmake_minimum_required(VERSION 3.2)
project(gpgme_sample)

set(CMAKE_C_STANDARD 99)

set(CMAKE_C_FLAGS "-Wall")

add_library(common src/common.c)

set(LIBS common gpgme)

add_executable(list_keys src/list_keys.c)
target_link_libraries(list_keys ${LIBS})

add_executable(encrypt src/encrypt.c)
target_link_libraries(encrypt ${LIBS})

add_executable(decrypt src/decrypt.c)
target_link_libraries(decrypt ${LIBS})

add_executable(sign src/sign.c)
target_link_libraries(sign ${LIBS})

add_executable(verify src/verify.c)
target_link_libraries(verify ${LIBS})

add_executable(encrypt_sign src/encrypt_sign.c)
target_link_libraries(encrypt_sign ${LIBS})

add_executable(decrypt_verify src/decrypt_verify.c)
target_link_libraries(decrypt_verify ${LIBS})

add_executable(key_edit src/key_edit.c)
target_link_libraries(key_edit ${LIBS})
