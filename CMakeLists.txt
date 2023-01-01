project(MTLS)

add_executable(mtlsserver ./src/server.c)
add_executable(mtlsclient ./src/client.c)

target_link_libraries(mtlsserver wolfssl)
target_link_libraries(mtlsclient wolfssl)