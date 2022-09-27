link_libraries(ext2fs)

add_executable(userobd
  user.cpp
)
target_include_directories(userobd PUBLIC
  ${PHOTON_INCLUDE_DIR}
  ${CMAKE_SOURCE_DIR}/src/overlaybd
)

target_link_libraries(userobd
  photon_static
  overlaybd_lib
)
