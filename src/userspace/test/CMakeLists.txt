add_executable(ufs_test test.cpp)
target_link_libraries(ufs_test photon_static userfs_lib)
add_executable(ufs_test_2 test2.cpp)
target_link_libraries(ufs_test_2 photon_static userfs_lib)