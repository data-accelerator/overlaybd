include(FetchContent)
set(FETCHCONTENT_QUIET false)

FetchContent_Declare(
  photon
  GIT_REPOSITORY https://github.com/liulanzheng/PhotonLibOS.git
  GIT_TAG main
)

if(BUILD_TESTING)
  set(BUILD_TESTING 0)
  FetchContent_MakeAvailable(photon)
  set(BUILD_TESTING 1)
else()
  FetchContent_MakeAvailable(photon)
endif()
set(PHOTON_INCLUDE_DIR ${photon_SOURCE_DIR}/include/)
