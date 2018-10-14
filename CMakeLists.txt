cmake_minimum_required(VERSION 2.8)

project(openssling)
find_package(Qt5Core)
find_package(Qt5Network)
find_package(OpenSSL 1.1 REQUIRED)

find_path(QTKEYCHAIN_INCLUDE_DIR
            NAMES
              keychain.h
            HINTS
               ${QT_LIB_DIR}/../include
            PATH_SUFFIXES
              qt5keychain
            )

find_library(QTKEYCHAIN_LIBRARY
            NAMES
              qt5keychain
              lib5qtkeychain
            HINTS
               ${QT_LIB_DIR}
            PATHS
               /usr/lib
               /usr/lib/${CMAKE_ARCH_TRIPLET}
               /usr/local/lib
               /opt/local/lib
               ${CMAKE_LIBRARY_PATH}
               ${CMAKE_INSTALL_PREFIX}/lib
            )

include_directories(${OPENSSL_INCLUDE_DIR})
list(APPEND openssling_LIBRARIES ${OPENSSL_LIBRARIES})

include_directories(${QTKEYCHAIN_INCLUDE_DIR})
list(APPEND openssling_LIBRARIES ${QTKEYCHAIN_LIBRARY})

add_executable(${PROJECT_NAME} "main.cpp")
target_link_libraries(${PROJECT_NAME} Qt5::Core Qt5::Network ${OPENSSL_LIBRARIES} ${QTKEYCHAIN_LIBRARY})
