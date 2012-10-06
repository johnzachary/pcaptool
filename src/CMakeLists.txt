# -*- coding: utf-8 -*-
# ----------------------------------------------------------------------
# Copyright © 2011, RedJack, LLC.
# All rights reserved.
#
# Please see the LICENSE.txt file in this distribution for license
# details.
# ----------------------------------------------------------------------

include_directories(../include)

#-----------------------------------------------------------------------
# Build the library

file(GLOB_RECURSE LIBPCNT_SRC libpcnt/*.c)

add_library(libpcnt SHARED ${LIBPCNT_SRC})
set_target_properties(libpcnt PROPERTIES
    OUTPUT_NAME appname
    SOVERSION 0.0.0)
target_link_libraries(libpcnt
    ${CORK_LIBRARIES}
)

install(TARGETS libpcnt
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib)

#-----------------------------------------------------------------------
# Generate the pkg-config file

set(prefix ${CMAKE_INSTALL_PREFIX})
configure_file(libpcnt.pc.in libpcnt.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libpcnt.pc
        DESTINATION lib/pkgconfig)
