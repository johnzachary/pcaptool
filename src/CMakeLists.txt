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

set(LIBPCAPTOOL_SRC
    libpcaptool.c
)

add_library(libpcaptool SHARED ${LIBPCAPTOOL_SRC})
set_target_properties(libpcaptool PROPERTIES
    OUTPUT_NAME libpcaptool
    SOVERSION 0.0.0
)
target_link_libraries(libpcaptool
    ${CORK_LIBRARIES}
    ${CLOGGER_LIBRARIES}
    ${PCAP_LIBRARY}
)

#-----------------------------------------------------------------------
# Build the executable

set(PCAPTOOL_SRC
    pcaptool.c
)

add_executable(pcaptool ${PCAPTOOL_SRC})
target_link_libraries(pcaptool
    ${CORK_LIBRARIES}
    ${CLOGGER_LIBRARIES}
    ${PCAP_LIBRARY}
)

#-----------------------------------------------------------------------
# Install the library and executable

install(TARGETS pcaptool libpcaptool
    DESTINATION bin
    LIBRARY DESTINATION lib
)

#-----------------------------------------------------------------------
# Generate the pkg-config file

set(prefix ${CMAKE_INSTALL_PREFIX})
configure_file(pcaptool.pc.in pcaptool.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/pcaptool.pc
        DESTINATION lib/pkgconfig)
