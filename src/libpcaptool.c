/* -*- coding: utf-8 -*-
 *
 * NAME
 *  libpcaptool - library of callbacks for pcaptool
 *
 * DESCRIPTION
 *  The library extensively uses the libcork and clogger libraries.
 *
 *  Coding style is based on the Google C++ Style Guide.
 *  Ref. http://google-styleguide.googlecode.com/svn/trunk/cppguide.xml
 *
 * Copyright 2012. All rights reservered.
 */

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <clogger.h>
#include <libcork/cli.h>
#include <libcork/core.h>
#include <libcork/ds.h>
#include <libcork/helpers/errors.h>

#include "pcaptool.h"

#define CLOG_CHANNEL  "libpcaptool"
#define CLOG_TRACE  1


