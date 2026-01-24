#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
# Stratosphere Linux IPS. A machine-learning Intrusion Detection System
# Copyright (C) 2021 Sebastian Garcia

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
# Contact: eldraco@gmail.com, sebastian.garcia@agents.fel.cvut.cz, stratosphere@aic.fel.cvut.cz

from __future__ import print_function

import os
import sys
import time
import warnings

from smartshield.main import Main
from smartshield.daemon import Daemon


# Ignore warnings on CPU from tensorflow
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"
# Ignore warnings in general
warnings.filterwarnings("ignore")


####################
# Main
####################
if __name__ == "__main__":
    if sys.version_info[0] < 3:
        sys.exit("smartshield can only run on python3+ .. Stopping.")

    smartshield = Main()

    if smartshield.args.stopdaemon:
        # -S is provided
        daemon_status: dict = Daemon(smartshield).stop()
        # it takes about 5 seconds for the stop_smartshield msg
        # to arrive in the channel, so give smartshield time to stop
        time.sleep(5)
        if daemon_status["stopped"]:
            print("Daemon stopped.")
        else:
            print(daemon_status["error"])

    elif smartshield.args.daemon:
        print("smartshield daemon starting..")
        Daemon(smartshield).start()
    else:
        # interactive mode
        smartshield.start()
