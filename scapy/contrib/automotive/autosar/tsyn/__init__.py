# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Jack Winch <jack.winch@bitryx.io>

# scapy.contrib.description = AUTOSAR Time Synchronization Protocol Suite
# scapy.contrib.status = loads

"""
AUTOSAR Time Synchronization (TSyn) Protocol Suite

This package provides support for AUTOSAR Time Synchronization protocols
over CAN and FlexRay networks.

Modules:
    can: Time Synchronization over CAN and CAN FD
    flexray: Time Synchronization over FlexRay
    common: Shared constants and utilities

Usage:
    # Import protocol-specific modules
    from scapy.contrib.automotive.autosar.tsyn import can, flexray

    # Or import specific classes
    from scapy.contrib.automotive.autosar.tsyn.can import TSynCanBase, Sync
    from scapy.contrib.automotive.autosar.tsyn.flexray import TSynFlexRayBase

    # Or import shared constants
    from scapy.contrib.automotive.autosar.tsyn.common import (
        MESSAGE_TYPE_SYNC,
        MESSAGE_TYPE_SYNC_CRC,
    )
"""

# Make submodules easily accessible
from scapy.contrib.automotive.autosar.tsyn import can, flexray, common

__all__ = ['can', 'flexray', 'common']
