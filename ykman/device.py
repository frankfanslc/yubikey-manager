# Copyright (c) 2015-2020 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

from yubikit.core import Connection, PID
from yubikit.core.otp import OtpConnection
from yubikit.core.fido import FidoConnection
from yubikit.core.smartcard import SmartCardConnection
from yubikit.management import (
    DeviceInfo,
    USB_INTERFACE,
)
from yubikit.support import read_info
from .base import YkmanDevice
from .hid import (
    list_otp_devices as _list_otp_devices,
    list_ctap_devices as _list_ctap_devices,
)
from .pcsc import list_devices as _list_ccid_devices
from smartcard.pcsc.PCSCExceptions import EstablishContextException
from smartcard.Exceptions import NoCardException

from time import sleep
from collections import Counter
from typing import Dict, Mapping, List, Tuple, Optional, Iterable, Type, cast
import sys
import ctypes
import logging

logger = logging.getLogger(__name__)


class ConnectionNotAvailableException(ValueError):
    def __init__(self, connection_types):
        types_str = ", ".join([c.__name__ for c in connection_types])
        super().__init__(f"No eligiable connections are available ({types_str}).")
        self.connection_types = connection_types


def _warn_once(message, e_type=Exception):
    warned: List[bool] = []

    def outer(f):
        def inner():
            try:
                return f()
            except e_type:
                if not warned:
                    logger.warning(message)
                    warned.append(True)
                raise

        return inner

    return outer


@_warn_once(
    "PC/SC not available. Smart card (CCID) protocols will not function.",
    EstablishContextException,
)
def list_ccid_devices():
    return _list_ccid_devices()


@_warn_once("No CTAP HID backend available. FIDO protocols will not function.")
def list_ctap_devices():
    return _list_ctap_devices()


@_warn_once("No OTP HID backend available. OTP protocols will not function.")
def list_otp_devices():
    return _list_otp_devices()


CONNECTION_LIST_MAPPING = {
    SmartCardConnection: list_ccid_devices,
    OtpConnection: list_otp_devices,
    FidoConnection: list_ctap_devices,
}


def scan_devices() -> Tuple[Mapping[PID, int], int]:
    """Scan USB for attached YubiKeys, without opening any connections.

    Returns a dict mapping PID to device count, and a state object which can be used to
    detect changes in attached devices.
    """
    fingerprints = set()
    merged: Dict[PID, int] = {}
    for list_devs in CONNECTION_LIST_MAPPING.values():
        try:
            devs = list_devs()
        except Exception:
            logger.debug("Device listing error", exc_info=True)
            devs = []
        merged.update(Counter(d.pid for d in devs if d.pid is not None))
        fingerprints.update({d.fingerprint for d in devs})
    if sys.platform == "win32" and not bool(ctypes.windll.shell32.IsUserAnAdmin()):
        from .hid.windows import list_paths

        counter = Counter()
        for pid, path in list_paths():
            if pid not in merged:
                try:
                    counter[PID(pid)] += 1
                    fingerprints.add(path)
                except ValueError:  # Unsupported PID
                    logger.debug(f"Unsupported Yubico device with PID: {pid:02x}")
        merged.update(counter)
    return merged, hash(tuple(fingerprints))


class _UsbCompositeDevice(YkmanDevice):
    def __init__(self, transport, fingerprint, pid, info, refs):
        super().__init__(transport, fingerprint, pid)
        self.info = info
        self._refs = refs

    def supports_connection(self, connection_type):
        return cast(PID, self.pid).usb_interfaces.supports_connection(connection_type)

    def open_connection(self, connection_type):
        if not self.supports_connection(connection_type):
            raise ValueError("Unsupported Connection type")
        iface = connection_type.usb_interface
        dev = self._refs[0][iface].get(self.info.serial or self.fingerprint)

        # Device already known
        if dev:
            return dev.open_connection(connection_type)

        # Lookup among remaining
        devs = self._refs[1][iface].get(self.pid, [])
        logger.debug("Available device candidates: %s", devs)
        while devs:
            candidate = devs.pop()
            logger.debug("Checking candidate: %s", candidate)
            try:
                conn = candidate.open_connection(connection_type)
                info = read_info(self.pid, conn)
                ref_key = info.serial or candidate.fingerprint
                self._refs[0][iface][ref_key] = candidate
                if self.info.serial == info.serial:
                    logger.debug("Match on serial: %s", info.serial)
                    return conn
                conn.close()
            except Exception:
                logger.exception("Failed opening device")

        raise ValueError("Failed to connect to the device")


def list_all_devices() -> List[Tuple[YkmanDevice, DeviceInfo]]:
    """Connects to all attached YubiKeys and reads device info from them.

    Returns a list of (device, info) tuples for each connected device.
    """
    handled_pids = set()
    pids: Dict[PID, bool] = {}
    refs: Tuple = ({i: {} for i in USB_INTERFACE}, {i: {} for i in USB_INTERFACE})
    devices: List[Tuple[YkmanDevice, DeviceInfo]] = []

    for connection_type, list_devs in CONNECTION_LIST_MAPPING.items():
        iface = connection_type.usb_interface
        try:
            devs = list_devs()
        except Exception:
            logger.exception("Unable to list devices for connection")
            devs = []

        for dev in devs:
            if dev.pid not in handled_pids and pids.get(dev.pid, True):
                try:
                    with dev.open_connection(connection_type) as conn:
                        info = read_info(dev.pid, conn)
                    pids[dev.pid] = True
                    ref_key = info.serial or dev.fingerprint
                    refs[0][iface][ref_key] = dev
                    devices.append(
                        (
                            _UsbCompositeDevice(
                                dev.transport, dev.fingerprint, dev.pid, info, refs
                            ),
                            info,
                        )
                    )
                except Exception:
                    pids[dev.pid] = False
                    logger.exception("Failed opening device")
            else:
                refs[1][iface].setdefault(dev.pid, []).append(dev)
        handled_pids.update({pid for pid, handled in pids.items() if handled})

    return devices


def connect_to_device(
    serial: Optional[int] = None,
    connection_types: Iterable[Type[Connection]] = CONNECTION_LIST_MAPPING.keys(),
) -> Tuple[Connection, YkmanDevice, DeviceInfo]:
    """Looks for a YubiKey to connect to.

    :param serial: Used to filter devices by serial number, if present.
    :param connection_types: Filter connection types.
    :return: An open connection to the device, the device reference, and the device
        information read from the device.
    """
    failed_connections = set()
    retry_ccid = []
    for connection_type in connection_types:
        try:
            devs = CONNECTION_LIST_MAPPING[connection_type]()
        except Exception:
            logger.debug(
                f"Error listing connection of type {connection_type}", exc_info=True
            )
            failed_connections.add(connection_type)
            continue

        for dev in devs:
            try:
                conn = dev.open_connection(connection_type)
            except NoCardException:
                retry_ccid.append(dev)
                logger.debug("CCID No card present, will retry")
                continue
            info = read_info(dev.pid, conn)
            if serial and info.serial != serial:
                conn.close()
            else:
                return conn, dev, info

    if set(connection_types) == failed_connections:
        raise ConnectionNotAvailableException(connection_types)

    # NEO ejects the card when other interfaces are used, and returns it after ~3s.
    for _ in range(6):
        if not retry_ccid:
            break
        sleep(0.5)
        for dev in retry_ccid[:]:
            try:
                conn = dev.open_connection(SmartCardConnection)
            except NoCardException:
                continue
            retry_ccid.remove(dev)
            info = read_info(dev.pid, conn)
            if serial and info.serial != serial:
                conn.close()
            else:
                return conn, dev, info

    if serial:
        raise ValueError("YubiKey with given serial not found")
    raise ValueError("No YubiKey found with the given interface(s)")
