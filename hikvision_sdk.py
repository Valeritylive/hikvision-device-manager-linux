"""Optional Hikvision Device Network SDK helpers for NVR-mediated SADP operations."""

from __future__ import annotations

import ctypes
import ipaddress
import os
from pathlib import Path

from hikvision_api import HikvisionError


DEFAULT_LIBRARY = (Path(__file__).resolve().parent /
                   "EN-HCNetSDKV6.1.9.4_build20220412_linux64/lib/libhcnetsdk.so")


class _IPAddr(ctypes.Structure):
    _fields_ = [("ipv4", ctypes.c_char * 16), ("ipv6_reserved", ctypes.c_ubyte * 128)]


class _SadpInfo(ctypes.Structure):
    _fields_ = [
        ("ip", _IPAddr), ("port", ctypes.c_uint16), ("factory_type", ctypes.c_uint16),
        ("software_version", ctypes.c_char * 48), ("serial", ctypes.c_char * 16),
        ("encoder_count", ctypes.c_uint16), ("mac", ctypes.c_ubyte * 6),
        ("subnet_mask", _IPAddr), ("gateway", _IPAddr), ("dns1", _IPAddr), ("dns2", _IPAddr),
        ("dns_enabled", ctypes.c_ubyte), ("dhcp", ctypes.c_ubyte),
        ("gb28181_id", ctypes.c_ubyte * 32), ("activated", ctypes.c_ubyte),
        ("model", ctypes.c_ubyte * 24), ("reserved", ctypes.c_ubyte * 101),
    ]


class _SadpInfoList(ctypes.Structure):
    _fields_ = [("size", ctypes.c_uint32), ("count", ctypes.c_uint16),
                ("reserved", ctypes.c_ubyte * 6), ("items", _SadpInfo * 256)]


class _SadpVerify(ctypes.Structure):
    _fields_ = [("password", ctypes.c_char * 16), ("old_ip", _IPAddr),
                ("old_port", ctypes.c_uint16), ("reserved", ctypes.c_ubyte * 62)]


def _library() -> ctypes.CDLL:
    configured = os.environ.get("HIKVISION_HCNETSDK_LIBRARY")
    path = Path(configured) if configured else DEFAULT_LIBRARY
    if not path.is_file():
        raise HikvisionError("HCNetSDK для операций через регистратор не найден.")
    try:
        sdk = ctypes.CDLL(str(path))
    except OSError as exc:
        raise HikvisionError(f"Не удалось загрузить HCNetSDK: {exc}") from exc
    sdk.NET_DVR_Init.argtypes = []
    sdk.NET_DVR_Init.restype = ctypes.c_int
    sdk.NET_DVR_Cleanup.argtypes = []
    sdk.NET_DVR_Cleanup.restype = ctypes.c_int
    sdk.NET_DVR_GetLastError.argtypes = []
    sdk.NET_DVR_GetLastError.restype = ctypes.c_uint32
    sdk.NET_DVR_Login_V30.argtypes = [ctypes.c_char_p, ctypes.c_uint16, ctypes.c_char_p,
                                      ctypes.c_char_p, ctypes.c_void_p]
    sdk.NET_DVR_Login_V30.restype = ctypes.c_int32
    sdk.NET_DVR_Logout.argtypes = [ctypes.c_int32]
    sdk.NET_DVR_Logout.restype = ctypes.c_int
    sdk.NET_DVR_GetSadpInfoList.argtypes = [ctypes.c_int32, ctypes.POINTER(_SadpInfoList)]
    sdk.NET_DVR_GetSadpInfoList.restype = ctypes.c_int
    sdk.NET_DVR_UpdateSadpInfo.argtypes = [ctypes.c_int32, ctypes.POINTER(_SadpVerify),
                                           ctypes.POINTER(_SadpInfo)]
    sdk.NET_DVR_UpdateSadpInfo.restype = ctypes.c_int
    return sdk


def _text(value: bytes) -> str:
    return value.split(b"\0", 1)[0].decode("utf-8", errors="replace").strip()


def _ip(value: _IPAddr) -> str:
    return _text(value.ipv4)


def _set_ip(target: _IPAddr, value: str) -> None:
    target.ipv4 = value.encode("ascii")


def _login(sdk: ctypes.CDLL, address: str, port: int, username: str,
           password: str) -> tuple[int, ctypes.Array]:
    device_info = ctypes.create_string_buffer(80)  # NET_DVR_DEVICEINFO_V30 from HCNetSDK.h
    user_id = sdk.NET_DVR_Login_V30(address.encode("ascii"), port,
                                    username.encode("utf-8"), password.encode("utf-8"),
                                    ctypes.byref(device_info))
    if user_id < 0:
        raise HikvisionError(f"Не удалось войти в регистратор через HCNetSDK (код {sdk.NET_DVR_GetLastError()}).")
    return user_id, device_info


def _with_login(address: str, port: int, username: str, password: str, action):
    sdk = _library()
    if not sdk.NET_DVR_Init():
        raise HikvisionError(f"HCNetSDK не удалось инициализировать (код {sdk.NET_DVR_GetLastError()}).")
    user_id = -1
    try:
        user_id, _device_info = _login(sdk, address, port, username, password)
        return action(sdk, user_id)
    finally:
        if user_id >= 0:
            sdk.NET_DVR_Logout(user_id)
        sdk.NET_DVR_Cleanup()


def get_nvr_sadp_devices(address: str, port: int, username: str, password: str) -> list[dict[str, str]]:
    """List cameras the recorder exposes through its remote SADP SDK functions."""
    def read(sdk: ctypes.CDLL, user_id: int) -> list[dict[str, str]]:
        info_list = _SadpInfoList()
        info_list.size = ctypes.sizeof(info_list)
        if not sdk.NET_DVR_GetSadpInfoList(user_id, ctypes.byref(info_list)):
            raise HikvisionError(f"Регистратор не вернул SADP-список камер (код {sdk.NET_DVR_GetLastError()}).")
        result = []
        for index in range(min(info_list.count, 256)):
            item = info_list.items[index]
            mac = ":".join(f"{byte:02X}" for byte in item.mac)
            result.append({
                "mac": mac, "ip": _ip(item.ip), "port": str(item.port),
                "model": _text(bytes(item.model)), "serial": _text(item.serial),
                "firmware": _text(item.software_version), "mask": _ip(item.subnet_mask),
                "gateway": _ip(item.gateway), "dns1": _ip(item.dns1), "dns2": _ip(item.dns2),
                "dhcp": "true" if item.dhcp else "false",
                "activated": "true" if item.activated == 1 else "false" if item.activated == 2 else "",
                "_sdk_index": str(index),
            })
        return result
    return _with_login(address, port, username, password, read)


def modify_nvr_camera_ip(nvr_address: str, nvr_port: int, nvr_username: str, nvr_password: str,
                         camera_mac: str, camera_password: str, new_ip: str, mask: str,
                         gateway: str, dns1: str, dns2: str, dhcp: bool,
                         device_port: int | None = None) -> None:
    """Modify a camera's SADP network settings through the recorder's SDK."""
    try:
        ipaddress.IPv4Address(new_ip) if not dhcp else None
        ipaddress.IPv4Address(mask) if not dhcp else None
        ipaddress.IPv4Address(gateway) if gateway else None
        ipaddress.IPv4Address(dns1) if dns1 else None
        ipaddress.IPv4Address(dns2) if dns2 else None
    except ValueError as exc:
        raise HikvisionError(f"Проверьте сетевые параметры камеры: {exc}") from exc
    camera_password_bytes = camera_password.encode("utf-8")
    if len(camera_password_bytes) > 16:
        raise HikvisionError("Эта функция HCNetSDK допускает пароль камеры до 16 байт.")
    try:
        mac_key = bytes.fromhex(camera_mac.replace(":", "").replace("-", ""))
    except ValueError as exc:
        raise HikvisionError("У камеры некорректный MAC-адрес.") from exc
    if len(mac_key) != 6:
        raise HikvisionError("У камеры некорректный MAC-адрес.")

    def update(sdk: ctypes.CDLL, user_id: int) -> None:
        info_list = _SadpInfoList()
        info_list.size = ctypes.sizeof(info_list)
        if not sdk.NET_DVR_GetSadpInfoList(user_id, ctypes.byref(info_list)):
            raise HikvisionError(f"Не удалось перечитать SADP-список камер (код {sdk.NET_DVR_GetLastError()}).")
        item = next((info_list.items[index] for index in range(min(info_list.count, 256))
                     if bytes(info_list.items[index].mac) == mac_key), None)
        if item is None:
            raise HikvisionError("Камера с выбранным MAC-адресом больше не найдена в SADP-списке регистратора.")
        verify = _SadpVerify()
        ctypes.memmove(ctypes.addressof(verify), camera_password_bytes.ljust(16, b"\0"), 16)
        verify.old_ip = item.ip
        verify.old_port = item.port
        if not dhcp:
            _set_ip(item.ip, new_ip)
            _set_ip(item.subnet_mask, mask)
            _set_ip(item.gateway, gateway or "0.0.0.0")
            if dns1:
                _set_ip(item.dns1, dns1)
            if dns2:
                _set_ip(item.dns2, dns2)
        item.dhcp = 1 if dhcp else 0
        if device_port is not None:
            if not 1 <= device_port <= 65535:
                raise HikvisionError("Порт камеры должен быть от 1 до 65535.")
            item.port = device_port
        if not sdk.NET_DVR_UpdateSadpInfo(user_id, ctypes.byref(verify), ctypes.byref(item)):
            raise HikvisionError(f"Регистратор не изменил сетевые параметры камеры (код {sdk.NET_DVR_GetLastError()}).")
    _with_login(nvr_address, nvr_port, nvr_username, nvr_password, update)
