#!/usr/bin/env python3
"""Small GTK4 SADP discovery client for Linux."""

from __future__ import annotations

import ipaddress
import csv
import os
import secrets
import socket
import struct
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass

import gi

gi.require_version("Gtk", "4.0")
try:
    gi.require_version("Gst", "1.0")
    from gi.repository import Gst
    Gst.init(None)
except (ImportError, ValueError):
    Gst = None
from gi.repository import Gdk, GLib, Gtk

from hikvision_api import (
    HikvisionError,
    activate_device,
    export_guid_file,
    get_network_interfaces,
    get_service_ports,
    get_security_questions,
    set_ipv4,
    set_recovery_email,
    set_service_ports,
    set_security_questions,
    unbind_hik_connect,
)
from hikvision_sdk import get_nvr_sadp_devices, modify_nvr_camera_ip


PORT = 37020
GROUP = "239.255.255.250"


@dataclass
class Device:
    ip: str = ""
    mac: str = ""
    model: str = ""
    serial: str = ""
    firmware: str = ""
    status: str = ""
    http_port: int = 80
    rtsp_port: int = 554
    device_port: int = 8000
    gateway: str = ""
    subnet_mask: str = ""
    ipv6: str = ""
    ipv6_gateway: str = ""
    enhanced_sdk_port: int = 0
    activated: bool | None = None
    raw: dict[str, str] | None = None


def local_interfaces() -> list[tuple[str, str, str]]:
    """Return (interface, IPv4, netmask) for active non-loopback Linux links."""
    result: list[tuple[str, str, str]] = []
    try:
        names = os.listdir("/sys/class/net")
    except OSError:
        return result
    ctl = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for name in names:
            if name == "lo" or not os.path.exists(f"/sys/class/net/{name}/operstate"):
                continue
            if open(f"/sys/class/net/{name}/operstate", encoding="ascii").read().strip() not in ("up", "unknown"):
                continue
            try:
                req = struct.pack("256s", name.encode()[:15])
                addr = socket.inet_ntoa(fcntl_ioctl(ctl, 0x8915, req)[20:24])
                mask = socket.inet_ntoa(fcntl_ioctl(ctl, 0x891B, req)[20:24])
                result.append((name, addr, mask))
            except OSError:
                continue
    finally:
        ctl.close()
    return result


def fcntl_ioctl(sock: socket.socket, request: int, data: bytes) -> bytes:
    import fcntl
    return fcntl.ioctl(sock.fileno(), request, data)


def parse_response(data: bytes, sender_ip: str) -> Device | None:
    try:
        root = ET.fromstring(data.decode("utf-8", errors="replace"))
    except ET.ParseError:
        return None
    fields = {node.tag.rsplit("}", 1)[-1].lower(): (node.text or "").strip()
              for node in root.iter() if node is not root}
    # SADP replies have appeared as ProbeMatch and as flat DeviceInfo XML.
    ip = fields.get("ipv4address") or fields.get("ipaddress") or sender_ip
    mac = fields.get("mac") or fields.get("macaddress") or ""
    model = fields.get("deviceproductionname") or fields.get("model") or fields.get("devicetype") or ""
    serial = fields.get("serialno") or fields.get("serialnumber") or fields.get("deviceid") or ""
    firmware = fields.get("softwareversion") or fields.get("firmwareversion") or ""
    status = fields.get("activestatus") or fields.get("activationstatus") or ""
    activation_raw = fields.get("activated") or fields.get("activestatus") or fields.get("activationstatus")
    activated = None
    if activation_raw:
        value = activation_raw.strip().lower()
        if value in ("true", "1", "activated", "active"):
            activated = True
        elif value in ("false", "0", "inactive", "not activated", "notactivated"):
            activated = False
    try:
        http_port = int(fields.get("httpport") or fields.get("httpserviceport") or "80")
    except ValueError:
        http_port = 80
    try:
        rtsp_port = int(fields.get("rtspport") or fields.get("rtspserviceport") or "554")
    except ValueError:
        rtsp_port = 554
    try:
        device_port = int(fields.get("port") or fields.get("sdkport") or "8000")
    except ValueError:
        device_port = 8000
    gateway = fields.get("ipv4gateway") or fields.get("gateway") or ""
    subnet_mask = fields.get("ipv4subnetmask") or fields.get("subnetmask") or ""
    ipv6 = fields.get("ipv6address") or fields.get("ipv6addr") or ""
    ipv6_gateway = fields.get("ipv6gateway") or ""
    try:
        enhanced_sdk_port = int(fields.get("enhancedsdkport") or fields.get("sdkhttpsport") or "0")
    except ValueError:
        enhanced_sdk_port = 0
    if not any((mac, model, serial)):
        return None
    return Device(ip=ip, mac=mac, model=model, serial=serial, firmware=firmware,
                  status=status, http_port=http_port, rtsp_port=rtsp_port, device_port=device_port,
                  gateway=gateway, subnet_mask=subnet_mask, ipv6=ipv6,
                  ipv6_gateway=ipv6_gateway, enhanced_sdk_port=enhanced_sdk_port,
                  activated=activated, raw=fields)


def discover(interface: tuple[str, str, str], timeout: float = 3.0) -> list[Device]:
    name, address, netmask = interface
    payload = (f'<?xml version="1.0" encoding="utf-8"?>'
               f'<Probe><Uuid>{secrets.token_hex(16)}</Uuid><Types>inquiry</Types></Probe>').encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(0.25)
    devices: dict[str, Device] = {}
    try:
        sock.bind(("", PORT))
        # Scope multicast to the selected NIC; many devices also listen to local broadcast.
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(address))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        group_req = socket.inet_aton(GROUP) + socket.inet_aton(address)
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, group_req)
        except OSError:
            pass
        broadcasts = {"255.255.255.255"}
        try:
            network = ipaddress.IPv4Network(f"{address}/{netmask}", strict=False)
            broadcasts.add(str(network.broadcast_address))
        except ValueError:
            pass
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            for target in (GROUP, *broadcasts):
                try:
                    sock.sendto(payload, (target, PORT))
                except OSError:
                    continue
            burst_end = min(until, time.monotonic() + 0.6)
            while time.monotonic() < burst_end:
                try:
                    packet, peer = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                device = parse_response(packet, peer[0])
                if device:
                    devices[device.mac or device.serial or device.ip] = device
        return sorted(devices.values(), key=lambda d: (d.ip, d.mac))
    finally:
        sock.close()


class SadpWindow(Gtk.ApplicationWindow):
    def __init__(self, app: Gtk.Application):
        super().__init__(application=app, title="Hikvision Device Manager")
        self.set_default_size(1040, 680)
        self.set_size_request(760, 480)
        self.interfaces = local_interfaces()
        self.devices: dict[str, Device] = {}
        self.device_seen: dict[str, float] = {}
        self.checked_devices: set[str] = set()
        self.live_view_windows: list[Gtk.Window] = []
        self.scanning = False
        self.selected: Device | None = None
        self.scan_button = Gtk.Button(label="⟳  Найти устройства")
        self.scan_button.add_css_class("suggested-action")
        self.scan_button.connect("clicked", self.on_scan)

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        outer.add_css_class("background")
        self.set_child(outer)
        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        header.set_margin_top(18); header.set_margin_bottom(18)
        header.set_margin_start(22); header.set_margin_end(22)
        title = Gtk.Label(label="Устройства Hikvision")
        title.add_css_class("title-1"); title.set_halign(Gtk.Align.START)
        header.append(title)
        self.count = Gtk.Label(label="Готово к поиску")
        self.count.add_css_class("dim-label")
        self.count.set_hexpand(True); self.count.set_halign(Gtk.Align.END)
        header.append(self.count)
        nvr_button = Gtk.Button(label="Камеры через NVR…")
        nvr_button.connect("clicked", lambda *_: self.open_nvr_sadp())
        header.append(nvr_button)
        header.append(self.scan_button)
        outer.append(header)

        bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        bar.set_margin_start(22); bar.set_margin_end(22); bar.set_margin_bottom(12)
        bar.append(Gtk.Label(label="Сетевой интерфейс:"))
        self.iface_combo = Gtk.DropDown.new_from_strings(
            [f"{name}  ·  {ip}" for name, ip, _mask in self.interfaces] or ["Интерфейсы не найдены"])
        self.iface_combo.set_hexpand(True)
        bar.append(self.iface_combo)
        outer.append(bar)

        tools = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        tools.set_margin_start(22); tools.set_margin_end(22); tools.set_margin_bottom(12)
        self.filter_entry = Gtk.SearchEntry()
        self.filter_entry.set_placeholder_text("Фильтр по IP, модели, MAC или серийному номеру")
        self.filter_entry.set_hexpand(True)
        self.filter_entry.connect("search-changed", lambda *_: self.render_devices())
        tools.append(self.filter_entry)
        self.sort_combo = Gtk.DropDown.new_from_strings(
            ["IP", "Модель", "Статус", "Серийный номер", "MAC", "Прошивка", "Шлюз"])
        self.sort_combo.connect("notify::selected", lambda *_: self.render_devices())
        tools.append(self.sort_combo)
        export_button = Gtk.Button(label="Экспорт CSV")
        export_button.connect("clicked", self.export_devices)
        tools.append(export_button)
        self.batch_activate_button = Gtk.Button(label="Активировать выбранные")
        self.batch_activate_button.connect("clicked", lambda *_: self.open_batch_activation())
        tools.append(self.batch_activate_button)
        self.batch_activate_button.set_sensitive(False)
        self.batch_network_button = Gtk.Button(label="Сменить IP выбранных…")
        self.batch_network_button.connect("clicked", lambda *_: self.open_batch_network())
        self.batch_network_button.set_sensitive(False)
        tools.append(self.batch_network_button)
        select_all = Gtk.Button(label="Выбрать все")
        select_all.connect("clicked", self.toggle_select_all)
        tools.append(select_all)
        outer.append(tools)

        split = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        split.set_wide_handle(True); split.set_vexpand(True)
        split.set_margin_start(22); split.set_margin_end(22); split.set_margin_bottom(12)
        outer.append(split)

        self.list_box = Gtk.ListBox()
        self.list_box.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self.list_box.add_css_class("boxed-list")
        self.list_box.connect("row-selected", self.on_selected)
        scroller = Gtk.ScrolledWindow(); scroller.set_child(self.list_box); scroller.set_min_content_width(570)
        split.set_start_child(scroller); split.set_resize_start_child(True)

        detail_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        detail_box.set_margin_start(24); detail_box.set_margin_top(12)
        detail_box.set_margin_end(10)
        self.detail_title = Gtk.Label(label="Выберите устройство")
        self.detail_title.add_css_class("title-2"); self.detail_title.set_halign(Gtk.Align.START)
        detail_box.append(self.detail_title)
        self.details = Gtk.Grid(column_spacing=18, row_spacing=14)
        detail_box.append(self.details)
        self.actions = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        detail_box.append(self.actions)
        split.set_end_child(detail_box); split.set_position(640)

        foot = Gtk.Label(label="Поиск работает в локальной сети через SADP (UDP 37020). Для изменения настроек потребуется пароль устройства.")
        foot.add_css_class("dim-label"); foot.set_halign(Gtk.Align.START)
        foot.set_margin_start(22); foot.set_margin_bottom(12)
        outer.append(foot)
        self.show_details(None)
        GLib.timeout_add_seconds(15, self.periodic_scan)
        GLib.idle_add(self.on_scan, self.scan_button)

    def on_scan(self, _button: Gtk.Button) -> None:
        if self.scanning:
            return
        if not self.interfaces:
            self.count.set_text("Не найден активный сетевой интерфейс")
            return
        index = self.iface_combo.get_selected()
        interface = self.interfaces[min(index, len(self.interfaces) - 1)]
        self.scan_button.set_sensitive(False)
        self.scanning = True
        self.count.set_text(f"Ищем устройства в {interface[0]}…")
        threading.Thread(target=self.scan_worker, args=(interface,), daemon=True).start()

    def scan_worker(self, interface: tuple[str, str, str]) -> None:
        try:
            found = discover(interface)
            GLib.idle_add(self.update_devices, found, None)
        except OSError as exc:
            GLib.idle_add(self.update_devices, [], str(exc))

    def update_devices(self, found: list[Device], error: str | None) -> bool:
        self.scan_button.set_sensitive(True)
        self.scanning = False
        if error:
            self.count.set_text(f"Ошибка поиска: {error}")
            return False
        now = time.monotonic()
        for device in found:
            key = device.mac or device.serial or device.ip
            self.devices[key] = device
            self.device_seen[key] = now
        expired = [key for key, last_seen in self.device_seen.items() if now - last_seen > 45]
        for key in expired:
            self.devices.pop(key, None)
            self.device_seen.pop(key, None)
            self.checked_devices.discard(key)
        self.render_devices()
        self.count.set_text(f"Найдено устройств: {len(self.devices)}")
        if not self.devices:
            self.count.set_text("Устройства не найдены — проверьте интерфейс и подключение к сети")
        return False

    def periodic_scan(self) -> bool:
        if self.interfaces:
            self.on_scan(self.scan_button)
        return True

    def render_devices(self) -> None:
        while row := self.list_box.get_row_at_index(0):
            self.list_box.remove(row)
        query = self.filter_entry.get_text().strip().lower() if hasattr(self, "filter_entry") else ""
        sort_keys = (
            lambda item: tuple(int(part) for part in item[1].ip.split(".") if part.isdigit()),
            lambda item: item[1].model.lower(),
            lambda item: item[1].status.lower(),
            lambda item: item[1].serial.lower(),
            lambda item: item[1].mac.lower(),
            lambda item: item[1].firmware.lower(),
            lambda item: item[1].gateway.lower(),
        )
        sort_index = min(self.sort_combo.get_selected(), len(sort_keys) - 1) if hasattr(self, "sort_combo") else 0
        for key, device in sorted(self.devices.items(), key=sort_keys[sort_index]):
            haystack = " ".join((device.ip, device.mac, device.model, device.serial, device.firmware,
                                 device.status, device.gateway, device.subnet_mask, str(device.http_port),
                                 str(device.device_port), device.ipv6, device.ipv6_gateway)).lower()
            if query and query not in haystack:
                continue
            rowbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
            rowbox.set_margin_top(10); rowbox.set_margin_bottom(10)
            rowbox.set_margin_start(12); rowbox.set_margin_end(12)
            check = Gtk.CheckButton()
            check.set_active(key in self.checked_devices)
            check.connect("toggled", self.on_device_checked, key)
            rowbox.append(check)
            textbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            title = Gtk.Label(label=device.model or "Устройство Hikvision")
            title.set_halign(Gtk.Align.START); title.add_css_class("heading")
            subtitle = Gtk.Label(label=f"{device.ip}   ·   {device.status or 'Статус неизвестен'}   ·   {device.mac or 'MAC не указан'}")
            subtitle.set_halign(Gtk.Align.START); subtitle.add_css_class("dim-label")
            properties = [f"Шлюз {device.gateway}" if device.gateway else "",
                          f"Маска {device.subnet_mask}" if device.subnet_mask else "",
                          f"SDK {device.device_port}", f"HTTP {device.http_port}",
                          f"RTSP {device.rtsp_port}",
                          device.firmware, f"S/N {device.serial}" if device.serial else ""]
            metadata = Gtk.Label(label="   ·   ".join(value for value in properties if value))
            metadata.set_halign(Gtk.Align.START); metadata.add_css_class("dim-label")
            textbox.append(title); textbox.append(subtitle); textbox.append(metadata)
            textbox.set_hexpand(True)
            rowbox.append(textbox)
            status = Gtk.Label(label=device.status or "Найдено")
            status.add_css_class("dim-label"); rowbox.append(status)
            row = Gtk.ListBoxRow(); row.set_child(rowbox); row.device_key = key
            self.list_box.append(row)
        self.batch_activate_button.set_sensitive(bool(self.checked_devices))

    def on_device_checked(self, _button, key: str) -> None:
        # The checkbox controls batch selection independently of the detail selection.
        checkbox = _button
        if checkbox.get_active():
            self.checked_devices.add(key)
        else:
            self.checked_devices.discard(key)
        self.batch_activate_button.set_sensitive(bool(self.checked_devices))
        self.batch_network_button.set_sensitive(bool(self.checked_devices))

    def toggle_select_all(self, button) -> None:
        visible = []
        query = self.filter_entry.get_text().strip().lower()
        for key, device in self.devices.items():
            if not query or query in " ".join((device.ip, device.mac, device.model, device.serial,
                                                device.firmware, device.status, device.gateway,
                                                device.subnet_mask, str(device.http_port),
                                                str(device.device_port), device.ipv6,
                                                device.ipv6_gateway)).lower():
                visible.append(key)
        if visible and all(key in self.checked_devices for key in visible):
            self.checked_devices.difference_update(visible)
            button.set_label("Выбрать все")
        else:
            self.checked_devices.update(visible)
            button.set_label("Снять выделение")
        self.render_devices()

    def export_devices(self, _button) -> None:
        dialog = Gtk.FileChooserNative.new("Экспорт списка устройств", self,
                                          Gtk.FileChooserAction.SAVE, "Экспорт", "Отмена")
        dialog.set_current_name("hikvision-devices.csv")
        def response(chooser, response_id):
            if response_id == Gtk.ResponseType.ACCEPT:
                file = chooser.get_file()
                path = file.get_path() if file else None
                if path:
                    try:
                        keys = self.checked_devices or set(self.devices)
                        with open(path, "w", newline="", encoding="utf-8-sig") as output:
                            writer = csv.writer(output)
                            extra_columns = sorted({name for device in self.devices.values()
                                                    for name in (device.raw or {})})
                            writer.writerow(["ID", "Модель", "Статус", "IPv4", "Маска IPv4", "Шлюз IPv4",
                                             "IPv6", "Шлюз IPv6", "Порт устройства", "Порт Enhanced SDK",
                                             "HTTP порт", "RTSP порт", "Прошивка", "Серийный номер", "MAC",
                                             *extra_columns])
                            for number, key in enumerate(sorted(keys), 1):
                                device = self.devices.get(key)
                                if device:
                                    raw = device.raw or {}
                                    writer.writerow([number, device.model, device.status, device.ip,
                                                     device.subnet_mask, device.gateway, device.ipv6,
                                                     device.ipv6_gateway, device.device_port,
                                                     device.enhanced_sdk_port or "", device.http_port,
                                                     device.rtsp_port, device.firmware, device.serial, device.mac,
                                                     *(raw.get(name, "") for name in extra_columns)])
                        self.count.set_text(f"Экспортировано устройств: {len(keys)}")
                    except OSError as exc:
                        self.show_result(f"Не удалось сохранить CSV: {exc}", error=True)
            dialog.destroy()
        dialog.connect("response", response)
        dialog.show()

    def open_batch_activation(self) -> None:
        devices = [self.devices[key] for key in self.checked_devices if key in self.devices]
        if not devices:
            return
        def submit(values):
            password = values["Новый пароль"]
            if not self._valid_password(password):
                return False
            if password != values["Повторите пароль"]:
                self.show_result("Пароли не совпадают.", error=True)
                return False
            state = {"done": 0, "failed": []}
            def activate_many():
                for device in devices:
                    if device.activated is True:
                        continue
                    try:
                        activate_device(device.ip, device.http_port, password, device.device_port)
                        device.activated = True
                        device.status = "Активировано"
                        state["done"] += 1
                    except HikvisionError as exc:
                        state["failed"].append(f"{device.ip}: {exc}")
                return None
            def complete():
                self.render_devices()
                summary = f"Активировано: {state['done']}. Ошибок: {len(state['failed'])}."
                if state["failed"]:
                    summary += "\n" + "\n".join(state["failed"][:8])
                self.show_result(summary, error=bool(state["failed"]))
            self.start_operation(f"Активируем выбранные устройства: {len(devices)}…", activate_many, complete)
            return True
        self._operation_dialog("Пакетная активация", [("Новый пароль", True), ("Повторите пароль", True)],
                               "Активировать", submit)

    def open_batch_network(self) -> None:
        devices = [self.devices[key] for key in self.checked_devices if key in self.devices]
        if not devices:
            return
        dialog = Gtk.Dialog(title="Пакетная настройка IPv4", transient_for=self, modal=True)
        dialog.add_button("Отмена", Gtk.ResponseType.CANCEL)
        dialog.add_button("Применить", Gtk.ResponseType.ACCEPT).add_css_class("destructive-action")
        box = dialog.get_content_area()
        box.set_spacing(9); box.set_margin_top(18); box.set_margin_bottom(18)
        box.set_margin_start(20); box.set_margin_end(20)
        box.append(Gtk.Label(label=f"Будет изменено устройств: {len(devices)}. IP задаются подряд, начиная с указанного.",
                             xalign=0, wrap=True))
        dhcp = Gtk.CheckButton(label="Включить DHCP для всех выбранных устройств")
        box.append(dhcp)
        fields = {}
        for label in ("Начальный IPv4", "Маска подсети", "Шлюз", "Основной DNS", "Дополнительный DNS",
                      "Пароль администратора"):
            box.append(Gtk.Label(label=label, xalign=0))
            secret = label == "Пароль администратора"
            entry = Gtk.PasswordEntry() if secret else Gtk.Entry()
            if secret:
                entry.set_show_peek_icon(True)
            entry.set_hexpand(True)
            box.append(entry)
            fields[label] = entry
        def set_editable(*_args):
            for key in ("Начальный IPv4", "Маска подсети", "Шлюз", "Основной DNS", "Дополнительный DNS"):
                fields[key].set_sensitive(not dhcp.get_active())
        dhcp.connect("toggled", set_editable)
        set_editable()
        def response(_dialog, response_id):
            if response_id == Gtk.ResponseType.ACCEPT:
                values = {key: entry.get_text().strip() for key, entry in fields.items()}
                is_dhcp = dhcp.get_active()
                if not values["Пароль администратора"]:
                    self.show_result("Введите пароль администратора.", error=True)
                    return
                try:
                    start = ipaddress.IPv4Address(values["Начальный IPv4"]) if not is_dhcp else None
                    mask = values["Маска подсети"]
                    if not is_dhcp:
                        network = ipaddress.IPv4Network(f"{start}/{mask}", strict=False)
                        if values["Шлюз"]:
                            gateway = ipaddress.IPv4Address(values["Шлюз"])
                            if gateway not in network:
                                raise ValueError("шлюз должен быть в той же подсети")
                        proposed = [ipaddress.IPv4Address(int(start) + offset) for offset in range(len(devices))]
                        if any(ip not in network for ip in proposed):
                            raise ValueError("диапазон IP выходит за указанную подсеть")
                        if network.prefixlen < 31 and any(ip in (network.network_address, network.broadcast_address)
                                                         for ip in proposed):
                            raise ValueError("нельзя назначить адрес сети или broadcast-адрес")
                    if len(devices) > 1 and start and int(start) + len(devices) - 1 > 0xFFFFFFFF:
                        raise ValueError("Диапазон адресов выходит за пределы IPv4")
                except ValueError as exc:
                    self.show_result(f"Проверьте начальный адрес и маску: {exc}", error=True)
                    return
                state = {"done": 0, "failed": []}
                def configure_many():
                    for offset, device in enumerate(devices):
                        try:
                            interfaces = get_network_interfaces(device.ip, device.http_port, "admin",
                                                                values["Пароль администратора"])
                            target = next((item for item in interfaces if item["ip"] == device.ip), interfaces[0])
                            new_ip = str(ipaddress.IPv4Address(int(start) + offset)) if start else ""
                            set_ipv4(device.ip, device.http_port, "admin", values["Пароль администратора"],
                                     target["id"], new_ip, mask, values["Шлюз"], values["Основной DNS"],
                                     values["Дополнительный DNS"], is_dhcp)
                            state["done"] += 1
                        except (HikvisionError, ValueError) as exc:
                            state["failed"].append(f"{device.ip}: {exc}")
                    return None
                def complete():
                    message = f"Настроено устройств: {state['done']}. Ошибок: {len(state['failed'])}. Найдите устройства заново."
                    if state["failed"]:
                        message += "\n" + "\n".join(state["failed"][:8])
                    self.show_result(message, error=bool(state["failed"]))
                self.start_operation(f"Настраиваем сеть на {len(devices)} устройствах…", configure_many, complete)
            dialog.destroy()
        dialog.connect("response", response)
        dialog.present()

    def on_selected(self, _box: Gtk.ListBox, row: Gtk.ListBoxRow | None) -> None:
        self.selected = self.devices.get(row.device_key) if row else None
        self.show_details(self.selected)

    def show_details(self, device: Device | None) -> None:
        while child := self.details.get_first_child():
            self.details.remove(child)
        while child := self.actions.get_first_child():
            self.actions.remove(child)
        if not device:
            self.detail_title.set_text("Выберите устройство")
            return
        self.detail_title.set_text(device.model or "Устройство Hikvision")
        items = [("IPv4", device.ip), ("Маска IPv4", device.subnet_mask),
                 ("Шлюз IPv4", device.gateway), ("IPv6", device.ipv6),
                 ("Шлюз IPv6", device.ipv6_gateway), ("MAC", device.mac),
                 ("Серийный номер", device.serial),
                 ("Порт устройства", str(device.device_port)), ("HTTP порт", str(device.http_port)),
                 ("RTSP порт", str(device.rtsp_port)),
                 ("Порт Enhanced SDK", str(device.enhanced_sdk_port) if device.enhanced_sdk_port else ""),
                 ("Прошивка", device.firmware), ("Статус", device.status)]
        for i, (label, value) in enumerate(items):
            key = Gtk.Label(label=label); key.add_css_class("dim-label"); key.set_halign(Gtk.Align.START)
            val = Gtk.Label(label=value or "—"); val.set_selectable(True); val.set_halign(Gtk.Align.START)
            self.details.attach(key, 0, i, 1, 1); self.details.attach(val, 1, i, 1, 1)
        live_view = Gtk.Button(label="Открыть видео в реальном времени…")
        live_view.set_halign(Gtk.Align.START)
        live_view.connect("clicked", lambda _button, item=device: self.open_live_view(item))
        self.actions.append(live_view)
        if device.activated is not True:
            activate = Gtk.Button(label="Активировать устройство…")
            activate.set_halign(Gtk.Align.START)
            activate.connect("clicked", lambda _button, item=device: self.open_activation(item))
            self.actions.append(activate)
        recover = Gtk.Button(label="Настроить email восстановления…")
        recover.set_halign(Gtk.Align.START)
        recover.connect("clicked", lambda _button, item=device: self.open_recovery_email(item))
        self.actions.append(recover)
        questions = Gtk.Button(label="Настроить контрольные вопросы…")
        questions.set_halign(Gtk.Align.START)
        questions.connect("clicked", lambda _button, item=device: self.open_security_questions(item))
        self.actions.append(questions)
        guid = Gtk.Button(label="Экспортировать GUID для восстановления…")
        guid.set_halign(Gtk.Align.START)
        guid.connect("clicked", lambda _button, item=device: self.open_guid_export(item))
        self.actions.append(guid)
        network = Gtk.Button(label="Изменить IP-адрес…")
        network.set_halign(Gtk.Align.START)
        network.connect("clicked", lambda _button, item=device: self.open_network_settings(item))
        self.actions.append(network)
        ports = Gtk.Button(label="Изменить сетевые порты…")
        ports.set_halign(Gtk.Align.START)
        ports.connect("clicked", lambda _button, item=device: self.open_service_ports(item))
        self.actions.append(ports)
        unbind = Gtk.Button(label="Отвязать Hik-Connect…")
        unbind.set_halign(Gtk.Align.START)
        unbind.connect("clicked", lambda _button, item=device: self.open_hik_connect_unbind(item))
        self.actions.append(unbind)

    def open_live_view(self, device: Device) -> None:
        window = LiveViewWindow(self, device)
        self.live_view_windows.append(window)
        window.connect("close-request", self.remove_live_view_window)
        window.present()

    def remove_live_view_window(self, window: Gtk.Window) -> bool:
        if window in self.live_view_windows:
            self.live_view_windows.remove(window)
        return False

    def _operation_dialog(self, title: str, fields: list[tuple[str, bool]],
                          submit_label: str, callback) -> None:
        dialog = Gtk.Dialog(title=title, transient_for=self, modal=True)
        dialog.set_default_size(440, -1)
        dialog.add_button("Отмена", Gtk.ResponseType.CANCEL)
        submit = dialog.add_button(submit_label, Gtk.ResponseType.ACCEPT)
        submit.add_css_class("suggested-action")
        box = dialog.get_content_area()
        box.set_spacing(10); box.set_margin_top(18); box.set_margin_bottom(18)
        box.set_margin_start(20); box.set_margin_end(20)
        entries = {}
        for label, secret in fields:
            box.append(Gtk.Label(label=label, xalign=0))
            entry = Gtk.PasswordEntry() if secret else Gtk.Entry()
            if secret:
                entry.set_show_peek_icon(True)
            entry.set_hexpand(True)
            box.append(entry)
            entries[label] = entry
        def response(_dialog, response_id):
            if response_id == Gtk.ResponseType.ACCEPT:
                values = {key: value.get_text().strip() for key, value in entries.items()}
                if not callback(values):
                    return
            dialog.destroy()
        dialog.connect("response", response)
        dialog.present()

    def _valid_password(self, password: str) -> bool:
        if len(password) < 8:
            self.show_result("Пароль должен содержать не менее 8 символов.", error=True)
            return False
        return True

    def open_activation(self, device: Device) -> None:
        def submit(values):
            password = values["Новый пароль"]
            if not self._valid_password(password):
                return False
            if password != values["Повторите пароль"]:
                self.show_result("Пароли не совпадают.", error=True)
                return False
            self.start_operation("Активируем устройство…",
                                 lambda: activate_device(device.ip, device.http_port, password,
                                                         device.device_port),
                                 on_success=lambda: self.activation_finished(device))
            return True
        self._operation_dialog("Активация устройства", [("Новый пароль", True), ("Повторите пароль", True)],
                               "Активировать", submit)

    def open_recovery_email(self, device: Device) -> None:
        def submit(values):
            email = values["Резервный email"]
            password = values["Пароль администратора"]
            if "@" not in email or email.startswith("@") or email.endswith("@"):
                self.show_result("Введите корректный email для восстановления.", error=True)
                return False
            if not password:
                self.show_result("Введите пароль администратора устройства.", error=True)
                return False
            self.start_operation("Настраиваем email восстановления…",
                                 lambda: set_recovery_email(device.ip, device.http_port, "admin", password, email),
                                 on_success=lambda: self.recovery_finished())
            return True
        self._operation_dialog("Email восстановления", [("Резервный email", False),
                                                        ("Пароль администратора", True)],
                               "Сохранить", submit)

    def open_security_questions(self, device: Device) -> None:
        def submit(values):
            password = values["Пароль администратора"]
            if not password:
                self.show_result("Введите пароль администратора устройства.", error=True)
                return False
            state = {}
            self.start_operation("Читаем список контрольных вопросов…",
                                 lambda: state.setdefault("questions", get_security_questions(
                                     device.ip, device.http_port, "admin", password)),
                                 on_success=lambda: self.show_security_question_editor(
                                     device, password, state["questions"]))
            return True
        self._operation_dialog("Контрольные вопросы восстановления", [("Пароль администратора", True)],
                               "Продолжить", submit)

    def show_security_question_editor(self, device: Device, password: str,
                                      available: list[dict[str, str]]) -> None:
        ids = [item["id"] for item in available]
        if len(ids) < 3:
            self.show_result("Устройство вернуло меньше трёх доступных вопросов.", error=True)
            return
        dialog = Gtk.Dialog(title="Контрольные вопросы восстановления", transient_for=self, modal=True)
        dialog.set_default_size(480, -1)
        dialog.add_button("Отмена", Gtk.ResponseType.CANCEL)
        apply_button = dialog.add_button("Сохранить вопросы", Gtk.ResponseType.ACCEPT)
        apply_button.add_css_class("suggested-action")
        box = dialog.get_content_area()
        box.set_spacing(10); box.set_margin_top(18); box.set_margin_bottom(18)
        box.set_margin_start(20); box.set_margin_end(20)
        note = Gtk.Label(label="ISAPI устройства возвращает номера, но не формулировки вопросов. Сверьте номер с интерфейсом самого устройства.",
                         xalign=0, wrap=True)
        note.add_css_class("dim-label")
        box.append(note)
        inputs = []
        preselected = [item["id"] for item in available if item.get("mark") == "true"]
        for idx in range(3):
            box.append(Gtk.Label(label=f"Контрольный вопрос {idx + 1}", xalign=0))
            dropdown = Gtk.DropDown.new_from_strings([f"Вопрос №{qid}" for qid in ids])
            selected_id = preselected[idx] if idx < len(preselected) and preselected[idx] in ids else ids[min(idx, len(ids) - 1)]
            dropdown.set_selected(ids.index(selected_id))
            box.append(dropdown)
            answer = Gtk.PasswordEntry()
            answer.set_placeholder_text("Ответ")
            answer.set_show_peek_icon(True)
            box.append(answer)
            inputs.append((dropdown, answer))
        def response(_dialog, response_id):
            if response_id == Gtk.ResponseType.ACCEPT:
                chosen = [(ids[dropdown.get_selected()], answer.get_text().strip())
                          for dropdown, answer in inputs]
                if len({question_id for question_id, _ in chosen}) != 3:
                    self.show_result("Выберите три разных контрольных вопроса.", error=True)
                    return
                if any(not answer for _question_id, answer in chosen):
                    self.show_result("Введите ответ на каждый контрольный вопрос.", error=True)
                    return
                self.start_operation("Сохраняем контрольные вопросы…",
                                     lambda: set_security_questions(device.ip, device.http_port,
                                                                    "admin", password, chosen),
                                     on_success=lambda: self.show_result(
                                         "Контрольные вопросы сохранены на устройстве."))
            dialog.destroy()
        dialog.connect("response", response)
        dialog.present()

    def open_network_settings(self, device: Device) -> None:
        def submit(values):
            password = values["Пароль администратора"]
            if not password:
                self.show_result("Введите пароль администратора устройства.", error=True)
                return False
            state = {}
            self.start_operation("Читаем сетевые параметры…",
                                 lambda: state.setdefault("interfaces", get_network_interfaces(
                                     device.ip, device.http_port, "admin", password)),
                                 on_success=lambda: self.show_network_editor(device, password, state["interfaces"]))
            return True
        self._operation_dialog("Смена сетевых параметров", [("Пароль администратора", True)],
                               "Продолжить", submit)

    def open_service_ports(self, device: Device) -> None:
        def submit(values):
            password = values["Пароль администратора"]
            if not password:
                self.show_result("Введите пароль администратора устройства.", error=True)
                return False
            state = {}
            self.start_operation("Читаем список сетевых портов…",
                                 lambda: state.setdefault("ports", get_service_ports(
                                     device.ip, device.http_port, "admin", password)),
                                 on_success=lambda: self.show_service_ports_editor(
                                     device, password, state["ports"]))
            return True
        self._operation_dialog("Настройка сетевых портов", [("Пароль администратора", True)],
                               "Продолжить", submit)

    def show_service_ports_editor(self, device: Device, password: str,
                                  current_ports: dict[str, str]) -> None:
        names = {"HTTP": "HTTP", "HTTPS": "HTTPS", "RTSP": "RTSP",
                 "SDK": "SDK", "DEV_MANAGE": "SDK / Device Management",
                 "SDK_OVER_TLS": "SDK over TLS"}
        entries = {}
        dialog = Gtk.Dialog(title="Сетевые порты", transient_for=self, modal=True)
        dialog.set_default_size(470, -1)
        dialog.add_button("Отмена", Gtk.ResponseType.CANCEL)
        apply_button = dialog.add_button("Применить", Gtk.ResponseType.ACCEPT)
        apply_button.add_css_class("destructive-action")
        box = dialog.get_content_area()
        box.set_spacing(10); box.set_margin_top(18); box.set_margin_bottom(18)
        box.set_margin_start(20); box.set_margin_end(20)
        warning = Gtk.Label(label="Порты показаны по списку возможностей устройства. Изменение HTTP-порта оборвёт текущее соединение; после этого для подключения укажите новый порт.",
                            xalign=0, wrap=True)
        warning.add_css_class("warning")
        box.append(warning)
        grid = Gtk.Grid(column_spacing=14, row_spacing=10)
        box.append(grid)
        for row, (protocol, value) in enumerate(current_ports.items()):
            grid.attach(Gtk.Label(label=names.get(protocol, protocol), xalign=0), 0, row, 1, 1)
            entry = Gtk.Entry()
            entry.set_text(value)
            entry.set_input_purpose(Gtk.InputPurpose.DIGITS)
            entry.set_hexpand(True)
            grid.attach(entry, 1, row, 1, 1)
            entries[protocol] = entry

        def response(_dialog, response_id):
            if response_id == Gtk.ResponseType.ACCEPT:
                new_ports = {name: entry.get_text().strip() for name, entry in entries.items()}
                if any(not value for value in new_ports.values()):
                    self.show_result("Укажите порт для каждого отображённого протокола.", error=True)
                    return
                self.start_operation("Применяем сетевые порты…",
                                     lambda: set_service_ports(device.ip, device.http_port, "admin",
                                                               password, new_ports),
                                     on_success=lambda: self.show_result(
                                         "Порты обновлены. Если изменён HTTP-порт, найдите устройство заново и подключитесь по новому порту."))
            dialog.destroy()
        dialog.connect("response", response)
        dialog.present()

    def open_hik_connect_unbind(self, device: Device) -> None:
        def submit(values):
            password = values["Пароль администратора"]
            if not password:
                self.show_result("Введите пароль администратора устройства.", error=True)
                return False
            confirm = Gtk.MessageDialog(
                transient_for=self, modal=True, message_type=Gtk.MessageType.WARNING,
                buttons=Gtk.ButtonsType.YES_NO,
                text="Отвязать устройство от учётной записи Hik-Connect?"
            )
            confirm.set_secondary_text(
                "Операция может лишить текущую учётную запись доступа к устройству. "
                "Устройство и компьютер должны находиться в одной локальной сети."
            )
            def response(dialog, response_id):
                dialog.destroy()
                if response_id == Gtk.ResponseType.YES:
                    self.start_operation(
                        "Проверяем поддержку и отвязываем устройство…",
                        lambda: unbind_hik_connect(device.ip, device.http_port, "admin", password),
                        on_success=lambda: self.show_result(
                            "Запрос отвязки Hik-Connect принят устройством."
                        )
                    )
            confirm.connect("response", response)
            confirm.present()
            return True
        self._operation_dialog("Отвязка Hik-Connect", [("Пароль администратора", True)],
                               "Продолжить", submit)

    def open_guid_export(self, device: Device) -> None:
        def submit(values):
            password = values["Пароль администратора"]
            if not password:
                self.show_result("Введите пароль администратора устройства.", error=True)
                return False
            state = {}
            self.start_operation("Экспортируем GUID-файл…",
                                 lambda: state.setdefault("data", export_guid_file(
                                     device.ip, device.http_port, "admin", password)),
                                 on_success=lambda: self.save_guid_file(device, state["data"]))
            return True
        self._operation_dialog("Экспорт GUID-файла", [("Пароль администратора", True)],
                               "Экспортировать", submit)

    def open_nvr_sadp(self) -> None:
        def submit(values):
            address = values["IP регистратора"]
            username = values["Имя пользователя"] or "admin"
            password = values["Пароль регистратора"]
            try:
                port = int(values["SDK порт"] or "8000")
                ipaddress.IPv4Address(address)
                if not 1 <= port <= 65535:
                    raise ValueError("порт должен быть от 1 до 65535")
            except ValueError as exc:
                self.show_result(f"Проверьте адрес и порт регистратора: {exc}", error=True)
                return False
            if not username or not password:
                self.show_result("Введите имя пользователя и пароль регистратора.", error=True)
                return False
            state = {}
            self.start_operation("Получаем SADP-список камер с регистратора…",
                                 lambda: state.setdefault("devices", get_nvr_sadp_devices(
                                     address, port, username, password)),
                                 on_success=lambda: self.show_nvr_sadp_devices(
                                     address, port, username, password, state["devices"]))
            return True
        self._operation_dialog("Камеры за регистратором (HCNetSDK)",
                               [("IP регистратора", False), ("SDK порт", False),
                                ("Имя пользователя", False), ("Пароль регистратора", True)],
                               "Получить список", submit)

    def show_nvr_sadp_devices(self, address: str, port: int, username: str,
                              password: str, devices: list[dict[str, str]]) -> None:
        if not devices:
            self.show_result("Регистратор не вернул камеры через SADP API.", error=True)
            return
        dialog = Gtk.Dialog(title=f"Камеры за регистратором · {address}", transient_for=self, modal=True)
        dialog.set_default_size(760, 520)
        dialog.add_button("Закрыть", Gtk.ResponseType.CLOSE)
        content = dialog.get_content_area()
        content.set_spacing(10); content.set_margin_top(14); content.set_margin_bottom(14)
        content.set_margin_start(16); content.set_margin_end(16)
        content.append(Gtk.Label(label=f"Камер в SADP-списке регистратора: {len(devices)}", xalign=0))
        list_box = Gtk.ListBox()
        list_box.set_selection_mode(Gtk.SelectionMode.SINGLE)
        list_box.add_css_class("boxed-list")
        scroll = Gtk.ScrolledWindow(); scroll.set_child(list_box); scroll.set_vexpand(True)
        content.append(scroll)
        state = {"selected": None}
        for item in devices:
            row_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            row_box.set_margin_top(9); row_box.set_margin_bottom(9)
            row_box.set_margin_start(12); row_box.set_margin_end(12)
            title = Gtk.Label(label=item["model"] or "IP камера")
            title.set_halign(Gtk.Align.START); title.add_css_class("heading")
            subtitle = Gtk.Label(label=f"{item['ip']}  ·  {item['mac']}  ·  порт {item['port']}  ·  {item['serial'] or 'SN не указан'}")
            subtitle.set_halign(Gtk.Align.START); subtitle.add_css_class("dim-label")
            row_box.append(title); row_box.append(subtitle)
            row = Gtk.ListBoxRow(); row.set_child(row_box); row.camera_info = item
            list_box.append(row)
        def selected(_box, row):
            state["selected"] = row.camera_info if row else None
            edit.set_sensitive(state["selected"] is not None)
        list_box.connect("row-selected", selected)
        edit = Gtk.Button(label="Изменить IP / шлюз / DNS / SDK порт…")
        edit.set_sensitive(False)
        edit.set_halign(Gtk.Align.START)
        edit.connect("clicked", lambda *_: self.open_nvr_camera_network(
            address, port, username, password, state["selected"]))
        content.append(edit)
        dialog.connect("response", lambda window, _response: window.destroy())
        dialog.present()

    def open_nvr_camera_network(self, nvr_address: str, nvr_port: int, nvr_username: str,
                                nvr_password: str, camera: dict[str, str]) -> None:
        dialog = Gtk.Dialog(title=f"Сетевые параметры камеры · {camera['ip']}",
                            transient_for=self, modal=True)
        dialog.set_default_size(500, -1)
        dialog.add_button("Отмена", Gtk.ResponseType.CANCEL)
        apply_button = dialog.add_button("Изменить через NVR", Gtk.ResponseType.ACCEPT)
        apply_button.add_css_class("destructive-action")
        box = dialog.get_content_area()
        box.set_spacing(9); box.set_margin_top(16); box.set_margin_bottom(16)
        box.set_margin_start(18); box.set_margin_end(18)
        note = Gtk.Label(label="Нужен текущий пароль камеры для SADP-проверки. После смены IP связь регистратора с камерой может прерваться.",
                         xalign=0, wrap=True)
        note.add_css_class("warning")
        box.append(note)
        dhcp = Gtk.CheckButton(label="Включить DHCP для IPv4")
        dhcp.set_active(camera.get("dhcp") == "true")
        box.append(dhcp)
        fields = {}
        for key, label, secret in (("ip", "Новый IPv4 адрес", False), ("mask", "Маска подсети", False),
                                   ("gateway", "Шлюз", False), ("dns1", "Основной DNS", False),
                                   ("dns2", "Дополнительный DNS", False),
                                   ("port", "Порт устройства", False),
                                   ("camera_password", "Пароль камеры", True)):
            box.append(Gtk.Label(label=label, xalign=0))
            entry = Gtk.PasswordEntry() if secret else Gtk.Entry()
            if secret:
                entry.set_show_peek_icon(True)
            else:
                entry.set_text(camera.get(key, ""))
            entry.set_hexpand(True)
            box.append(entry)
            fields[key] = entry
        def set_editable(*_args):
            for key in ("ip", "mask", "gateway", "dns1", "dns2"):
                fields[key].set_sensitive(not dhcp.get_active())
        dhcp.connect("toggled", set_editable)
        set_editable()
        def response(_dialog, response_id):
            if response_id == Gtk.ResponseType.ACCEPT:
                values = {key: entry.get_text().strip() for key, entry in fields.items()}
                is_dhcp = dhcp.get_active()
                if not values["camera_password"]:
                    self.show_result("Введите текущий пароль камеры.", error=True)
                    return
                try:
                    new_port = int(values["port"])
                    if not 1 <= new_port <= 65535:
                        raise ValueError("порт должен быть от 1 до 65535")
                    if not is_dhcp:
                        subnet = ipaddress.IPv4Network(f"{values['ip']}/{values['mask']}", strict=False)
                        if values["gateway"] and ipaddress.IPv4Address(values["gateway"]) not in subnet:
                            raise ValueError("шлюз должен находиться в той же подсети")
                except ValueError as exc:
                    self.show_result(f"Проверьте сетевые параметры: {exc}", error=True)
                    return
                self.start_operation(f"Изменяем параметры камеры {camera['mac']} через NVR…",
                                     lambda: modify_nvr_camera_ip(
                                         nvr_address, nvr_port, nvr_username, nvr_password,
                                         camera["mac"], values["camera_password"], values["ip"],
                                         values["mask"], values["gateway"], values["dns1"],
                                         values["dns2"], is_dhcp, new_port),
                                     on_success=lambda: self.show_result(
                                         "Регистратор принял изменения. Обновите SADP-список; камера может появиться по новому адресу."))
            dialog.destroy()
        dialog.connect("response", response)
        dialog.present()

    def save_guid_file(self, device: Device, data: bytes) -> None:
        dialog = Gtk.FileChooserNative.new("Сохранить GUID-файл восстановления", self,
                                          Gtk.FileChooserAction.SAVE, "Сохранить", "Отмена")
        safe_serial = "".join(ch for ch in device.serial if ch.isalnum() or ch in "-_")
        dialog.set_current_name(f"{safe_serial or device.ip}-recovery.guid")
        def response(chooser, response_id):
            if response_id == Gtk.ResponseType.ACCEPT:
                file = chooser.get_file()
                path = file.get_path() if file else None
                if path:
                    try:
                        with open(path, "wb") as output:
                            output.write(data)
                        self.show_result("GUID-файл сохранён. Храните его в защищённом месте: он может помочь восстановить пароль устройства.")
                    except OSError as exc:
                        self.show_result(f"Не удалось сохранить GUID-файл: {exc}", error=True)
            dialog.destroy()
        dialog.connect("response", response)
        dialog.show()

    def show_network_editor(self, device: Device, password: str, interfaces: list[dict[str, str]]) -> None:
        dialog = Gtk.Dialog(title="Сетевые параметры IPv4/IPv6", transient_for=self, modal=True)
        dialog.set_default_size(500, -1)
        dialog.add_button("Отмена", Gtk.ResponseType.CANCEL)
        apply_button = dialog.add_button("Применить IP", Gtk.ResponseType.ACCEPT)
        apply_button.add_css_class("destructive-action")
        box = dialog.get_content_area()
        box.set_spacing(10); box.set_margin_top(18); box.set_margin_bottom(18)
        box.set_margin_start(20); box.set_margin_end(20)
        warning = Gtk.Label(label="После применения текущее соединение оборвётся. Найдите устройство заново по SADP.",
                            xalign=0, wrap=True)
        warning.add_css_class("warning")
        box.append(warning)
        box.append(Gtk.Label(label="Сетевой интерфейс", xalign=0))
        dropdown = Gtk.DropDown.new_from_strings(
            [f"Интерфейс {item['id']}  ·  {item['ip'] or 'IP не назначен'}" for item in interfaces])
        box.append(dropdown)
        dhcp = Gtk.CheckButton(label="Получать IP-адрес автоматически (DHCP)")
        box.append(dhcp)
        grid = Gtk.Grid(column_spacing=14, row_spacing=10)
        box.append(grid)
        fields = {}
        for row, (key, label) in enumerate((("ip", "IPv4 адрес"), ("mask", "Маска подсети"),
                                            ("gateway", "Шлюз IPv4"), ("dns1", "Основной DNS IPv4"),
                                            ("dns2", "Дополнительный DNS IPv4"),
                                            ("ipv6", "IPv6 адрес (необязательно)"),
                                            ("ipv6_prefix", "Префикс IPv6"),
                                            ("ipv6_gateway", "Шлюз IPv6"))):
            grid.attach(Gtk.Label(label=label, xalign=0), 0, row, 1, 1)
            entry = Gtk.Entry()
            entry.set_hexpand(True)
            grid.attach(entry, 1, row, 1, 1)
            fields[key] = entry

        def load_interface(*_args):
            idx = min(dropdown.get_selected(), len(interfaces) - 1)
            current = interfaces[idx]
            for key, entry in fields.items():
                entry.set_text(current.get(key, ""))
            dhcp.set_active(current.get("dhcp") == "true")
        def set_editable(*_args):
            editable = not dhcp.get_active()
            for key in ("ip", "mask", "gateway", "dns1", "dns2"):
                fields[key].set_sensitive(editable)
        dropdown.connect("notify::selected", load_interface)
        dhcp.connect("toggled", set_editable)
        load_interface()
        set_editable()

        def response(_dialog, response_id):
            if response_id == Gtk.ResponseType.ACCEPT:
                idx = min(dropdown.get_selected(), len(interfaces) - 1)
                selected = interfaces[idx]
                values = {key: entry.get_text().strip() for key, entry in fields.items()}
                is_dhcp = dhcp.get_active()
                if not is_dhcp and (not values["ip"] or not values["mask"]):
                    self.show_result("Для статического адреса укажите IPv4 и маску подсети.", error=True)
                    return
                self.start_operation("Применяем настройки…",
                                     lambda: set_ipv4(device.ip, device.http_port, "admin", password,
                                                      selected["id"], values["ip"], values["mask"],
                                                      values["gateway"], values["dns1"], values["dns2"], is_dhcp,
                                                      values["ipv6"], values["ipv6_prefix"],
                                                      values["ipv6_gateway"]),
                                     on_success=lambda: self.network_change_finished(
                                         device, values["ip"] if not is_dhcp else "DHCP"))
            dialog.destroy()
        dialog.connect("response", response)
        dialog.present()

    def network_change_finished(self, device: Device, new_ip: str) -> None:
        self.count.set_text("IP изменён — устройство нужно найти заново")
        self.show_result(f"Настройки отправлены. Новый адрес: {new_ip}. Найдите устройство заново, чтобы подключиться к нему.")

    def start_operation(self, busy_text: str, operation, on_success) -> None:
        self.count.set_text(busy_text)
        def worker():
            try:
                operation()
                GLib.idle_add(self.operation_finished, None, on_success)
            except (HikvisionError, OSError, ValueError) as exc:
                GLib.idle_add(self.operation_finished, str(exc), None)
        threading.Thread(target=worker, daemon=True).start()

    def operation_finished(self, error: str | None, on_success) -> bool:
        if error:
            self.count.set_text("Операция завершилась с ошибкой")
            self.show_result(error, error=True)
        else:
            self.count.set_text("Операция выполнена")
            on_success()
        return False

    def activation_finished(self, device: Device) -> None:
        device.activated = True
        device.status = "Активировано"
        self.show_result("Устройство активировано. Теперь можно настроить email восстановления.")
        self.show_details(device)

    def recovery_finished(self) -> None:
        self.show_result("Email сохранён. Устройство может запросить подтверждение адреса через QR-код согласно своей прошивке.")

    def show_result(self, message: str, error: bool = False) -> None:
        dialog = Gtk.MessageDialog(transient_for=self, modal=True,
                                   message_type=Gtk.MessageType.ERROR if error else Gtk.MessageType.INFO,
                                   buttons=Gtk.ButtonsType.OK, text=message)
        dialog.connect("response", lambda window, _response: window.destroy())
        dialog.present()


class LiveViewWindow(Gtk.Window):
    """RTSP live view using GStreamer; credentials stay out of the stream URL."""

    def __init__(self, parent: Gtk.Window, device: Device):
        super().__init__(title=f"Видео · {device.ip}", transient_for=parent)
        self.set_default_size(960, 680)
        self.device = device
        self.pipeline = None
        self.bus = None
        self.bus_handler = 0
        self._frame_lock = threading.Lock()
        self._pending_frame = None
        self._frame_dispatch_scheduled = False

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        root.set_margin_top(14); root.set_margin_bottom(14)
        root.set_margin_start(14); root.set_margin_end(14)
        self.set_child(root)

        controls = Gtk.Grid(column_spacing=12, row_spacing=8)
        root.append(controls)
        controls.attach(Gtk.Label(label=f"Камера: {device.model or 'Hikvision'} · {device.ip}",
                                  xalign=0), 0, 0, 2, 1)
        controls.attach(Gtk.Label(label="Логин", xalign=0), 0, 1, 1, 1)
        self.username = Gtk.Entry()
        self.username.set_text("admin")
        self.username.set_hexpand(True)
        controls.attach(self.username, 1, 1, 1, 1)
        controls.attach(Gtk.Label(label="Пароль", xalign=0), 0, 2, 1, 1)
        self.password = Gtk.PasswordEntry()
        self.password.set_show_peek_icon(True)
        controls.attach(self.password, 1, 2, 1, 1)
        controls.attach(Gtk.Label(label="RTSP порт", xalign=0), 0, 3, 1, 1)
        self.port = Gtk.Entry()
        self.port.set_text(str(device.rtsp_port or 554))
        self.port.set_input_purpose(Gtk.InputPurpose.DIGITS)
        controls.attach(self.port, 1, 3, 1, 1)
        controls.attach(Gtk.Label(label="Качество", xalign=0), 0, 4, 1, 1)
        self.stream = Gtk.DropDown.new_from_strings(["Основной поток", "Дополнительный поток"])
        controls.attach(self.stream, 1, 4, 1, 1)

        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.connect_button = Gtk.Button(label="Подключиться")
        self.connect_button.add_css_class("suggested-action")
        self.connect_button.connect("clicked", self.connect_stream)
        actions.append(self.connect_button)
        self.stop_button = Gtk.Button(label="Остановить")
        self.stop_button.set_sensitive(False)
        self.stop_button.connect("clicked", lambda *_: self.stop_stream())
        actions.append(self.stop_button)
        self.status = Gtk.Label(label="Введите учётные данные камеры", xalign=0)
        self.status.add_css_class("dim-label")
        self.status.set_hexpand(True)
        actions.append(self.status)
        root.append(actions)

        self.picture = Gtk.Picture()
        self.picture.set_content_fit(Gtk.ContentFit.CONTAIN)
        self.picture.set_hexpand(True); self.picture.set_vexpand(True)
        root.append(self.picture)
        self.connect("close-request", self.on_close_request)

        if Gst is None:
            self.connect_button.set_sensitive(False)
            self.status.set_text("Для live view установите GStreamer и python3-gst-1.0.")

    def connect_stream(self, _button) -> None:
        if Gst is None:
            return
        username = self.username.get_text().strip()
        password = self.password.get_text()
        try:
            port = int(self.port.get_text().strip())
            if not 1 <= port <= 65535:
                raise ValueError("порт должен быть от 1 до 65535")
        except ValueError as exc:
            self.status.set_text(f"Проверьте RTSP порт: {exc}")
            return
        if not username or not password:
            self.status.set_text("Введите логин и пароль камеры")
            return

        self.stop_stream(clear_picture=False)
        playbin = Gst.ElementFactory.make("playbin", "hikvision-live-view")
        video_sink = Gst.ElementFactory.make("appsink", "gtk-video-frames")
        audio_sink = Gst.ElementFactory.make("fakesink", "discard-audio")
        if not playbin or not video_sink or not audio_sink:
            self.status.set_text("Не найдены GStreamer playbin/appsink плагины.")
            return

        video_sink.set_property("caps", Gst.Caps.from_string("video/x-raw,format=RGB,framerate=15/1"))
        video_sink.set_property("emit-signals", True)
        video_sink.set_property("sync", False)
        video_sink.set_property("max-buffers", 1)
        video_sink.set_property("drop", True)
        video_sink.connect("new-sample", self.on_new_sample)
        playbin.set_property("video-sink", video_sink)
        playbin.set_property("audio-sink", audio_sink)
        playbin.connect("source-setup", self.configure_rtsp_source, username, password)
        channel = 101 if self.stream.get_selected() == 0 else 102
        playbin.set_property("uri", f"rtsp://{self.device.ip}:{port}/Streaming/Channels/{channel}")

        self.pipeline = playbin
        self.bus = playbin.get_bus()
        self.bus.add_signal_watch()
        self.bus_handler = self.bus.connect("message", self.on_bus_message)
        self.status.set_text(f"Подключаемся к потоку {channel}…")
        self.connect_button.set_sensitive(False)
        self.stop_button.set_sensitive(True)
        result = playbin.set_state(Gst.State.PLAYING)
        if result == Gst.StateChangeReturn.FAILURE:
            self.status.set_text("GStreamer не смог запустить поток.")
            self.stop_stream(clear_picture=False)

    @staticmethod
    def configure_rtsp_source(_playbin, source, username: str, password: str) -> None:
        # RTSP credentials are properties on rtspsrc, never embedded in the URI.
        for name, value in (("user-id", username), ("user-pw", password),
                            ("protocols", 4), ("latency", 200)):
            if source.find_property(name) is not None:
                source.set_property(name, value)

    def on_new_sample(self, sink):
        sample = sink.emit("pull-sample")
        if sample is None:
            return Gst.FlowReturn.ERROR
        structure = sample.get_caps().get_structure(0)
        width = structure.get_value("width")
        height = structure.get_value("height")
        buffer = sample.get_buffer()
        mapped_ok, mapped = buffer.map(Gst.MapFlags.READ)
        if not mapped_ok or not height:
            return Gst.FlowReturn.ERROR
        try:
            pixels = bytes(mapped.data)
        finally:
            buffer.unmap(mapped)
        if len(pixels) % height:
            return Gst.FlowReturn.ERROR
        stride = len(pixels) // height
        if stride < width * 3:
            return Gst.FlowReturn.ERROR
        frame = (width, height, stride, pixels)
        with self._frame_lock:
            self._pending_frame = frame
            if not self._frame_dispatch_scheduled:
                self._frame_dispatch_scheduled = True
                GLib.idle_add(self.display_latest_frame)
        return Gst.FlowReturn.OK

    def display_latest_frame(self) -> bool:
        with self._frame_lock:
            frame = self._pending_frame
            self._pending_frame = None
            self._frame_dispatch_scheduled = False
        if frame:
            width, height, stride, pixels = frame
            texture = Gdk.MemoryTexture.new(width, height, Gdk.MemoryFormat.R8G8B8,
                                            GLib.Bytes.new(pixels), stride)
            self.picture.set_paintable(texture)
            self.status.set_text(f"В эфире · {width}×{height}")
        return GLib.SOURCE_REMOVE

    def on_bus_message(self, _bus, message) -> None:
        if message.type == Gst.MessageType.ERROR:
            error, _debug = message.parse_error()
            self.status.set_text(f"Ошибка RTSP: {error.message}")
            self.stop_stream(clear_picture=False)
        elif message.type == Gst.MessageType.EOS:
            self.status.set_text("Поток завершился")
            self.stop_stream(clear_picture=False)

    def stop_stream(self, clear_picture: bool = True) -> None:
        if self.pipeline is not None:
            self.pipeline.set_state(Gst.State.NULL)
        if self.bus is not None:
            if self.bus_handler:
                self.bus.disconnect(self.bus_handler)
                self.bus_handler = 0
            self.bus.remove_signal_watch()
        self.pipeline = None
        self.bus = None
        self.connect_button.set_sensitive(Gst is not None)
        self.stop_button.set_sensitive(False)
        if clear_picture:
            self.picture.set_paintable(None)
            self.status.set_text("Просмотр остановлен")
        with self._frame_lock:
            self._pending_frame = None

    def on_close_request(self, _window) -> bool:
        self.stop_stream()
        return False


class SadpApp(Gtk.Application):
    def __init__(self):
        super().__init__(application_id="io.codex.hikvision.sadp")

    def do_activate(self) -> None:
        window = self.props.active_window
        if not window:
            window = SadpWindow(self)
        window.present()


if __name__ == "__main__":
    raise SystemExit(SadpApp().run())
