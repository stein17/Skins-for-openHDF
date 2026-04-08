# Components/Converter/GradientVPNInfo.py
# Python 3 only
# Concept and design by stein17, with the assistance of Python Code Generator
# Please do not remove these lines; kindly request my permission before sharing or publishing.

# ============================================================================
# README / Hinweis
# ----------------------------------------------------------------------------
# Dieser Converter erkennt:
#   - Netzwerk aktiv / nicht aktiv
#   - Verbindungstyp (LAN / WLAN / net_off)
#   - VPN aktiv / nicht aktiv
#   - VPN-Protokoll (wireguard / openvpn / none)
#   - VPN-Interface (z. B. wg0 / tun0)
#   - Public-IP / Country / Provider
#
# Wichtiger Fix in dieser Version:
#   Frühere Varianten konnten bei mehreren Converter-Instanzen oder häufigem
#   Polling zu viele Threads starten. Das konnte zu folgendem Crash führen:
#
#       RuntimeError: can't start new thread
#
#   Diese Version verhindert das so:
#   - nur noch EIN gemeinsamer Public-IP-Fetch für alle Instanzen
#   - gemeinsamer Cache auf Klassenebene
#   - Lock gegen Race Conditions
#   - defensiver Schutz beim Thread-Start
#   - Backoff bei Offline-/Fehlerfällen
#
# Dadurch:
#   - kein Thread-Spam mehr
#   - kein Crash durch zu viele Fetch-Threads
#   - GUI bleibt weiterhin frei / nicht blockierend
#
# Falls man später wieder etwas ändert:
#   - poll() darf niemals unkontrolliert neue Threads starten
#   - immer prüfen, ob bereits ein Fetch läuft
#   - RuntimeError beim Threadstart immer defensiv abfangen
#
# Debug:
#   DEBUG = True
#   Log-Datei:
#       /tmp/vpninfo.log
# ============================================================================
#
# Unterstützte Converter-Keys:
#
#   VpnActive         -> True / False
#   NetActive         -> net_on / net_off
#   ConnType          -> lan / wlan / modem / net_off
#   VpnProto          -> wireguard / openvpn / none
#   VpnIface          -> z. B. wg0 / tun0
#   CountryCode       -> DE / US / TR
#   CountryName       -> Deutschland / United States / ...
#   CountryLabel      -> DE – Deutschland
#   IP                -> öffentliche IP
#   PublicIP          -> öffentliche IP
#   ReceiverIP        -> lokale Box-IP
#   VpnProvider       -> z. B. mullvad / nordvpn / ovpn
#   VpnProviderPretty -> z. B. Mullvad VPN / NordVPN / OVPN
#
# Hinweise:
#   - WireGuard wird über Interfaces wie wg0 erkannt
#   - OpenVPN / OVPN über tun*, tap*, vpn*, ovpn*
#   - Split-Tunneling wird berücksichtigt
#   - Public-IP / Geo-Daten werden asynchron geholt
#   - Cache-Datei:
#       /tmp/vpninfo_cache.json
#

from Components.Converter.Converter import Converter
from Components.Converter.Poll import Poll
from Components.Element import cached

import time
import json
import socket
import subprocess
import threading
import os
import re

DEBUG = False


def _log(msg):
    if DEBUG:
        try:
            with open('/tmp/vpninfo.log', 'a') as f:
                f.write('%s %s\n' % (time.strftime('%Y-%m-%d %H:%M:%S'), msg))
        except Exception:
            pass


CACHE_PATH = '/tmp/vpninfo_cache.json'

VPN_PROVIDER_KEYS = {
    'mullvad': 'mullvad',
    'nordvpn': 'nordvpn',
    'nord lynx': 'nordvpn',
    'nordlynx': 'nordvpn',
    'protonvpn': 'protonvpn',
    'proton': 'protonvpn',
    'expressvpn': 'expressvpn',
    'surfshark': 'surfshark',
    'ipvanish': 'ipvanish',
    'cyberghost': 'cyberghost',
    'ovpn': 'ovpn',
    'ovpn.com': 'ovpn',
    'ofn': 'ovpn',
    'ofn101': 'ovpn',
    'private internet access': 'private internet access',
    'pia': 'private internet access',
    'airvpn': 'airvpn',
    'ivpn': 'ivpn',
    'vyprvpn': 'vyprvpn',
    'windscribe': 'windscribe',
    'perfect privacy': 'perfect privacy',
    'azire': 'azirevpn',
    'hide.me': 'hide.me',
    'hidemyass': 'hidemyass',
    'ip vanish': 'ipvanish',
    'tunnelbear': 'tunnelbear',
    'mozilla vpn': 'mozilla vpn',
    'cryptostorm': 'cryptostorm',
    'wevpn': 'wevpn',
    'privatevpn': 'privatevpn',
}

PROVIDER_DOMAIN_KEYS = {
    'nordvpn.com': 'nordvpn',
    'mullvad.net': 'mullvad',
    'ovpn.com': 'ovpn',
    'surfshark.com': 'surfshark',
    'protonvpn.com': 'protonvpn',
    'expressvpn.com': 'expressvpn',
    'ipvanish.com': 'ipvanish',
    'cyberghostvpn.com': 'cyberghost',
    'privateinternetaccess.com': 'private internet access',
    'airvpn.org': 'airvpn',
    'ivpn.net': 'ivpn',
    'vyprvpn.com': 'vyprvpn',
    'windscribe.com': 'windscribe',
    'perfect-privacy.com': 'perfect privacy',
    'azirevpn.com': 'azirevpn',
    'hide.me': 'hide.me',
    'hidemyass.com': 'hidemyass',
    'tunnelbear.com': 'tunnelbear',
    'mozilla.org': 'mozilla vpn',
    'cryptostorm.is': 'cryptostorm',
    'wevpn.com': 'wevpn',
    'privatevpn.com': 'privatevpn',
    'nordlynx': 'nordvpn',
}

PROVIDER_PRETTY = {
    'mullvad': 'Mullvad VPN',
    'nordvpn': 'NordVPN',
    'protonvpn': 'ProtonVPN',
    'expressvpn': 'ExpressVPN',
    'surfshark': 'Surfshark VPN',
    'ipvanish': 'IPVanish VPN',
    'cyberghost': 'CyberGhost VPN',
    'ovpn': 'OVPN',
    'private internet access': 'Private Internet Access',
    'airvpn': 'AirVPN',
    'ivpn': 'IVPN',
    'vyprvpn': 'VyprVPN',
    'windscribe': 'Windscribe VPN',
    'perfect privacy': 'Perfect Privacy',
    'azirevpn': 'AzireVPN',
    'hide.me': 'hide.me',
    'hidemyass': 'HideMyAss',
    'tunnelbear': 'TunnelBear',
    'mozilla vpn': 'Mozilla VPN',
    'cryptostorm': 'Cryptostorm',
    'wevpn': 'WeVPN',
    'privatevpn': 'PrivateVPN',
}

GERMAN_NAMES = {
    'DE': 'Deutschland',
    'AT': 'Österreich',
    'CH': 'Schweiz',
}


def _run(cmd):
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        return out.decode('utf-8', 'ignore')
    except Exception:
        return ''


def _default_iface():
    out = _run("ip -4 route show default 2>/dev/null | head -n1") or _run("ip route show 0.0.0.0/0 2>/dev/null | head -n1")
    if out:
        parts = out.split()
        if 'dev' in parts:
            try:
                return parts[parts.index('dev') + 1]
            except Exception:
                pass
    try:
        with open('/proc/net/route', 'r') as f:
            for line in f:
                sp = line.split()
                if len(sp) >= 4:
                    iface = sp[0]
                    dest = sp[1]
                    try:
                        flags = int(sp[3], 16)
                    except Exception:
                        flags = 0
                    if dest == '00000000' and (flags & 0x2):
                        return iface
    except Exception:
        pass
    return None


def _iface_online(iface):
    if not iface:
        return False
    try:
        s = open('/sys/class/net/%s/operstate' % iface, 'r').read().strip()
        if s not in ('up', 'unknown'):
            return False
    except Exception:
        pass
    try:
        c = open('/sys/class/net/%s/carrier' % iface, 'r').read().strip()
        if c != '1':
            return False
    except Exception:
        pass
    return True


def _ip_for_iface(iface):
    try:
        out = _run('ip -4 addr show dev %s' % iface)
        for line in out.splitlines():
            line = line.strip()
            if line.startswith('inet '):
                return line.split()[1].split('/')[0]
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        pass
    return ''


def _conn_type_for_iface(iface):
    if not iface:
        return 'net_off'
    name = iface.lower()
    if name.startswith(('eth', 'en', 'br', 'lan')):
        return 'lan'
    if name.startswith(('wl', 'wlan', 'ra')):
        return 'wlan'
    if name.startswith(('ppp', 'wwan', 'usb', 'rmnet')):
        return 'modem'
    return 'lan'


def _list_up_ifaces(prefixes):
    up = []
    try:
        for name in os.listdir('/sys/class/net'):
            low = name.lower()
            if any(low.startswith(p) for p in prefixes):
                try:
                    st = open('/sys/class/net/%s/operstate' % name, 'r').read().strip()
                except Exception:
                    st = ''
                if st in ('up', 'unknown'):
                    up.append(name)
    except Exception:
        pass
    return up


def _vpn_detect_by_interfaces():
    up_wg = _list_up_ifaces(('wg',))
    up_tun = _list_up_ifaces(('tun', 'tap', 'vpn', 'ovpn'))
    if up_wg:
        return True, 'wireguard', up_wg[0]
    if up_tun:
        return True, 'openvpn', up_tun[0]
    return False, 'none', ''


def _load_forced_proto():
    for p in ('/etc/enigma2/vpnproto', '/etc/vpnproto'):
        try:
            if os.path.exists(p):
                v = open(p, 'r').read().strip().lower()
                if v.startswith('wg'):
                    return 'wireguard'
                if v in ('openvpn', 'ovpn') or v.startswith('ovpn'):
                    return 'openvpn'
        except Exception:
            pass
    return ''


def _looks_like_vpn_provider(fields):
    text = ' '.join([
        fields.get('isp', '') or '',
        fields.get('org', '') or '',
        fields.get('asn', '') or '',
        fields.get('rdns', '') or '',
    ]).lower()

    for k, slug in VPN_PROVIDER_KEYS.items():
        if k in text:
            return slug
    return ''


def _scan_local_vpn_configs():
    paths = [
        '/etc/wireguard',
        '/etc/openvpn',
        '/etc/enigma2/wireguard',
        '/etc/enigma2/openvpn',
    ]
    found = ''
    for base in paths:
        if not os.path.isdir(base):
            continue
        try:
            for root, _, files in os.walk(base):
                for fn in files:
                    if not fn.lower().endswith(('.conf', '.ovpn', '.cfg', '.txt')):
                        continue
                    try:
                        data = open(os.path.join(root, fn), 'r', errors='ignore').read().lower()
                    except Exception:
                        continue
                    for m in re.findall(r'(?:(?:endpoint|remote)\s*=\s*|remote\s+)([^\s:]+)', data):
                        for key, slug in PROVIDER_DOMAIN_KEYS.items():
                            if key in m:
                                return slug
                    if '103.86.96.100' in data or '103.86.99.100' in data:
                        return 'nordvpn'
                    if 'nordlynx' in data:
                        return 'nordvpn'
        except Exception:
            pass
    return found


def _fetch_public_info(timeout=2.0):
    urls = [
        ('http://ip-api.com/json/?fields=status,message,query,country,countryCode,isp,org,as,reverse', 'ip-api'),
        ('http://ipinfo.io/json', 'ipinfo'),
        ('https://ipapi.co/json/', 'ipapi'),
    ]
    for u, tag in urls:
        try:
            import urllib.request
            raw = urllib.request.urlopen(u, timeout=timeout).read().decode('utf-8', 'ignore')
            js = json.loads(raw)
            if tag == 'ip-api':
                return {
                    'ip': js.get('query', ''),
                    'cc': (js.get('countryCode', '') or '').upper(),
                    'country': js.get('country', ''),
                    'isp': js.get('isp', ''),
                    'org': js.get('org', ''),
                    'asn': js.get('as', ''),
                    'rdns': js.get('reverse', ''),
                }
            elif tag == 'ipinfo':
                return {
                    'ip': js.get('ip', ''),
                    'cc': (js.get('country', '') or '').upper(),
                    'country': js.get('country', ''),
                    'isp': '',
                    'org': js.get('org', ''),
                    'asn': js.get('org', ''),
                    'rdns': js.get('hostname', ''),
                }
            else:
                return {
                    'ip': js.get('ip', ''),
                    'cc': (js.get('country_code', '') or js.get('country', '') or '').upper(),
                    'country': js.get('country_name', '') or js.get('country', ''),
                    'isp': js.get('org', ''),
                    'org': js.get('org', ''),
                    'asn': js.get('asn', ''),
                    'rdns': '',
                }
        except Exception:
            continue
    return {
        'ip': '',
        'cc': '',
        'country': '',
        'isp': '',
        'org': '',
        'asn': '',
        'rdns': '',
    }


class GradientVPNInfo(Poll, Converter):
    IP = 0
    CountryCode = 1
    CountryName = 2
    ReceiverIP = 3
    ConnType = 4
    VpnActive = 5
    CountryLabel = 6
    NetActive = 7
    VpnProto = 8
    VpnIface = 9
    VpnProvider = 10
    VpnProviderPretty = 11

    # Gemeinsamer Fetch-Status für ALLE Instanzen
    _shared_lock = threading.Lock()
    _shared_fetch_thread = None
    _shared_last_public_ip = ''
    _shared_last_country_code = ''
    _shared_last_country_name = ''
    _shared_prov_public = ''
    _shared_last_fetch_ts = 0
    _shared_last_fetch_vpn_state = None
    _shared_offline_backoff = 30
    _shared_offline_until = 0
    _shared_cache_loaded = False

    def __init__(self, type):
        Poll.__init__(self)
        Converter.__init__(self, type)

        self.type = {
            'IP': self.IP,
            'PublicIP': self.IP,
            'CountryCode': self.CountryCode,
            'CountryName': self.CountryName,
            'ReceiverIP': self.ReceiverIP,
            'ConnType': self.ConnType,
            'VpnActive': self.VpnActive,
            'CountryLabel': self.CountryLabel,
            'CountryText': self.CountryLabel,
            'NetActive': self.NetActive,
            'VpnProto': self.VpnProto,
            'VpnIface': self.VpnIface,
            'VpnProvider': self.VpnProvider,
            'VpnProviderPretty': self.VpnProviderPretty,
        }.get(type, type)

        self.poll_interval = 2000
        self.poll_enabled = True

        self._last_public_ip = ''
        self._last_country_code = ''
        self._last_country_name = ''
        self._last_receiver_ip = ''
        self._last_conn_type = 'net_off'
        self._last_vpn_active = False
        self._last_net_active = False
        self._last_vpn_proto = 'none'
        self._last_vpn_iface = ''

        self._prov_local = ''
        self._prov_public = ''

        self._last_iface = None
        self._last_local_ip_ts = 0
        self._last_fast_ts = 0
        self._min_fetch_interval = 60

        self._ensure_shared_cache_loaded()
        self._sync_from_shared()

    @classmethod
    def _load_cache_data(cls):
        try:
            if os.path.exists(CACHE_PATH):
                js = json.load(open(CACHE_PATH, 'r'))
                return {
                    'ip': js.get('ip', '') or '',
                    'cc': (js.get('cc', '') or '').upper(),
                    'country': js.get('country', '') or '',
                    'provider': js.get('provider', '') or '',
                }
        except Exception:
            pass
        return {
            'ip': '',
            'cc': '',
            'country': '',
            'provider': '',
        }

    @classmethod
    def _save_cache_data(cls):
        try:
            data = {
                'ip': cls._shared_last_public_ip,
                'cc': cls._shared_last_country_code,
                'country': cls._shared_last_country_name,
                'provider': cls._shared_prov_public,
            }
            with open(CACHE_PATH, 'w') as f:
                json.dump(data, f)
        except Exception:
            pass

    @classmethod
    def _ensure_shared_cache_loaded(cls):
        with cls._shared_lock:
            if cls._shared_cache_loaded:
                return
            data = cls._load_cache_data()
            cls._shared_last_public_ip = data.get('ip', '')
            cls._shared_last_country_code = data.get('cc', '')
            cls._shared_last_country_name = data.get('country', '')
            cls._shared_prov_public = data.get('provider', '')
            cls._shared_cache_loaded = True

    def _sync_from_shared(self):
        cls = self.__class__
        with cls._shared_lock:
            self._last_public_ip = cls._shared_last_public_ip
            self._last_country_code = cls._shared_last_country_code
            self._last_country_name = cls._shared_last_country_name
            self._prov_public = cls._shared_prov_public

    def _update_fast(self):
        now = time.time()

        if now - self._last_fast_ts < 1.5:
            self._sync_from_shared()
            return

        iface = _default_iface()
        iface_online = bool(iface and _iface_online(iface))
        self._last_iface = iface

        self._last_conn_type = _conn_type_for_iface(iface)

        if iface and (now - self._last_local_ip_ts > 60):
            self._last_receiver_ip = _ip_for_iface(iface)
            self._last_local_ip_ts = now

        vpn_on, vpn_proto, vpn_if = _vpn_detect_by_interfaces()
        self._last_vpn_active = vpn_on
        self._last_vpn_proto = vpn_proto
        self._last_vpn_iface = vpn_if

        self._prov_local = _scan_local_vpn_configs() or ''

        self._sync_from_shared()

        cls = self.__class__
        with cls._shared_lock:
            shared_offline_until = cls._shared_offline_until

        if self._last_public_ip:
            self._last_net_active = True
        elif now < shared_offline_until:
            self._last_net_active = False
        else:
            self._last_net_active = iface_online

        if not self._last_vpn_active and self._last_net_active and self._prov_public and not self._prov_local:
            self._last_vpn_active = True
            forced = _load_forced_proto()
            if forced:
                self._last_vpn_proto = forced

        self._last_fast_ts = now

    def _need_fetch_public(self):
        now = time.time()
        cls = self.__class__

        with cls._shared_lock:
            offline_until = cls._shared_offline_until
            last_fetch_ts = cls._shared_last_fetch_ts
            last_fetch_vpn_state = cls._shared_last_fetch_vpn_state
            fetch_thread = cls._shared_fetch_thread

        if now < offline_until:
            return False
        if not self._last_iface or not _iface_online(self._last_iface):
            return False
        if fetch_thread and fetch_thread.is_alive():
            return False
        if (now - last_fetch_ts) > self._min_fetch_interval:
            return True
        if self._last_vpn_active != last_fetch_vpn_state:
            return True
        return False

    @classmethod
    def _shared_fetch_worker(cls, current_vpn_state):
        try:
            info = _fetch_public_info(timeout=2.0)

            with cls._shared_lock:
                if info.get('ip'):
                    cc = (info.get('cc', '') or '').upper()
                    name = info.get('country', '') or ''
                    if cc in GERMAN_NAMES:
                        name = GERMAN_NAMES.get(cc, name)

                    provider = _looks_like_vpn_provider(info) or ''

                    cls._shared_last_public_ip = info.get('ip', '') or ''
                    cls._shared_last_country_code = cc
                    cls._shared_last_country_name = name
                    cls._shared_prov_public = provider
                    cls._shared_last_fetch_ts = time.time()
                    cls._shared_last_fetch_vpn_state = current_vpn_state
                    cls._shared_offline_backoff = 30
                    cls._shared_offline_until = 0
                    cls._save_cache_data()
                    _log('[GradientVPNInfo] shared fetch ok ip=%s cc=%s provider=%s' % (
                        cls._shared_last_public_ip,
                        cls._shared_last_country_code,
                        cls._shared_prov_public
                    ))
                else:
                    cls._shared_offline_until = time.time() + cls._shared_offline_backoff
                    cls._shared_offline_backoff = min(cls._shared_offline_backoff * 2, 600)
                    _log('[GradientVPNInfo] shared fetch failed backoff=%s' % cls._shared_offline_backoff)

        except Exception as e:
            with cls._shared_lock:
                cls._shared_offline_until = time.time() + cls._shared_offline_backoff
                cls._shared_offline_backoff = min(cls._shared_offline_backoff * 2, 600)
            _log('[GradientVPNInfo] shared worker exception: %s' % str(e))

        finally:
            with cls._shared_lock:
                cls._shared_fetch_thread = None

    def _start_fetch_thread(self):
        cls = self.__class__

        with cls._shared_lock:
            if cls._shared_fetch_thread and cls._shared_fetch_thread.is_alive():
                return

            try:
                t = threading.Thread(
                    target=cls._shared_fetch_worker,
                    args=(self._last_vpn_active,),
                    daemon=True
                )
                t.start()
                cls._shared_fetch_thread = t
                _log('[GradientVPNInfo] shared fetch thread started')
            except RuntimeError as e:
                # Crash-Schutz:
                # Niemals Enigma2 wegen Thread-Limit abstürzen lassen.
                cls._shared_fetch_thread = None
                cls._shared_offline_until = time.time() + 120
                cls._shared_offline_backoff = min(max(cls._shared_offline_backoff, 120), 600)
                _log('[GradientVPNInfo] thread start blocked: %s' % str(e))
            except Exception as e:
                cls._shared_fetch_thread = None
                cls._shared_offline_until = time.time() + 120
                cls._shared_offline_backoff = min(max(cls._shared_offline_backoff, 120), 600)
                _log('[GradientVPNInfo] unexpected start error: %s' % str(e))

    def poll(self):
        self._update_fast()

        if self._need_fetch_public():
            self._start_fetch_thread()

        self._sync_from_shared()

        if not self._last_vpn_active and self._last_net_active and self._prov_public and not self._prov_local:
            self._last_vpn_active = True
            forced = _load_forced_proto()
            if forced:
                self._last_vpn_proto = forced

        Converter.changed(self, (self.CHANGED_POLL,))

    @cached
    def getText(self):
        if self.type == self.IP:
            return self._last_public_ip or ''

        elif self.type == self.CountryCode:
            return self._last_country_code or ''

        elif self.type == self.CountryName:
            return self._last_country_name or ''

        elif self.type == self.ReceiverIP:
            return self._last_receiver_ip or ''

        elif self.type == self.ConnType:
            if not self._last_net_active:
                return 'net_off'
            return self._last_conn_type or 'lan'

        elif self.type == self.VpnActive:
            return 'True' if self._last_vpn_active else 'False'

        elif self.type == self.CountryLabel:
            code = self._last_country_code or ''
            name = self._last_country_name or ''
            return ('%s – %s' % (code, name)) if (code and name) else (name or code)

        elif self.type == self.NetActive:
            return 'net_on' if self._last_net_active else 'net_off'

        elif self.type == self.VpnProto:
            return self._last_vpn_proto or 'none'

        elif self.type == self.VpnIface:
            return self._last_vpn_iface or ''

        elif self.type == self.VpnProvider:
            if not self._last_vpn_active:
                return 'none'
            slug = self._prov_local or self._prov_public
            return slug or 'unknown'

        elif self.type == self.VpnProviderPretty:
            if not self._last_vpn_active:
                return 'None'
            slug = self._prov_local or self._prov_public
            if not slug:
                return 'Unknown'
            return PROVIDER_PRETTY.get(slug, slug.capitalize())

        return ''

    text = property(getText)

    @cached
    def getBoolean(self):
        if self.type == self.VpnActive:
            return bool(self._last_vpn_active)
        if self.type == self.NetActive:
            return bool(self._last_net_active)
        return False

    boolean = property(getBoolean)

    def changed(self, what):
        Converter.changed(self, what)