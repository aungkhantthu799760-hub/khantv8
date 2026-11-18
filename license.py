# =====================================================================
# license.py - License Management Module (KAVIN V9 & Khant Key Optimized)
# =====================================================================

import os
import json
import hashlib
import hmac
import base64
import uuid
from datetime import datetime, timedelta

LICENSE_FILE = "license.dat"
USED_KEYS_FILE = "used_keys.txt"      # သုံးပြီးသား Key တွေ သိမ်းမယ့်ဖိုင်
DEVICE_FILE = ".device_id"          # ဖုန်းရဲ့ Device ID သိမ်းမယ့်ဖိုင်

SECRET_KEY = b"KavinV9SecretKey2026!@#$%^&*()"

def _get_device_id():
    if os.path.exists(DEVICE_FILE):
        with open(DEVICE_FILE, "r") as f: return f.read().strip()
    else:
        new_id = str(uuid.uuid4())[:8].upper()
        with open(DEVICE_FILE, "w") as f: f.write(new_id)
        return new_id

def _is_key_used(key: str):
    if not os.path.exists(USED_KEYS_FILE): return False
    with open(USED_KEYS_FILE, "r") as f:
        used = f.read().splitlines()
    return key in used

def _mark_key_used(key: str):
    with open(USED_KEYS_FILE, "a") as f:
        f.write(key + "\n")

def _encode_license(data: dict) -> str:
    try:
        json_str = json.dumps(data, separators=(',', ':'))
        raw = json_str.encode('utf-8')
        sig = hmac.new(SECRET_KEY, raw, hashlib.sha256).hexdigest()[:16]
        return f"{sig}.{base64.b64encode(raw).decode()}"
    except Exception: return ""

def _decode_license(encoded: str) -> dict:
    try:
        if '.' not in encoded: return None
        sig, payload_b64 = encoded.split('.', 1)
        raw = base64.b64decode(payload_b64)
        expected_sig = hmac.new(SECRET_KEY, raw, hashlib.sha256).hexdigest()[:16]
        if not hmac.compare_digest(sig, expected_sig): return None
        return json.loads(raw.decode('utf-8'))
    except Exception: return None

def _generate_license_data(key: str, days: float, device_id: str) -> str:
    try:
        now = datetime.now()
        expiry = now + timedelta(days=days) 
        data = {
            "key_hash": hashlib.sha256(key.encode()).hexdigest()[:32],
            "device_id": device_id,
            "issued": now.strftime("%Y-%m-%d %H:%M:%S"),
            "expiry": expiry.strftime("%Y-%m-%d %H:%M:%S"),
            "days": days,
        }
        return _encode_license(data)
    except Exception: return ""

def check_approval():
    try:
        if not os.path.exists(LICENSE_FILE): return False, "No license"
        with open(LICENSE_FILE, "r") as f: encoded = f.read().strip()
        if not encoded: return False, "Empty license"

        data = _decode_license(encoded)
        if not data: return False, "Invalid license"

        if data.get("device_id") != _get_device_id():
            return False, "License is bound to another device."

        expiry_str = data.get("expiry", "")
        try: 
            expiry = datetime.strptime(expiry_str, "%Y-%m-%d %H:%M:%S")
        except Exception: 
            return False, "Invalid expiry format"

        now = datetime.now()
        if now > expiry: return False, f"Expired on {expiry_str}"

        diff = expiry - now
        h, rem = divmod(diff.seconds, 3600)
        m = rem // 60
        return True, f"{diff.days}d {h}h {m}m left"
    except Exception as e: return False, f"Error: {e}"

def activate(key: str):
    try:
        key = key.strip()
        
        # 1. Key ထဲတွင် 'khant' ပါဝင်ရမည့် စည်းကမ်းချက်
        if "khant" not in key.lower():
            return False, "❌ Invalid Key: 'khant' အပါအဝင်ဖြစ်ရပါမည်။"
        
        # 2. Key ပုံစံ မှန်ကန်မှု စစ်ဆေးခြင်း (ဥပမာ - KHANT-V9-365-XXXX)
        if not key.upper().startswith("KHANT-"):
            return False, "❌ Invalid Key Format ('KHANT-' ဖြင့်စတင်ရပါမည်။)"
        
        # 3. တစ်ခါသုံး (One-Time Use) ဖြစ်ပြီးသားလား စစ်ဆေးခြင်း
        if _is_key_used(key):
            return False, "❌ ဤ Key မှာ အခြားဖုန်းတွင် အသုံးပြုပြီးသား ဖြစ်ပါသည်။ (One-Time Use Only)"

        parts = key.split("-")
        if len(parts) < 4: return False, "❌ Invalid Key Structure"
        
        try: days_float = float(parts[2]) 
        except: days_float = 365.0

        # 4. လက်ရှိဖုန်း၏ Device ID နှင့် တွဲ၍ License ဖိုင်ထုတ်ပေးခြင်း
        device_id = _get_device_id()
        encoded = _generate_license_data(key, days_float, device_id)
        if not encoded: return False, "❌ Failed to generate license"

        # 5. ဖိုင်ထဲသို့ သိမ်းပြီး ဤ Key ကို သုံးပြီးသားအဖြစ် မှတ်တမ်းတင်ခြင်း
        with open(LICENSE_FILE, "w") as f: f.write(encoded)
        _mark_key_used(key)

        is_valid, msg = check_approval()
        if is_valid: return True, f"✓ Activated! {msg}"
        return False, "Activation failed"
    except Exception as e: return False, f"Error: {e}"
