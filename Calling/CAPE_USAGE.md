# CAPE API Wrapper - คู่มือการใช้งาน

## ภาพรวม

Class `CAPEAnalyzer` ถูกออกแบบมาเพื่อทำงานกับ CAPE Sandbox API โดยเฉพาะสำหรับการวิเคราะห์มัลแวร์และส่งผลลัพธ์ให้ LLM (Gemini) วิเคราะห์ต่อ

## การ Filter รายงานสำหรับ LLM

ฟังก์ชัน `get_report()` ได้รับการปรับปรุงให้ **Filter เฉพาะข้อมูลที่สำคัญ** ตาม `system_prompt.py` โดยรองรับ **"The Dynamic Reality Rule (CAPE Sandbox Override)"**

### ข้อมูลที่ถูก Filter (ส่งให้ LLM):

```json
{
  "target_info": {
    "filename": "ชื่อไฟล์",
    "file_type": "PE32 executable",
    "file_size": 12345,
    "md5": "...",
    "sha256": "...",
    "developer_company": "ชื่อบริษัทผู้พัฒนา",
    "product_name": "ชื่อผลิตภัณฑ์",
    "file_description": "คำอธิบาย"
  },

  "malscore": 5.2,

  "malware_identification": {
    "identified": true/false,
    "malware_families": ["ransomware", "stealer"],
    "cape_payloads": [...]
  },

  "signatures_analysis": {
    "total_signatures": 25,
    "critical_count": 3,        // severity 3+
    "warning_count": 8,         // severity 2
    "info_count": 14,           // severity 1
    "critical_signatures": [...],
    "warning_signatures": [...],
    "info_signatures": [...]
  },

  "network_activity": {
    "has_network_activity": true,
    "total_connections": 15,
    "suspicious_hosts": [
      {"ip": "1.2.3.4", "country": "Unknown"}
    ],
    "http_requests": [
      {"method": "POST", "uri": "/api/...", "host": "evil.com"}
    ],
    "dns_queries": ["evil.com", "c2server.com"],
    "tcp_count": 10,
    "udp_count": 5
  },

  "behavior_summary": {
    "files_written": [...],
    "files_deleted": [...],
    "files_read": [...],
    "registry_written": [...],
    "registry_deleted": [...],
    "mutexes": [...],
    "commands": [...]
  },

  "ttps": [
    {
      "technique": "T1055",
      "description": "Process Injection"
    }
  ],

  "analysis_info": {
    "duration": 120,
    "started": "2025-01-01 10:00:00",
    "ended": "2025-01-01 10:02:00"
  }
}
```

## ความแตกต่างจากเดิม

### ❌ โค้ดเดิม (มีปัญหา):
- มี `return None` บรรทัด 149 ทำให้โค้ดไม่ทำงาน
- ข้อมูลไม่ครบตาม Prompt
- ไม่มีการจัดกลุ่ม signatures ตาม severity
- ไม่มีข้อมูล TTPs, malware identification
- Network summary ไม่ละเอียด

### ✅ โค้ดใหม่ (ถูกต้อง):
- ✅ แก้ไข bug `return None`
- ✅ จัดกลุ่ม signatures เป็น critical/warning/info
- ✅ ตรวจหา malware families อัตโนมัติ
- ✅ ดึงข้อมูล Network Activity ละเอียด (hosts, HTTP, DNS)
- ✅ รวม TTPs (MITRE ATT&CK)
- ✅ ดึง CAPE payloads (malware ที่ extract ได้)
- ✅ รวม Behavior summary (files, registry, mutexes)

## การใช้งาน

### 1. วิเคราะห์ไฟล์และดึงรายงาน

```python
from Calling.CAPE import CAPEAnalyzer

cape = CAPEAnalyzer()

# วิธีที่ 1: วิเคราะห์ครบวงจร (แนะนำ)
result = cape.analyze_file_complete(
    file_path="suspicious.exe",
    wait=True,
    timeout=600,
    get_filtered_report=True
)

if result['status'] == 'completed':
    filtered_data = result['report']['data']
    # ส่งไปให้ Gemini วิเคราะห์
    print(filtered_data)
```

### 2. ดึงรายงานจาก task_id ที่มีอยู่แล้ว

```python
# วิธีที่ 2: ดึงรายงานจาก task ที่วิเคราะห์เสร็จแล้ว
task_id = 123

report = cape.get_report(task_id)

if report['status'] == 'success':
    data = report['data']

    # ตรวจสอบว่าเป็นมัลแวร์หรือไม่
    if data['malware_identification']['identified']:
        print(f"⚠️ ตรวจพบมัลแวร์: {data['malware_identification']['malware_families']}")

    # ตรวจสอบ critical signatures
    critical = data['signatures_analysis']['critical_signatures']
    if critical:
        print(f"🚨 มี {len(critical)} critical signatures!")

    # ตรวจสอบ network activity (C2 communication)
    if data['network_activity']['has_network_activity']:
        print("🌐 พบการเชื่อมต่อเครือข่าย")
        print(f"Hosts: {data['network_activity']['suspicious_hosts']}")
```

## การทำงานกับ LLM (Gemini)

โค้ดนี้ได้ออกแบบให้ทำงานร่วมกับ Prompt ใน `system_prompt.py`:

### Key Features สำหรับ LLM:

1. **The "Dynamic Reality Rule"** - CAPE results มีน้ำหนักมากกว่า static analysis
   - ถ้า `malware_identification.identified = true` → แดงทันที
   - ถ้ามี `critical_signatures` → วิเคราะห์ต่อ
   - ถ้าไม่มี network activity แปลก → เพิ่มความมั่นใจ

2. **Signatures แบ่งตาม Severity**:
   - `critical_signatures` (severity 3+) → พฤติกรรมอันตราย
   - `warning_signatures` (severity 2) → น่าสงสัย
   - `info_signatures` (severity 1) → ข้อมูลทั่วไป

3. **Network Activity** - สำคัญมากสำหรับตรวจ C2:
   - `suspicious_hosts` - IP ที่เชื่อมต่อ
   - `http_requests` - HTTP traffic (อาจเป็น C2 communication)
   - `dns_queries` - โดเมนที่ query

4. **TTPs** - MITRE ATT&CK techniques
   - ช่วยให้ LLM เข้าใจ tactics ของมัลแวร์

## ตัวอย่างการส่งให้ Gemini

```python
import json
import google.generativeai as genai
from Calling.CAPE import CAPEAnalyzer
from Calling.prompt.system_promtp import system_prompt

# 1. ดึงรายงาน CAPE
cape = CAPEAnalyzer()
report = cape.get_report(task_id=123)

if report['status'] == 'success':
    cape_data = report['data']

    # 2. สร้าง prompt สำหรับ Gemini
    user_prompt = f"""
    วิเคราะห์รายงาน CAPE Sandbox นี้และให้คำแนะนำว่าควรติดตั้งหรือไม่:

    {json.dumps(cape_data, ensure_ascii=False, indent=2)}
    """

    # 3. ส่งให้ Gemini
    genai.configure(api_key="YOUR_API_KEY")
    model = genai.GenerativeModel('gemini-pro')

    response = model.generate_content([
        system_prompt(),
        user_prompt
    ])

    print(response.text)
```

## สรุปความแตกต่างสำคัญ

| Feature | โค้ดเดิม | โค้ดใหม่ |
|---------|----------|----------|
| Signatures แบ่ง severity | ❌ | ✅ (critical/warning/info) |
| Malware identification | ❌ | ✅ (auto-detect families) |
| Network analysis | 🟡 พื้นฐาน | ✅ ละเอียด (hosts, HTTP, DNS) |
| TTPs (MITRE ATT&CK) | ❌ | ✅ |
| Behavior summary | 🟡 บางส่วน | ✅ ครบถ้วน |
| CAPE payloads | ❌ | ✅ |
| Bug `return None` | ❌ มี bug | ✅ แก้แล้ว |

## ข้อควรระวัง

1. **Network Activity** - ถ้าไม่มี = ไม่ได้หมายความว่าปลอดภัย (อาจจะยังไม่ trigger)
2. **Malscore** - คะแนนต่ำไม่ได้หมายความว่าปลอดภัย ต้องดู signatures ด้วย
3. **Critical Signatures** - ถ้ามีแม้แค่ 1-2 รายการ ต้องตรวจสอบให้ดี

## ไฟล์ที่เกี่ยวข้อง

- `CAPE.py` - Main class
- `system_prompt.py` - Prompt สำหรับ LLM
- `test_cape_report.py` - ไฟล์ทดสอบ
- `.env` - ตั้งค่า `CAPE_BASE_URL`
