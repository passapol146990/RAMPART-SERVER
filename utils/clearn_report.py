def clean_mobsf_report(raw_data):
    if not raw_data:
        return None
    
    # ดึงเฉพาะส่วนที่ AI ต้องใช้ตัดสินใจ
    cleaned = {
        "app_name": raw_data.get("app_name"),
        "package_name": raw_data.get("package_name"),
        "version_name": raw_data.get("version_name"),
        "security_score": raw_data.get("appsec",{"security_score":None}).get("security_score"), # คะแนนความปลอดภัย
        "permissions": [],
        "high_risk_components": []
    }

    # 1. กรอง Permission เอาเฉพาะที่อันตราย (status: dangerous)
    # ปกติ MobSF จะส่งมาเยอะมาก เราคัดเฉพาะตัวแดงๆ
    if "permissions" in raw_data:
        for perm_name, details in raw_data["permissions"].items():
            if details.get("status") == "dangerous":
                cleaned["permissions"].append({
                    "name": perm_name,
                    "description": details.get("description")
                })

    # 2. กรองผลวิเคราะห์ Code (เอาเฉพาะระดับ High/Warning)
    # MobSF อาจเรียกส่วนนี้ว่า code_analysis หรือ api_analysis
    # ตัวอย่างการดึง (ต้องดู Structure จริงของ MobSF เวอร์ชันที่คุณใช้ประกอบ)
    if "code_analysis" in raw_data:
        for key, findings in raw_data["code_analysis"].items():
             # เช็คว่า findings เป็น dict และมี metadata
            if isinstance(findings, dict) and findings.get("metadata", {}).get("severity") == "high":
                 cleaned["high_risk_components"].append(key)

    # *** สำคัญมาก: ตัดส่วนที่กิน Token เยอะๆ ทิ้ง ***
    # raw_data.get("strings") -> รายชื่อ string ทั้งหมดในแอป (ยาวมาก)
    # raw_data.get("files") -> รายชื่อไฟล์ทั้งหมด
    # raw_data.get("icon") -> รูปภาพแบบ Base64 (กินที่มหาศาล)
    
    return cleaned

def clean_virustotal_smart(raw_data):
    if not raw_data:
        return None
    
    # เจาะเข้าไปที่ attributes
    attrs = raw_data.get("data", {}).get("attributes", {})
    androguard = attrs.get("androguard", {})
    
    # 1. ดึงข้อมูลยืนยันตัวตน (Identity) *** สำคัญมาก ***
    cert = androguard.get("certificate", {}).get("Subject", {})
    signer = cert.get("O") # Organization เช่น "Google Inc."
    
    # 2. ดึงสถิติความปลอดภัย
    stats = attrs.get("last_analysis_stats", {})
    
    # 3. ดึงรายชื่อ Antivirus ที่เจอว่าผิดปกติ (เฉพาะตัวแดง)
    # เราไม่เอาทั้ง 60 เจ้าที่บอกว่า Safe เราเอาแค่ตัวที่บอกว่า Malicious
    malware_findings = []
    results = attrs.get("last_analysis_results", {})
    for engine, result in results.items():
        if result.get("category") == "malicious":
            malware_findings.append(f"{engine}: {result.get('result')}")

    # 4. ดึง Permission (เผื่อ MobSF ไม่มีข้อมูล)
    # เอาแค่ชื่อ Permission พอ ไม่เอาคำอธิบายยาวๆ
    perms_raw = androguard.get("permission_details", {})
    permissions = list(perms_raw.keys()) if perms_raw else []

    return {
        "app_identity": {
            "names": attrs.get("names", [])[:3], # เอาชื่อไฟล์แค่ 3 ชื่อแรกพอ
            "package_name": androguard.get("Package"),
            "developer_signer": signer, # จุดตัดสินว่าของแท้ไหม
            "is_google_app": "Google" in str(signer) # Hint ให้ AI นิดนึง
        },
        "scan_summary": {
            "malicious_count": stats.get("malicious", 0),
            "total_scanners": sum(stats.values()) if stats else 0
        },
        "threats_found": malware_findings, # ถ้าเป็น [] แปลว่าสะอาด
        "permissions": permissions # ส่งไป Cross-check กับ MobSF
    }