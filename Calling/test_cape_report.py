"""
ไฟล์ทดสอบการ Filter รายงาน CAPE สำหรับส่งให้ LLM วิเคราะห์
"""
import json
from CAPE import CAPEAnalyzer

# สร้าง instance
cape = CAPEAnalyzer()

# ตัวอย่าง: ดึงรายงานจาก task_id ที่มีอยู่แล้ว
task_id = 1  # เปลี่ยนเป็น task_id ที่ต้องการทดสอบ

print("=" * 80)
print("กำลังดึงรายงาน CAPE และ Filter สำหรับ LLM...")
print("=" * 80)

# ดึงรายงาน
report = cape.get_report(task_id)

if report.get("status") == "success":
    data = report["data"]

    print("\n✅ ดึงรายงานสำเร็จ!\n")

    # แสดงข้อมูลสำคัญ
    print("📁 ข้อมูลไฟล์:")
    print(f"  - ชื่อไฟล์: {data['target_info']['filename']}")
    print(f"  - ประเภท: {data['target_info']['file_type']}")
    print(f"  - ขนาด: {data['target_info']['file_size']:,} bytes")
    print(f"  - ผู้พัฒนา: {data['target_info']['developer_company']}")
    print(f"  - ผลิตภัณฑ์: {data['target_info']['product_name']}")

    print(f"\n⚠️ คะแนนความเสี่ยง (Malscore): {data['malscore']}")

    # Malware Identification
    mal_id = data['malware_identification']
    print(f"\n🦠 Malware Identification:")
    print(f"  - ตรวจพบมัลแวร์: {'ใช่' if mal_id['identified'] else 'ไม่'}")
    if mal_id['identified']:
        print(f"  - ประเภทมัลแวร์: {', '.join(mal_id['malware_families'])}")
    if mal_id['cape_payloads']:
        print(f"  - Payloads ที่ Extract ได้: {len(mal_id['cape_payloads'])} ไฟล์")

    # Signatures
    sig = data['signatures_analysis']
    print(f"\n🔍 Signatures (รวม {sig['total_signatures']} รายการ):")
    print(f"  - Critical (severity 3+): {sig['critical_count']} รายการ")
    print(f"  - Warning (severity 2): {sig['warning_count']} รายการ")
    print(f"  - Info (severity 1): {sig['info_count']} รายการ")

    if sig['critical_signatures']:
        print("\n  🚨 Critical Signatures:")
        for s in sig['critical_signatures'][:5]:
            print(f"    • {s['name']}: {s['description']}")

    # Network Activity
    net = data['network_activity']
    print(f"\n🌐 Network Activity:")
    print(f"  - มี Network Activity: {'ใช่' if net['has_network_activity'] else 'ไม่'}")
    print(f"  - จำนวน Connections: {net['total_connections']} connections")
    print(f"  - TCP: {net['tcp_count']}, UDP: {net['udp_count']}")

    if net['suspicious_hosts']:
        print(f"\n  🌍 Suspicious Hosts:")
        for host in net['suspicious_hosts'][:5]:
            print(f"    • {host['ip']} ({host['country']})")

    if net['http_requests']:
        print(f"\n  📡 HTTP Requests:")
        for req in net['http_requests'][:5]:
            print(f"    • {req['method']} {req['uri']}")

    # Behavior
    behavior = data['behavior_summary']
    print(f"\n💾 Behavior Summary:")
    print(f"  - Files Written: {len(behavior['files_written'])} ไฟล์")
    print(f"  - Files Deleted: {len(behavior['files_deleted'])} ไฟล์")
    print(f"  - Registry Written: {len(behavior['registry_written'])} รายการ")
    print(f"  - Mutexes: {len(behavior['mutexes'])} รายการ")

    # TTPs
    ttps = data['ttps']
    if ttps:
        print(f"\n🎯 TTPs (MITRE ATT&CK): {len(ttps)} รายการ")
        for ttp in ttps[:5]:
            print(f"  • {ttp['technique']}: {ttp['description'][:60]}...")

    # บันทึกเป็นไฟล์ JSON
    output_file = "cape_filtered_report.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report, ensure_ascii=False, indent=2)

    print(f"\n✅ บันทึกรายงานที่ Filter แล้วไปที่: {output_file}")
    print("\n" + "=" * 80)
    print("ข้อมูลนี้พร้อมส่งให้ Gemini LLM วิเคราะห์แล้วครับ!")
    print("=" * 80)

else:
    print(f"\n❌ เกิดข้อผิดพลาด: {report.get('error', 'Unknown error')}")
