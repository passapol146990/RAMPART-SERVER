import os
import requests
import hashlib
import time
from typing import Optional, Dict, Any
from dotenv import load_dotenv
import json

load_dotenv()    

class CAPEAnalyzer:
    def __init__(self):
        self.base_url = os.getenv("CAPE_BASE_URL")
        if not self.base_url:
            raise ValueError("CAPE_BASE_URL not found in .env file")

    def calculate_hash(self, file_path: str, hash_type: str = "sha256") -> str:
        hash_obj = hashlib.new(hash_type)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_obj.update(chunk)

        return hash_obj.hexdigest()

    def cheack_analyer(self, file_path: str, hash_type: str = "sha256"):
        file_hash = self.calculate_hash(file_path, hash_type)
        url = f"{self.base_url}/apiv2/tasks/search/{hash_type}/{file_hash}/"
        try:
            response = requests.get(url)
            js = response.json()
            return js.get("data")
        except requests.exceptions.RequestException as e:
            return {"error": str(e), "data": None}

    def delete_taskID(self,task_id):
        requests.get(f"{self.base_url}/apiv2/tasks/delete/{task_id}")

    def create_file_task(
        self,
        file_path: str,
        machine: Optional[str] = None,
        is_pcap: bool = False,
    ) -> Dict[str, Any]:
        check_analy = self.cheack_analyer(file_path)
        if len(check_analy) > 0:
            return {
                "status": "exists",
                "task_id": check_analy[0],
                "message": f"File already analyzed. Task ID: {check_analy[0]["id"]}"
            }
        

        url = f"{self.base_url}/apiv2/tasks/create/file/"

        files = {'file': open(file_path, 'rb')}
        data = {}

        if machine:
            data['machine'] = machine

        if is_pcap:
            data['pcap'] = '1'

        try:
            response = requests.post(url, files=files, data=data)
            response.raise_for_status()
            result = response.json()

            return {
                "status": "created",
                "task_id": result.get("data", {}).get("task_ids", [None])[0] if result.get("data") else None,
                "response": result
            }
        except requests.exceptions.RequestException as e:
            return {"status": "error", "error": str(e)}
        finally:
            files['file'].close()

    def get_task_status(self, task_id: int) -> Dict[str, Any]:
        url = f"{self.base_url}/apiv2/tasks/status/{task_id}"
        try:
            response = requests.get(url)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": str(e), "data": None}

    def wait_for_task(
        self,
        task_id: int,
        timeout: int = 600,
        poll_interval: int = 10,
        verbose: bool = True
    ) -> bool:
        start_time = time.time()

        while time.time() - start_time < timeout:
            status = self.get_task_status(task_id)

            if status.get("data"):
                task_status = status["data"].get("status")

                if verbose:
                    print(f"Task {task_id} status: {task_status}")

                if task_status == "reported":
                    return True
                elif task_status in ["failed_analysis", "failed_processing"]:
                    if verbose:
                        print(f"Task {task_id} failed!")
                    return False

            time.sleep(poll_interval)

        if verbose:
            print(f"Task {task_id} timeout after {timeout} seconds")
        return False

    def get_task_report(
        self,
        task_id: int,
        report_format: str = "json",
        download_zip: bool = False
    ):
        url = f"{self.base_url}/apiv2/tasks/get/report/{task_id}/{report_format}/"

        if download_zip:
            url += "zip/"

        try:
            response = requests.get(url)
            response.raise_for_status()

            if download_zip:
                return {"status": "success", "content": response.content, "type": "zip"}
            else:
                return {"status": "success", "data": response.json()}
        except requests.exceptions.RequestException as e:
            return {"status": "error", "error": str(e)}

    def get_report(self, task_id: int):
        report = self.get_task_report(task_id)
        with open(f'z-report2.0-cape-{task_id}.json','w',encoding='utf-8') as wf:
            wf.write(json.dumps(report, ensure_ascii=False, indent=4))
            wf.close()

        if report.get("status") != "success":
            return report

        raw_data = report.get("data", {})

        # === 1. Target File Information ===
        target = raw_data.get("target", {})
        file_info = target.get("file", {})
        pe_info = file_info.get("pe", {})
        versioninfo = pe_info.get("versioninfo", [])

        # Extract company name from PE version info
        company_name = "Unknown"
        product_name = "Unknown"
        file_description = "Unknown"

        for item in versioninfo:
            name = item.get("name", "")
            value = item.get("value", "")
            if name == "CompanyName":
                company_name = value
            elif name == "ProductName":
                product_name = value
            elif name == "FileDescription":
                file_description = value

        # === 2. Signatures Analysis (จัดกลุ่มตาม severity) ===
        all_signatures = raw_data.get("signatures", [])

        critical_signatures = []  # severity 3+
        warning_signatures = []   # severity 2
        info_signatures = []      # severity 1

        # ตรวจหา malware identification จาก signature names
        malware_names = []

        for sig in all_signatures:
            sig_name = sig.get("name", "")
            sig_desc = sig.get("description", "")
            sig_severity = sig.get("severity", 0)

            sig_data = {
                "name": sig_name,
                "description": sig_desc,
                "severity": sig_severity
            }

            # จัดกลุ่มตาม severity
            if sig_severity >= 3:
                critical_signatures.append(sig_data)
            elif sig_severity == 2:
                warning_signatures.append(sig_data)
            else:
                info_signatures.append(sig_data)

            # ตรวจหา malware family names
            malware_keywords = [
                "ransomware", "stealer", "trojan", "backdoor", "rootkit",
                "banker", "cryptominer", "loader", "dropper", "keylogger",
                "rat", "spyware", "worm", "virus", "exploit"
            ]

            for keyword in malware_keywords:
                if keyword in sig_name.lower():
                    malware_names.append(sig_name)
                    break
        
        # === 3. Network Activity ===
        network = raw_data.get("network", {})

        hosts = network.get("hosts", [])
        http_requests = network.get("http", [])
        dns_requests = network.get("dns", [])
        tcp_connections = network.get("tcp", [])
        udp_connections = network.get("udp", [])

        # Extract suspicious domains/IPs
        suspicious_hosts = []
        for host in hosts[:10]:  # Top 10 hosts
            suspicious_hosts.append({
                "ip": host.get("ip"),
                "country": host.get("country_name", "Unknown")
            })

        # Extract HTTP requests (potential C2 communication)
        http_summary = []
        for req in http_requests[:10]:
            http_summary.append({
                "method": req.get("method"),
                "uri": req.get("uri"),
                "host": req.get("host")
            })

        # DNS queries
        dns_summary = [dns.get("request") for dns in dns_requests[:10]]

        network_summary = {
            "has_network_activity": len(hosts) > 0,
            "total_connections": len(tcp_connections) + len(udp_connections),
            "suspicious_hosts": suspicious_hosts,
            "http_requests": http_summary,
            "dns_queries": dns_summary,
            "tcp_count": len(tcp_connections),
            "udp_count": len(udp_connections)
        }

        # === 4. Behavior Analysis ===
        behavior = raw_data.get("behavior", {})
        summary = behavior.get("summary", {})

        behavior_summary = {
            "files_written": summary.get("write_files", [])[:15],
            "files_deleted": summary.get("delete_files", [])[:15],
            "files_read": summary.get("read_files", [])[:15],
            "registry_written": summary.get("write_keys", [])[:15],
            "registry_deleted": summary.get("delete_keys", [])[:15],
            "mutexes": summary.get("mutexes", [])[:10],
            "commands": summary.get("executed_commands", [])[:10],
        }

        # === 5. TTPs (Tactics, Techniques, and Procedures) ===
        ttps = raw_data.get("ttps", [])
        ttps_summary = []

        for ttp in ttps:
            ttps_summary.append(ttp)

        # === 6. CAPE Malware Extraction ===
        cape_data = raw_data.get("CAPE", {})
        cape_payloads = cape_data.get("payloads", []) if isinstance(cape_data, dict) else []

        extracted_malware = [] 
        for payload in cape_payloads[:5]:
            extracted_malware.append({
                "type": payload.get("cape_type"),
                "yara": payload.get("yara", []),
                "cape_yara": payload.get("cape_yara", []),
                "size": payload.get("size")
            })

        # === 7. Malware Score ===
        malscore = raw_data.get("malscore", 0.0)

        # === 8. Info ===
        info = raw_data.get("info", {})

        # === Final Filtered Data for LLM ===
        filtered_data = {
            # ข้อมูลไฟล์
            "target_info": {
                "filename": file_info.get("name"),
                "file_type": file_info.get("type"),
                "file_size": file_info.get("size"),
                "md5": file_info.get("md5"),
                "sha256": file_info.get("sha256"),
                "developer_company": company_name,
                "product_name": product_name,
                "file_description": file_description
            },

            # คะแนนความเสี่ยง
            "malscore": malscore,

            # Malware Identification
            "malware_identification": {
                "identified": len(malware_names) > 0,
                "malware_families": list(set(malware_names)),  # Remove duplicates
                "cape_payloads": extracted_malware
            },

            # Signatures (แบ่งตาม severity)
            "signatures_analysis": {
                "total_signatures": len(all_signatures),
                "critical_count": len(critical_signatures),
                "warning_count": len(warning_signatures),
                "info_count": len(info_signatures),
                "critical_signatures": critical_signatures[:10],  # Top 10
                "warning_signatures": warning_signatures[:10],
                "info_signatures": info_signatures[:5]
            },

            # Network Activity (สำคัญสำหรับ C2 detection)
            "network_activity": network_summary,

            # Behavior (พฤติกรรมการทำงาน)
            "behavior_summary": behavior_summary,

            # TTPs (Mitre ATT&CK)
            "ttps": ttps_summary[:15],

            # Additional Info
            "analysis_info": {
                "duration": info.get("duration"),
                "started": info.get("started"),
                "ended": info.get("ended")
            }
        }
        
        return {
            "status": "success",
            "data": filtered_data
        }

    def ScanFile(self, file_path):
        ck = self.cheack_analyer(file_path=file_path)
        print(ck)
        # if len(ck) > 0:

cape = None
def CAPE():
    global cape
    if cape is None:
        cape = CAPEAnalyzer()
    return cape



def testcape(file_path,dele=False):
    cape = CAPEAnalyzer()
    ckid = cape.cheack_analyer(file_path)
    print(f"{'#'*50}[ {file_path} ]{'#'*50}")
    print(ckid)
    if len(ckid) == 0:
        result = cape.create_file_task(file_path=file_path,machine="win10")
        print('*'*100)
        print(result)
        if result.get('status','faild'):
            print('*'*100)
            print("status : Faild")
            return
        task_id = result.get('task_id',None)
        if task_id is None:
            print('*'*100)
            print("Task ID is None")
            return
        if task_id is None:
            print('*'*100)
            print(f"Task ID : {task_id}")
            return
        return

    task_id = ckid[0].get('id',None)
    taskTarget = ckid[0].get('target',task_id)
    if task_id is None:
        print('*'*100)
        print(f"Task ID : {task_id}")
        return
    
    if dele:
        print('*'*100)
        cape.delete_taskID(task_id)
        return
    
    status_task = cape.get_task_status(task_id)
    print('*'*100)
    print(f"Status: {status_task}")
    if status_task.get('error',True):
        print('*'*100)
        print("Error : !!!")
        return

    status_data = status_task.get('data','pending')
    if status_data != 'reported':
        print('*'*100)
        print(f"Status Task Data : {status_data}")
        return

    report = cape.get_report(task_id)
    with open(f"z-report4.1-cape-{task_id}{taskTarget.replace('.','')}.json",'w',encoding="utf-8") as wf:
        report_str = json.dumps(report, ensure_ascii=False, indent=4)
        wf.write(report_str)
        wf.close()
    return


file_path = "/home/passapol/Downloads/AnyDesk.exe"
testcape(file_path)
file_path = "/home/passapol/Downloads/SpyEye/Spyeye/SpyEye1.exe"
testcape(file_path)
file_path = "/home/passapol/Downloads/SpyEye/Spyeye/SpyEye2.exe"
testcape(file_path)
file_path = "/home/passapol/Downloads/SpyEye/Spyeye/SpyEye3.exe"
testcape(file_path)
file_path = "/home/passapol/Downloads/SpyEye/Spyeye/SpyEye4.exe"
testcape(file_path)
