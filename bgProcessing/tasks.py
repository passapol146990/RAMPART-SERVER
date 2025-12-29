from bgProcessing.celery_app import celery_app
from Calling.VirusTotal import VirusTotal
from Calling.GeminiAPI import GeminiAPI
from Calling.MobSF import MobSF
import time
import json

VIRUSTOTAL_MAX_SIZE = 32 * 1024 * 1024  # 32 MB

# Decorator @celery_app.task เปลี่ยนฟังก์ชันธรรมดาให้เป็น Task
@celery_app.task(bind=True)
def analyze_malware_task(self, file_path: str, file_hashes:dict, total_size: int, analysis_tool:str):
    results = {}
    tools = []
    md5 = file_hashes.get('md5','')
    vt = VirusTotal()

    print("#"*50)
    print(f"[{self.request.id}] Starting analysis (MD5: {md5})")
    print(f"file: {file_path}")
    print('*'*50)
    if total_size > VIRUSTOTAL_MAX_SIZE:
        print(f"File size {total_size} bytes, VirusTotal upload limit of {VIRUSTOTAL_MAX_SIZE} bytes. Skipping VT upload.")
        rp = vt.get_report_by_hash(md5)
        print(f"VirusTotal report fetch result: {rp["success"]}")
        if rp['success']:
            results["virustotal"] = rp["data"]
    else:
        print(f"File size {total_size} bytes within VirusTotal upload limit. Proceeding with VT upload.")
        tools.append("virustotal")
    tools.append(analysis_tool)

    print('*'*50)
    print(f"tools: {tools}")

    # try:
    if "virustotal" in tools:
        print('*'*50)
        print(f"Uploading file to VirusTotal: {file_path}")
        res = vt.upload_file(file_path=file_path)
        print(f"VirusTotal upload response: {res}")
        if res["success"]:
            id_b64 = ""
            try:
                id_b64 = res['data']['data']['id']
            except:pass
            time.sleep(5)
            rp = vt.get_report_by_base64(id_b64)
            print(f"VirusTotal report fetch result: {rp['success']}")
            if rp['success']:
                results["virustotal"] = rp["data"]

    # --- 2. จำลองการส่งไป MobSF ---
    if "mobsf" in tools:
        print('*'*50)
        print(f"Scanning file with MobSF: {file_path}")
        mobsf = MobSF()
        report = mobsf.generate_json_report(file_hash=md5)
        print(f"MobSF report generation result: {report['success']}")
        if report["success"]:
            results["mobsf_report"] = report["data"]
        else:
            print(f"MobSF report not found, Start scaning!")
            mobsf_result = mobsf.scan_file(file_path=file_path)
            results["mobsf"] = mobsf_result

    # # --- 3. จำลองการส่งไป CAPE ---
    # if "cape" in tools:
    #     results["cape"] = {"behavior": "suspicious"}

    with open('z-report3-result.json','w',encoding='utf-8') as wf:
        wf.write(json.dumps(results,ensure_ascii=False, indent=4))
        wf.close()
    
    print('*'*50)
    print(f"Gemini Analysis starting...")
    response = GeminiAPI().AnalysisGemini(results)
    print(f"gemini response : {response}")
    data_to_save = {}
    if isinstance(response, str):
        clean_str = response.replace("```json", "").replace("```", "").strip()
        try:
            data_to_save = json.loads(clean_str)
        except json.JSONDecodeError:
            print("Failed to parse Gemini response as JSON.")
            data_to_save = response
    else:
        data_to_save = response
    try:
        with open('z-report4-gemini.json', 'w', encoding='utf-8') as f:
            json.dump(data_to_save, f, ensure_ascii=False, indent=4)
            f.close()
        print("success")
    except Exception as e:
        print(f"Error : {e}")

    return {
        "status": "completed",
        "file_path": file_path,
    }

    # except Exception as e:
    #     return {"status": "failed", "error": str(e)}