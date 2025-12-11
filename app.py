from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import os
import uuid
import aiofiles
import json
from pathlib import Path

from Calling.GeminiAPI import GeminiAPI
from Calling.VirusTotal import VirusTotal
from Calling.MobSF import MobSF
from utils.clearn_report import clean_mobsf_report, clean_virustotal_report

app = FastAPI(
    title="RAMPART-AI",
    description="RAMPART-AI Models Testing",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = Path("Files/files")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

REPORT_DIR = Path("Files/report")
REPORT_DIR.mkdir(parents=True, exist_ok=True)

MAX_FILE_SIZE = 1 * 1024 * 1024 * 1024  # 1 GB
CHUNK_SIZE = 1024 * 1024  # 1 MB
VIRUSTOTAL_MAX_SIZE = 32 * 1024 * 1024  # 32 MB (Public API limit)
MOBSF_SUPPORTED_EXTENSIONS = ['.apk', '.xapk', '.ipa', '.appx', '.zip']

@app.get('/')
async def root():
    return {"success":True}

@app.post('/api/upload')
async def uploadFile(
    file: UploadFile = File(...),
    accesstoken: str = Form(None),
    virustotal: str = Form("true"),
    mobsf: str = Form("false"),
):
    try:
        file_id = str(uuid.uuid4())
        file_extension = os.path.splitext(file.filename)[1]
        file_path = UPLOAD_DIR / f"{file_id}{file_extension}"

        total_size = 0

        async with aiofiles.open(file_path, 'wb') as f:
            while chunk := await file.read(CHUNK_SIZE):
                total_size += len(chunk)

                if total_size > MAX_FILE_SIZE:
                    await f.close()
                    if file_path.exists():
                        os.remove(file_path)
                    raise HTTPException(
                        status_code=413,
                        detail="File size exceeds 1 GB limit"
                    )

                await f.write(chunk)

        # แปลง string เป็น boolean
        virustotal_enabled = virustotal.lower() in ["true", "1", "yes"]
        mobsf_enabled = mobsf.lower() in ["true", "1", "yes"]

        print(f'virustotal : {virustotal_enabled}')
        print(f'mobsf : {mobsf_enabled}')

        vrtt_report = None
        mob_response = None
        warnings = []

        # VirusTotal scan
        if virustotal_enabled:
            if total_size > VIRUSTOTAL_MAX_SIZE:
                warnings.append({
                    "service": "VirusTotal",
                    "message": f"File size ({total_size / (1024*1024):.2f} MB) exceeds VirusTotal limit (32 MB). Skipping VirusTotal scan."
                })
                print(f"Warning: File too large for VirusTotal ({total_size / (1024*1024):.2f} MB > 32 MB)")
            else:
                try:
                    vrtt = VirusTotal()
                    vrtt_upload = vrtt.upload_file(file_path)
                    vrtt_report = vrtt.get_report(vrtt_upload["data"]['id'])
                except Exception as e:
                    warnings.append({
                        "service": "VirusTotal",
                        "message": f"VirusTotal scan failed: {str(e)}"
                    })
                    print(f"VirusTotal error: {str(e)}")

        # MobSF scan
        if mobsf_enabled:
            if file_extension.lower() not in MOBSF_SUPPORTED_EXTENSIONS:
                warnings.append({
                    "service": "MobSF",
                    "message": f"File type '{file_extension}' not supported by MobSF. Supported: {', '.join(MOBSF_SUPPORTED_EXTENSIONS)}"
                })
                print(f"Warning: MobSF does not support {file_extension} files")
            else:
                try:
                    mob = MobSF()
                    mob_response = mob.scan_file(file_path, original_filename=file.filename)
                except Exception as e:
                    warnings.append({
                        "service": "MobSF",
                        "message": f"MobSF scan failed: {str(e)}"
                    })
                    print(f"MobSF error: {str(e)}")

        # บันทึก reports แยกตามแต่ละ service
        report_paths = {}

        if vrtt_report:
            vt_report_path = REPORT_DIR / f"{file_id}_virustotal.json"
            with open(vt_report_path, 'w', encoding='utf-8') as f:
                json.dump(vrtt_report, f, indent=2, ensure_ascii=False)
            report_paths['virustotal'] = str(vt_report_path)
            print(f"VirusTotal report saved: {vt_report_path}")

        if mob_response:
            mobsf_report_path = REPORT_DIR / f"{file_id}_mobsf.json"
            with open(mobsf_report_path, 'w', encoding='utf-8') as f:
                json.dump(mob_response, f, indent=2, ensure_ascii=False)
            report_paths['mobsf'] = str(mobsf_report_path)
            print(f"MobSF report saved: {mobsf_report_path}")

        # สร้าง combined report
        clean_vt = clean_virustotal_report(vrtt_report)
        clean_mobsf = clean_mobsf_report(mob_response)
        user_selected_report = {
            "virustotal": vrtt_report,
            "mobsf": mob_response,
            "cape_sandbox": None
        }

        # วิเคราะห์ด้วย Gemini
        response = GeminiAPI().AnalysisGemini(user_selected_report)
        print(response)

        # บันทึก Gemini analysis report
        gemini_report_path = REPORT_DIR / f"{file_id}_gemini_analysis.json"
        with open(gemini_report_path, 'w', encoding='utf-8') as df:
            df.write(response)
        report_paths['gemini_analysis'] = str(gemini_report_path)
        print(f"Gemini analysis saved: {gemini_report_path}")

        # บันทึก combined report (รวมทุกอย่าง)
        combined_report_path = REPORT_DIR / f"{file_id}_combined.json"
        combined_data = {
            "file_info": {
                "file_id": file_id,
                "filename": file.filename,
                "file_path": str(file_path),
                "size_bytes": total_size,
                "upload_timestamp": str(uuid.uuid1().time)
            },
            "reports": {
                "virustotal": vrtt_report,
                "mobsf": mob_response,
                "gemini_analysis": response
            },
            "warnings": warnings if warnings else None,
            "report_paths": report_paths
        }
        with open(combined_report_path, 'w', encoding='utf-8') as f:
            json.dump(combined_data, f, indent=2, ensure_ascii=False)
        report_paths['combined'] = str(combined_report_path)
        print(f"Combined report saved: {combined_report_path}")

        return {
            "success": True,
            "file_id": file_id,
            "filename": file.filename,
            "file_path": str(file_path),
            "size_bytes": total_size,
            "response": response,
            "virustotal": vrtt_report,
            "mobsf": mob_response,
            "warnings": warnings if warnings else None,
            "report_paths": report_paths
        }

    except HTTPException:
        raise
    except Exception as e:
        if file_path.exists():
            os.remove(file_path)
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")

@app.post('/api/test')
async def test(file: UploadFile = File(...)):
    try:
        # อ่านข้อมูลจากไฟล์ JSON ที่อัพโหลด
        content = await file.read()
        json_data = json.loads(content.decode('utf-8'))

        # ส่งข้อมูล JSON เข้าไปที่ GeminiAPI
        user_selected_report = {
            "virustotal": None,
            "mobsf": json_data,
            "cape_sandbox": None
        }
        response = GeminiAPI().AnalysisGemini(user_selected_report)
        print(response)
        with open("report.json",'w',encoding="utf-") as df:
            df.write(response)
            df.close()
        return {"res": response}

    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON file")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing file: {str(e)}")

if __name__=="__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8006, reload=True)
