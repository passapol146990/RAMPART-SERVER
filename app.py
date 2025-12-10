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

MAX_FILE_SIZE = 1 * 1024 * 1024 * 1024
CHUNK_SIZE = 1024 * 1024

@app.get('/')
async def root():
    return {"success":True}

@app.post('/api/upload')
async def uploadFile(
    file: UploadFile = File(...),
    accesstoken: str = Form(None),
    virustotal: str = Form(True),
    mobsf: str = Form(False),
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
        vrtt_report = None
        mob_response = None
        if virustotal:
            vrtt = VirusTotal()
            vrtt_upload = vrtt.upload_file(file_path)
            vrtt_report = vrtt.get_report(vrtt_upload["data"]['id'])
        if mobsf:
            mob = MobSF()
            mob_response = mob.scan_file(file_path)
        
        return {
            "virustotal":vrtt_report,
            "mobsf":mob_response,
            "success": True,
            "file_id": file_id,
            "filename": file.filename,
            "file_path": str(file_path),
            "size_bytes": total_size
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
