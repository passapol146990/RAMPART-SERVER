from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import os
import aiofiles
import hashlib
from pathlib import Path
from dotenv import load_dotenv
import json
from datetime import datetime

load_dotenv()

from bgProcessing.tasks import analyze_malware_task
from celery.result import AsyncResult
from bgProcessing.celery_app import celery_app

from db.redis import redis_client

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

UPLOAD_DIR = Path("temps_files")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

MAX_FILE_SIZE = 1 * 1024 * 1024 * 1024
CHUNK_SIZE = 1024 * 1024
VIRUSTOTAL_MAX_SIZE = 32 * 1024 * 1024

MOBSF_SUPPORTED_EXTENSIONS = ['.apk', '.xapk', '.ipa', '.appx', '.zip']
CAPE_SUPPORTED_EXTENSIONS = ['.exe', '.dll', '.bin', '.msi', '.scr', '.com', '.bat', '.cmd', '.vbs', '.jar']

def calculate_file_hashes(file_path):
    """คำนวณ hash ของไฟล์ (MD5, SHA1, SHA256)"""
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()

    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b''):
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)

    return {
        'md5': md5_hash.hexdigest(),
        'sha1': sha1_hash.hexdigest(),
        'sha256': sha256_hash.hexdigest()
    }

def calculate_hash_from_chunks(chunks_data):
    """คำนวณ SHA256 hash จาก chunks ของไฟล์ที่อัปโหลด"""
    sha256_hash = hashlib.sha256()
    for chunk in chunks_data:
        sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def get_file_info_from_redis(sha256_hash):
    """ดึงข้อมูลไฟล์จาก Redis โดยใช้ SHA256 hash เป็น key"""
    try:
        redis_key = f"file:{sha256_hash}"
        file_data = redis_client.hgetall(redis_key)

        if file_data:
            return {
                'path': file_data.get('path'),
                'original_filename': file_data.get('original_filename'),
                'md5': file_data.get('md5'),
                'sha1': file_data.get('sha1'),
                'sha256': file_data.get('sha256'),
                'file_size': int(file_data.get('file_size', 0)),
                'upload_time': file_data.get('upload_time'),
                'file_extension': file_data.get('file_extension')
            }
        return None
    except Exception as e:
        print(f"Redis error when getting file info: {e}")
        return None

def save_file_info_to_redis(sha256_hash, file_path, original_filename, file_hashes, file_size, file_extension):
    """บันทึกข้อมูลไฟล์ลง Redis โดยใช้ SHA256 hash เป็น key"""
    try:
        redis_key = f"file:{sha256_hash}"
        upload_time = datetime.now().isoformat()

        redis_client.hset(redis_key, mapping={
            'path': str(file_path),
            'original_filename': original_filename,
            'md5': file_hashes['md5'],
            'sha1': file_hashes['sha1'],
            'sha256': file_hashes['sha256'],
            'file_size': file_size,
            'upload_time': upload_time,
            'file_extension': file_extension
        })

        return True
    except Exception as e:
        print(f"Redis error when saving file info: {e}")
        return False

def determine_analysis_tool(file_extension):
    """กำหนดเครื่องมือที่จะใช้วิเคราะห์ตาม extension"""
    file_extension = file_extension.lower()

    if file_extension in MOBSF_SUPPORTED_EXTENSIONS:
        return 'mobsf'
    elif file_extension in CAPE_SUPPORTED_EXTENSIONS:
        return 'cape'
    else:
        return 'unsupported'

@app.get('/')
async def root():
    return {"success":True}

@app.get('/api/task/{task_id}')
async def get_task_status(task_id: str):
    task_result = AsyncResult(task_id, app=celery_app)

    if task_result.state == 'PENDING':
        response = {
            "task_id": task_id,
            "status": "pending",
            "message": "Task is waiting to be processed"
        }
    elif task_result.state == 'STARTED':
        response = {
            "task_id": task_id,
            "status": "started",
            "message": "Task is currently being processed"
        }
    elif task_result.state == 'SUCCESS':
        response = {
            "task_id": task_id,
            "status": "success",
            "result": task_result.result,
            "message": "Task completed successfully"
        }
    elif task_result.state == 'FAILURE':
        response = {
            "task_id": task_id,
            "status": "failed",
            "error": str(task_result.info),
            "message": "Task failed"
        }
    else:
        response = {
            "task_id": task_id,
            "status": task_result.state.lower(),
            "message": f"Task state: {task_result.state}"
        }

    return response

@app.post('/api/upload')
async def uploadFile(
    file: UploadFile = File(...),
):
    file_path = None
    file_already_exists = False

    # try:
    file_extension = os.path.splitext(file.filename)[1]
    original_filename = file.filename

    chunks = []
    total_size = 0

    while chunk := await file.read(CHUNK_SIZE):
        total_size += len(chunk)

        if total_size > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=413,
                detail="File size exceeds 1 GB limit"
            )

        chunks.append(chunk)

    # คำนวณ hash จาก chunks
    sha256_hash = calculate_hash_from_chunks(chunks)

    # ตรวจสอบว่ามีไฟล์ซ้ำจาก Redis
    existing_file_info = get_file_info_from_redis(sha256_hash)

    if existing_file_info:
        # ไฟล์เคยอัปโหลดแล้ว ใช้ไฟล์เดิม
        file_already_exists = True
        file_path = Path(existing_file_info['path'])
        file_hashes = {
            'md5': existing_file_info['md5'],
            'sha1': existing_file_info['sha1'],
            'sha256': existing_file_info['sha256']
        }
        total_size = existing_file_info['file_size']

        # ตรวจสอบว่าไฟล์ยังอยู่ในระบบไฟล์หรือไม่
        if not file_path.exists():
            # ไฟล์หายไปจากระบบ ให้อัปโหลดใหม่
            file_path = UPLOAD_DIR / original_filename
            async with aiofiles.open(file_path, 'wb') as f:
                for chunk in chunks:
                    await f.write(chunk)
            file_already_exists = False

            # คำนวณ hash ใหม่เพื่อยืนยัน
            file_hashes = calculate_file_hashes(file_path)

            # อัปเดต path ใหม่ใน Redis
            save_file_info_to_redis(sha256_hash, file_path, original_filename, file_hashes, total_size, file_extension)
    else:
        # ไฟล์ใหม่ บันทึกด้วยชื่อเดิม
        file_path = UPLOAD_DIR / original_filename

        # ถ้ามีไฟล์ชื่อซ้ำในโฟลเดอร์ ให้เพิ่ม timestamp
        if file_path.exists():
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename_without_ext = os.path.splitext(original_filename)[0]
            file_path = UPLOAD_DIR / f"{filename_without_ext}_{timestamp}{file_extension}"

        async with aiofiles.open(file_path, 'wb') as f:
            for chunk in chunks:
                await f.write(chunk)

        file_already_exists = False

        # คำนวณ hash ของไฟล์ (ทั้ง MD5, SHA1, SHA256)
        file_hashes = calculate_file_hashes(file_path)

        # บันทึกข้อมูลไฟล์ลง Redis
        save_file_info_to_redis(sha256_hash, file_path, original_filename, file_hashes, total_size, file_extension)

    # กำหนดเครื่องมือที่จะใช้วิเคราะห์
    analysis_tool = determine_analysis_tool(file_extension)

    if analysis_tool == 'unsupported':
        if file_path.exists() and not file_already_exists:
            os.remove(file_path)
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type: {file_extension}. Supported types: {MOBSF_SUPPORTED_EXTENSIONS + CAPE_SUPPORTED_EXTENSIONS}"
        )

    # ส่ง task ไป Celery (ทำงานแบบ async ใน background)
    task = analyze_malware_task.delay(str(file_path), file_hashes, total_size, analysis_tool)

    return {
        "success": True,
        "file_id": sha256_hash,
        "filename": original_filename,
        "file_path": str(file_path),
        "file_size": total_size,
        "file_extension": file_extension,
        "hashes": file_hashes,
        "analysis_tool": analysis_tool,
        "virustotal_eligible": total_size <= VIRUSTOTAL_MAX_SIZE,
        "file_already_exists": file_already_exists,
        "task_id": task.id,
        "task_status": "queued",
        "message": (f"File already exists, using existing file. " if file_already_exists else f"File uploaded successfully. ") +
                    f"Task queued for analysis using {analysis_tool.upper()}" +
                    (f" and VirusTotal" if total_size <= VIRUSTOTAL_MAX_SIZE else " (VirusTotal: file too large)")
    }

    # except HTTPException:
    #     # ถ้าไฟล์เป็นไฟล์ใหม่ที่เพิ่งสร้าง ให้ลบทิ้ง
    #     print('x')
    #     if file_path and file_path.exists() and not file_already_exists:
    #         os.remove(file_path)
    #     raise
    # except Exception as e:
    #     # ถ้าไฟล์เป็นไฟล์ใหม่ที่เพิ่งสร้าง ให้ลบทิ้ง
    #     if file_path and file_path.exists() and not file_already_exists:
    #         os.remove(file_path)
    #     raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")

if __name__=="__main__":
    uvicorn.run("start_server:app", host="0.0.0.0", port=8006, reload=True)
