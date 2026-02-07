from datetime import datetime
import os
from pathlib import Path
from fastapi import UploadFile, HTTPException
from bgProcessing.tasks import analyze_malware_task
from cores.posrgrass import SessionLocal, User
from services.analy_service import create_file, get_file_by_hash
from utils.calculate_hash import calculate_file_hashes, calculate_hash_from_chunks
import os
import aiofiles
from pathlib import Path
from cores.redis import redis_client
from sqlalchemy import select

UPLOAD_DIR = Path("temps_files")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

MAX_FILE_SIZE = 1 * 1024 * 1024 * 1024  # 1GB
CHUNK_SIZE = 1024 * 1024
VIRUSTOTAL_MAX_SIZE = 32 * 1024 * 1024

MOBSF_SUPPORTED_EXTENSIONS = ['.apk', '.xapk', '.ipa', '.appx']
CAPE_SUPPORTED_EXTENSIONS = ['.exe', '.dll', '.bin', '.msi', '.scr', '.com', '.bat', '.cmd', '.vbs', '.jar',]
VT_SUPPORTED_EXTENSIONS = ['.zip']


def decode_redis_data(data):
    if not data:
        return None
    return {k.decode('utf-8'): v.decode('utf-8') for k, v in data.items()}

def get_file_info_from_redis(sha256_hash):
    try:
        redis_key = f"file:{sha256_hash}"
        raw_data = redis_client.hgetall(redis_key)
        return raw_data
    except Exception as e:
        print(f"Redis error when getting file info: {e}")
        return None

def save_file_info_to_redis(sha256_hash, file_path, original_filename, file_hashes, file_size, file_extension):
    try:
        redis_key = f"file:{sha256_hash}"
        upload_time = datetime.now().isoformat()

        redis_client.hset(redis_key, mapping={
            'path': str(file_path),
            'original_filename': original_filename,
            'md5': file_hashes['md5'],
            'sha1': file_hashes['sha1'],
            'sha256': file_hashes['sha256'],
            'file_size': str(file_size),
            'upload_time': upload_time,
            'file_extension': file_extension
        })
        return True
    except Exception as e:
        print(f"Redis error when saving file info: {e}")
        return False

def determine_analysis_tool(file_extension):
    file_extension = file_extension.lower()
    if file_extension in MOBSF_SUPPORTED_EXTENSIONS:
        return 'mobsf'
    elif file_extension in CAPE_SUPPORTED_EXTENSIONS:
        return 'cape'
    elif file_extension in VT_SUPPORTED_EXTENSIONS:
        return 'vt'
    else:
        return 'unsupported'


async def upload_file_controller(file: UploadFile, username:str):
    # ตรวจสอบ status ผู้ใช้
    async with SessionLocal() as session:
        result = await session.execute(
            select(User).where(User.username == username)
        )
        user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=401,
            detail={
                "success": False,
                "code": "USER_NOT_FOUND",
                "message": "User not found"
            }
        )

    if user.status != "ACTIVE":
        raise HTTPException(
            status_code=403,
            detail={
                "success": False,
                "code": f"USER IS : {user.status}, USER_NOT_ACTIVE",
                "message": "User account is not active"
            }
        )
    # เริ่มตรวจสอบค่า hash ของไฟล์และกระบวนการตรวจสอบอื่นๆ
    file_path = None
    file_already_exists = False,
    
    try:
        original_filename = file.filename
        file_extension = os.path.splitext(original_filename)[1]

        # 1. Read & Chunk Logic
        chunks = []
        total_size = 0
        while chunk := await file.read(CHUNK_SIZE):
            total_size += len(chunk)
            if total_size > MAX_FILE_SIZE:
                raise HTTPException(status_code=413, detail="File size exceeds 1 GB limit")
            chunks.append(chunk)

        # 2. Hash Calculation
        sha256_hash = calculate_hash_from_chunks(chunks)

        # Check database
        async with SessionLocal() as session:
            existing_file = await get_file_by_hash(session, sha256_hash)
            if existing_file:
                print(f"existing_file ==> {existing_file.file_path}")
                file_path = Path(existing_file.file_path)
                if not file_path.exists():
                    async with aiofiles.open(file_path, 'wb') as f:
                        for chunk in chunks:
                            await f.write(chunk)
                    file_hashes = calculate_file_hashes(file_path)
                    file_already_exists = False
            else:
                file_ext = os.path.splitext(file.filename)[1]
                file_path = UPLOAD_DIR / f"{sha256_hash}{file_ext}"
                async with aiofiles.open(file_path, "wb") as f:
                    for chunk in chunks:
                        await f.write(chunk)

                # Save to database
                db_file = await create_file(
                    session,
                    file_hash=sha256_hash,
                    file_path=str(file_path),
                    file_type=file.content_type,
                    file_size=total_size
                )
                print(f"uploaded ==> {sha256_hash}{file_ext}")
        
        # 4. Determine Tool
        analysis_tool = determine_analysis_tool(file_extension)

        if analysis_tool == 'unsupported':
            if file_path.exists() and not file_already_exists:
                os.remove(file_path)
            raise HTTPException(
                status_code=400, 
                detail=f"Unsupported file type: {file_extension}. Supported: {MOBSF_SUPPORTED_EXTENSIONS + CAPE_SUPPORTED_EXTENSIONS}"
            )
        return {}

        # 5. Dispatch to Celery
        total_size = int(total_size)
        print("*"*100)
        print(str(file_path), file_hashes, total_size, analysis_tool)
        task = analyze_malware_task.delay(str(file_path), file_hashes, total_size, analysis_tool)

        return {
            "success": True,
            "file_id": sha256_hash,
            "filename": original_filename,
            "file_path": str(file_path),
            "tool": analysis_tool,
            "task_id": task.id,
            "message": "File uploaded and task queued successfully."
        }
    except HTTPException:
        raise # ปล่อยผ่านให้ FastAPI จัดการ response
    except Exception as e:
        # if isinstance(file_path, Path) and file_path.exists() and not file_already_exists:
        #     try:
        #         file_path.unlink()
        #     except Exception as cleanup_err:
        #         print("Cleanup error:", cleanup_err)

        print(f"Upload Error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal Server Error: {str(e)}"
        )

