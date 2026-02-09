from datetime import datetime
import os
from pathlib import Path
from fastapi import UploadFile, HTTPException
from bgProcessing.tasks import analyze_malware_task
from cores.async_pg_db import SessionLocal
from cores.models_class import User
from services.analy_service import get_analy_by_task_id, get_file_by_hash, get_report_by_aid, get_table_analy, get_table_uploads, insert_table_analy, insert_table_files, insert_table_uploads, touch_upload_time
from utils.calculate_hash import calculate_file_hashes, calculate_hash_from_chunks
import os
import aiofiles
from pathlib import Path
from cores.redis import redis_client
from sqlalchemy import select
from celery.result import AsyncResult
from bgProcessing.celery_app import celery_app

UPLOAD_DIR = Path("temps_files")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

MAX_FILE_SIZE = 1 * 1024 * 1024 * 1024  # 1GB
CHUNK_SIZE = 1024 * 1024
VIRUSTOTAL_MAX_SIZE = 32 * 1024 * 1024

MOBSF_SUPPORTED_EXTENSIONS = ['.apk', '.xapk', '.ipa', '.appx']
CAPE_SUPPORTED_EXTENSIONS = ['.exe', '.dll', '.bin', '.msi', '.scr', '.com', '.bat', '.cmd', '.vbs', '.jar',]


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

def determine_analysis_tool(file_extension):
    file_extension = file_extension.lower()
    if file_extension in MOBSF_SUPPORTED_EXTENSIONS:
        return 'mobsf'
    elif file_extension in CAPE_SUPPORTED_EXTENSIONS:
        return 'cape'
    else:
        return 'mobsf,cape'

async def upload_file_controller(
    file: UploadFile,
    uid: int,
    privacy: bool
):
    # =========================
    # 1. ตรวจสอบ user ด้วย uid
    # =========================
    async with SessionLocal() as session:
        user = await session.get(User, uid)

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
                    "code": "USER_NOT_ACTIVE",
                    "message": "User account is not active"
                }
            )

        # =========================
        # 2. Read & Chunk file
        # =========================
        file_path = None
        try:
            original_filename = file.filename
            file_extension = os.path.splitext(original_filename)[1]

            chunks = []
            total_size = 0
            while chunk := await file.read(CHUNK_SIZE):
                total_size += len(chunk)
                if total_size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail="File size exceeds limit"
                    )
                chunks.append(chunk)

            # =========================
            # 3. Hash calculation
            # =========================
            sha256_hash = calculate_hash_from_chunks(chunks)

            # =========================
            # 4. Check existing file
            # =========================
            existing_file = await get_file_by_hash(session, sha256_hash)

            if existing_file:
                file_path = Path(existing_file.file_path)
                if not file_path.exists():
                    async with aiofiles.open(file_path, "wb") as f:
                        for chunk in chunks:
                            await f.write(chunk)
            else:
                file_ext = os.path.splitext(original_filename)[1]
                file_path = UPLOAD_DIR / f"{sha256_hash}{file_ext}"

                async with aiofiles.open(file_path, "wb") as f:
                    for chunk in chunks:
                        await f.write(chunk)

                existing_file = await insert_table_files(
                    session=session,
                    file_hash=sha256_hash,
                    file_path=str(file_path),
                    file_type=file.content_type,
                    file_size=total_size
                )

            # =========================
            # 5. ตรวจสอบ upload ซ้ำ (ราย user)
            # =========================
            existing_upload = await get_table_uploads(
                session=session,
                uid=user.uid,
                fid=existing_file.fid,
                file_name=original_filename
            )

            if existing_upload:
                await touch_upload_time(session, existing_upload)

                analysis = await get_table_analy(session, existing_file.fid)
                if analysis:
                    return {
                        "success": True,
                        "message": "File already uploaded",
                        "file_id": sha256_hash,
                        "filename": original_filename,
                        "task_id": analysis.task_id,
                        "status": analysis.status
                    }
            else:
                await insert_table_uploads(
                    session=session,
                    uid=user.uid,
                    fid=existing_file.fid,
                    file_name=original_filename,
                    privacy=privacy
                )

            # =========================
            # 6. ตรวจสอบ analysis ซ้ำ
            # =========================
            existing_analysis = await get_table_analy(session, existing_file.fid)
            if existing_analysis:
                return {
                    "success": True,
                    "file_id": sha256_hash,
                    "filename": original_filename,
                    "file_path": str(file_path),
                    "task_id": existing_analysis.task_id,
                    "message": "Analysis already exists"
                }

            # =========================
            # 7. Dispatch Celery task
            # =========================
            analysis_tool = determine_analysis_tool(file_extension)
            file_hashes = calculate_file_hashes(file_path)

            analysis = await insert_table_analy(
                session=session,
                fid=existing_file.fid,
                platform=[analysis_tool]
            )

            task = analyze_malware_task.delay(
                analysis.aid,
                str(file_path),
                file_hashes,
                int(total_size),
                analysis_tool
            )

            return {
                "success": True,
                "file_id": sha256_hash,
                "filename": original_filename,
                "file_path": str(file_path),
                "tool": analysis_tool,
                "task_id": task.id,
                "message": "File uploaded and task queued successfully"
            }

        except HTTPException:
            raise
        except Exception as e:
            print(f"Upload Error: {e}")
            raise HTTPException(
                status_code=500,
                detail="Internal Server Error"
            )

async def get_analysis_report(uid: int, task_id: str):
    async with SessionLocal() as session:
        analysis = await get_analy_by_task_id(session, task_id)
        if not analysis:
            raise HTTPException(
                status_code=404,
                detail={
                    "success": False,
                    "code": "TASK_NOT_FOUND",
                    "message": "Analysis task not found"
                }
            )

        if analysis.status != "success":
            return {
                "success": True,
                "task_id": task_id,
                "status": analysis.status,
                "message": "Analysis is not completed yet"
            }

        report = await get_report_by_aid(session, analysis.aid)
        return {
            "success": True,
            "task_id": task_id,
            "status": analysis.status,
            "report": {
                "rid": report.rid,
                "rampart_score": float(report.rampart_score) if report.rampart_score else None,
                "package": report.package,
                "type": report.type,
                "score": float(report.score) if report.score else None,
                "risk_level": report.risk_level,
                "color": report.color,
                "recommendation": report.recommendation,
                "analysis_summary": report.analysis_summary,
                "risk_indicators": report.risk_indicators,
                "created_at": report.created_at,
            }
        }

