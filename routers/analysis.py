from pathlib import Path
import re
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from controller.analysis_controller import get_analysis_report, upload_file_controller
from deps.auth import require_access_token
from schemas.analy import AnalysisReportRequest

router = APIRouter(
    prefix="/api",
    tags=["analy"]
)

@router.post("/analy/upload")
async def uploadFile(
    file: UploadFile = File(...), 
    uid: str = Depends(require_access_token), 
    privacy:bool = Form(False)
):
    print(uid)
    return await upload_file_controller(file, uid, privacy)

@router.post("/analy/report")
async def analyReport(
    payload: AnalysisReportRequest,
    uid: str = Depends(require_access_token),
):
    return await get_analysis_report(uid, payload.task_id)

from fastapi.responses import StreamingResponse

def iterfile(path, chunk_size: int = 1024 * 1024):  # 1MB chunk
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            yield chunk


BASE_REPORT_PATH = Path("reports").resolve()

ALLOWED_PLATFORMS = {"cape", "virustotal", "mobsf"}

# รูปแบบ: platform-md5
FILENAME_REGEX = re.compile(
    r"^(cape|virustotal|mobsf)-([a-fA-F0-9]{32})$"
)


@router.get("/analy/report/{file_name}")
async def download_report(file_name: str):

    print(file_name)
    match = FILENAME_REGEX.match(file_name)
    if not match:
        raise HTTPException(status_code=400, detail="Invalid file name format")

    platform, md5 = match.groups()

    if platform not in ALLOWED_PLATFORMS:
        raise HTTPException(status_code=400, detail="Invalid platform")
    
    file_path = (BASE_REPORT_PATH / f"{platform}-{md5}.json").resolve()
    print(file_path)

    if not str(file_path).startswith(str(BASE_REPORT_PATH)):
        raise HTTPException(status_code=403, detail="Access denied")

    if not file_path.is_file():
        raise HTTPException(status_code=404, detail="Report not found")
    
    # return StreamingResponse(
    #     iterfile(file_path),
    #     media_type="application/json",
    #     headers={
    #         "Content-Disposition": f"attachment; filename={platform}-{md5}.json"
    #     }
    # )

    return FileResponse(
        path=file_path,
        media_type="application/json",
        filename=f"{platform}-{md5}.json"
    )