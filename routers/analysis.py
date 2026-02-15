from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from controller.analysis_controller import get_analysis_report, upload_file_controller
from controller.auth_controller import login_confirm_controller
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
