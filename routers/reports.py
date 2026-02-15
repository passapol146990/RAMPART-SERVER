from fastapi import APIRouter, Request

from controller.report_controller import getAllReportsController

router = APIRouter(
    prefix="/api",
    tags=["report"]
)

@router.post('/reports')
async def getAllReports():
    page = 1
    limit = 20
    search = None
    return await getAllReportsController(page, limit, search)


# @router.get('/reports/user')



