from fastapi import APIRouter, Request
from controller.auth_controller import access_token_controller, login_confirm_controller, login_controller
from schemas.auth import LoginUser, LoginConfirmUser, AccessToken
from services.auth_service import verify_access_token

router = APIRouter(
    prefix="/api",
    tags=["Auth"]
)

@router.post("/login")
async def login(user: LoginUser, request: Request):
    user_agent = request.headers.get("user-agent", "")
    ip = request.client.host if request.client else "unknown"
    return await login_controller(user, user_agent, ip)


@router.post("/login/confirm")
async def login_confirm(data: LoginConfirmUser, request: Request):
    user_agent = request.headers.get("user-agent", "")
    ip = request.client.host if request.client else "unknown"
    return await login_confirm_controller(data, user_agent, ip)


@router.post("/login/access")
async def access_token(data: AccessToken):
    try:
        username = verify_access_token(data.token)
    except ValueError as e:
        return {
            "success": False,
            "message": str(e)
        }

    return await access_token_controller(username)