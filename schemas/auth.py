from pydantic import BaseModel

class LoginUser(BaseModel):
    username: str
    password: str


class LoginConfirmUser(BaseModel):
    token: str
    otp: str

class AccessToken(BaseModel):
    token: str