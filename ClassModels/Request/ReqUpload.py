from pydantic import BaseModel

class ReqUpload(BaseModel):
    accesstoken: str | None = None
