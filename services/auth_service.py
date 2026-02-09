from utils.jwt import decode_token, get_token_type, get_token_subject

def verify_access_token(token: str) -> str:
    payload = decode_token(token)

    if get_token_type(payload) != "access":
        raise ValueError("Invalid token type")

    uid = get_token_subject(payload)
    if not uid:
        raise ValueError("Invalid token payload")

    return uid
