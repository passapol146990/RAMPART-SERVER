import os
import requests
from dotenv import load_dotenv
import base64
from typing import Dict, Any, List, Optional
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def deCode_base64_string(b64_string: str) -> str:
    b64_bytes = b64_string.encode("utf-8")
    decoded_bytes = base64.b64decode(b64_bytes)
    decoded_text = decoded_bytes.decode("utf-8")
    return decoded_text


class VirusToTalAPI:
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self):
        load_dotenv()

        self.api_keys = self._load_api_keys()
        if not self.api_keys:
            raise ValueError("No VirusTotal API keys found in environment variables.")

        self.current_key_index = 0
        self.session = requests.Session()
        self._update_session_headers()

        logger.info(f"Initialized VirusTotal API with {len(self.api_keys)} API key(s)")

    def _load_api_keys(self) -> List[str]:
        keys = []

        index = 1
        while True:
            key = os.getenv(f'VIRUSTOTAL_KEY{index}')
            if key:
                keys.append(key)
                index += 1
            else:
                break

        if not keys:
            single_key = os.getenv('VIRUSTOTAL_API_KEY')
            if single_key:
                keys.append(single_key)

        return keys

    def _update_session_headers(self):
        current_key = self.api_keys[self.current_key_index]
        self.session.headers.update({
            "x-apikey": current_key,
            "accept": "application/json"
        })

    def _switch_api_key(self) -> bool:
        if self.current_key_index < len(self.api_keys) - 1:
            self.current_key_index += 1
            self._update_session_headers()
            logger.warning(f"Switched to API key #{self.current_key_index + 1}")
            return True
        else:
            logger.error("No more API keys available to switch")
            return False

    def _reset_key_index(self):
        self.current_key_index = 0
        self._update_session_headers()

    def _make_request(self, method: str, url: str, max_retries: Optional[int] = None, **kwargs) -> Dict[str, Any]:
        if max_retries is None:
            max_retries = len(self.api_keys)

        last_error = None

        for _ in range(max_retries):
            try:
                response = self.session.request(method, url, **kwargs)
                response.raise_for_status()
                if self.current_key_index > 0:
                    self._reset_key_index()
                    logger.info("Request successful, reset to first API key")

                return response.json()

            except requests.exceptions.HTTPError as e:
                status_code = e.response.status_code if e.response else None

                if status_code in [429, 403]:
                    logger.warning(f"API key #{self.current_key_index + 1} hit rate limit or quota (Status: {status_code})")

                    if not self._switch_api_key():
                        last_error = e
                        break
                    continue
                else:
                    raise RuntimeError(f"HTTP Error {status_code}: {e}")

            except requests.exceptions.RequestException as e:
                logger.error(f"Request error with API key #{self.current_key_index + 1}: {e}")
                last_error = e

                if not self._switch_api_key():
                    break
                continue

        self._reset_key_index()
        raise RuntimeError(f"All API keys failed. Last error: {last_error}")

    # -----------------------------
    # Upload File and Scan
    # -----------------------------
    def upload_file(self, file_path: str) -> Dict[str, Any]:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        url = f"{self.BASE_URL}/files"

        try:
            with open(file_path, "rb") as f:
                files = {"file": (os.path.basename(file_path), f)}
                return self._make_request("POST", url, files=files)

        except Exception as e:
            raise RuntimeError(f"Error uploading file to VirusTotal: {e}")

    # -----------------------------
    # Get Report by File Hash
    # -----------------------------
    def get_report(self, base64_string: str) -> Dict[str, Any]:
        md5_and_number = deCode_base64_string(base64_string)
        file_hash = md5_and_number.split(':')[0]
        url = f"{self.BASE_URL}/files/{file_hash}"

        try:
            return self._make_request("GET", url)
        except Exception as e:
            raise RuntimeError(f"Error fetching report: {e}")

    def get_report_by_hash(self, file_hash: str) -> Dict[str, Any]:
        url = f"{self.BASE_URL}/files/{file_hash}"

        try:
            return self._make_request("GET", url)
        except Exception as e:
            raise RuntimeError(f"Error fetching report for hash {file_hash}: {e}")

virustotal = None

def VirusTotal():
    global virustotal
    if virustotal is None:
        virustotal = VirusToTalAPI()
        return virustotal
    return virustotal


# x = VirusTotal().upload_file("Files/files/W3-2067-practice#6.pdf")
# print(x["data"]['id'])
# y = VirusTotal().get_report(x["data"]['id'])
# print(y)

