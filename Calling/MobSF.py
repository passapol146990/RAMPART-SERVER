import os
import requests
from dotenv import load_dotenv

load_dotenv()

class MobSFCall:
    def __init__(self):
        self.api_key = os.getenv("MOB_API_KEY")
        self.base_url = os.getenv("MOBSF_BASE_URL", "http://localhost:8000")

        if not self.api_key:
            raise ValueError("MOB_API_KEY not found in .env file")

    def _get_headers(self):
        return {
            "Authorization": self.api_key
        }

    def upload_file(self, file_path):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        url = f"{self.base_url}/api/v1/upload"
        headers = self._get_headers()

        try:
            with open(file_path, 'rb') as file:
                files = {'file': file}
                response = requests.post(url, headers=headers, files=files)

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 401:
                raise Exception(f"Unauthorized: {response.json().get('error', 'Invalid API key')}")
            else:
                error_msg = response.json().get('error', 'Unknown error')
                raise Exception(f"Error {response.status_code}: {error_msg}")

        except requests.exceptions.RequestException as e:
            raise Exception(f"Request failed: {str(e)}")

    def generate_json_report(self, file_hash):
        url = f"{self.base_url}/api/v1/report_json"
        headers = self._get_headers()
        data = {'hash': file_hash}

        try:
            response = requests.post(url, headers=headers, data=data)

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 401:
                raise Exception(f"Unauthorized: {response.json().get('error', 'Invalid API key')}")
            else:
                error_msg = response.json().get('error', 'Unknown error')
                raise Exception(f"Error {response.status_code}: {error_msg}")

        except requests.exceptions.RequestException as e:
            raise Exception(f"Request failed: {str(e)}")

    def scan_file(self, file_path):
        print(f"Uploading file: {file_path}")
        upload_result = self.upload_file(file_path)

        print(f"File uploaded successfully. Hash: {upload_result['hash']}")
        print(f"Generating JSON report...")

        report = self.generate_json_report(upload_result['hash'])

        print(f"Report generated successfully!")
        return report



Mobsf = None
def MobSF():
    global Mobsf
    if Mobsf is None:
        Mobsf = MobSFCall()
    return Mobsf