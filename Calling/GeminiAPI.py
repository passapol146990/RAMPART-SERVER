import os
from dotenv import load_dotenv
from google import genai
from google.genai import types
import json
import time
import re
from google.genai.errors import ServerError, ClientError

load_dotenv()

def normalize_attributes(attributes):
    """Normalize attributes to have consistent format"""
    normalized = []
    seen_keys = {}

    for attr in attributes:
        if not attr or ":" not in attr:
            continue

        key, value = attr.split(":", 1)
        key = key.strip()
        value = value.strip()

        # Normalize volume units
        if key == "volume":
            # Remove ALL spaces and convert units
            value = re.sub(r'\s+', '', value)  # Remove all spaces
            # Convert to lowercase
            value = value.replace('ML', 'ml').replace('มล.', 'ml').replace('G', 'g')

        # Normalize PA values (remove extra spaces)
        if key == "pa":
            value = re.sub(r'PA\s+', 'PA', value)

        # Store normalized attribute
        normalized_attr = f"{key}: {value}"

        # Track unique keys to avoid duplicates
        if key not in seen_keys:
            seen_keys[key] = []

        # Add only if not duplicate
        if value not in seen_keys[key]:
            seen_keys[key].append(value)
            normalized.append(normalized_attr)

    return normalized

def extract_json(text):
    """Extract and normalize JSON from text response"""
    # Try to find JSON in code blocks (both array and object)
    pattern_array = r"```(?:json)?\s*(\[.*?\])\s*```"
    pattern_object = r"```(?:json)?\s*(\{.*?\})\s*```"

    match = re.search(pattern_array, text, re.DOTALL)
    if match:
        json_str = match.group(1)
    else:
        match = re.search(pattern_object, text, re.DOTALL)
        if match:
            json_str = match.group(1)
        elif text.strip().startswith("[") or text.strip().startswith("{"):
            json_str = text.strip()
        else:
            return None

    try:
        # Parse JSON
        data = json.loads(json_str)

        # Normalize attributes in each item
        if isinstance(data, list):
            for item in data:
                if "attributes" in item and isinstance(item["attributes"], list):
                    item["attributes"] = normalize_attributes(item["attributes"])
        elif isinstance(data, dict):
            if "attributes" in data and isinstance(data["attributes"], list):
                data["attributes"] = normalize_attributes(data["attributes"])

        # Return normalized JSON string
        return json.dumps(data, ensure_ascii=False, indent=2)
    except json.JSONDecodeError:
        # If parsing fails, return original string
        return json_str
    
def system_prompt():
    return """
Role:
คุณคือ "Malware Analyst ผู้เชี่ยวชาญ" (AI Security Auditor) ที่มีความละเอียดรอบคอบ หน้าที่ของคุณคือวิเคราะห์ JSON Report เพื่อค้นหาภัยคุกคามที่ซ่อนอยู่ (Hidden Threats) โดยเฉพาะมัลแวร์ประเภท Dropper หรือ Spyware ที่มักหลบเลี่ยงการตรวจจับเบื้องต้น

Task:
วิเคราะห์ข้อมูลจาก JSON Input (VirusTotal, MobSF, Code Behavior) แล้วสรุปผลการวิเคราะห์และความเสี่ยงในรูปแบบ JSON

**Critical Analysis Logic (ลำดับการตัดสินใจแบบเข้มข้น):**

1. **The "Hidden Payload" Rule (กฎเหล็กด่านแรก - สำคัญที่สุด):**
   - ให้ตรวจสอบฟิลด์ `code_behavior` -> `suspicious_apis` เป็นอันดับแรก
   - **RED FLAG (อันตรายทันที):** หากพบ **`api_dexloading`** (Dynamic Class Loading) แม้แต่ 1 จุด ให้ฟันธงว่า **"อันตราย (Red)"** ทันที (Score = 0-20) เพราะนี่คือพฤติกรรมของ Dropper ที่จะแอบโหลดไวรัสมาลงทีหลัง (แม้ VT จะเป็น 0 ก็ห้ามเชื่อ)
   - **RED FLAG:** หากพบ **`api_sms_call`** ในแอปที่ไม่ใช่ Messenger/SMS (เช่น แอปกล้อง, เครื่องคิดเลข) ให้ฟันธงว่า **"อันตราย (Red)"** (Score = 20-40) อาจเป็น SMS Stealer
   - **YELLOW FLAG (ต้องระวัง):** หากพบ **`api_native_code`** (Shared Library) หรือ **`api_base64_decode`** จำนวนมากในแอปทั่วไป ให้สงสัยไว้ก่อนว่ามีการซ่อนโค้ด (Obfuscation)

2. **The "Clean & Simple" Rule (กฎแอปสะอาด - ฉบับปรับปรุง):**
   - คุณจะตัดสินว่าแอปนี้ "ปลอดภัย (Green)" จากการที่มันขอ Permission น้อยๆ ได้ **ก็ต่อเมื่อแอปนั้น "สอบผ่าน" กฎข้อที่ 1 แล้วเท่านั้น**
   - หาก Permission น้อย และ **ไม่พบ** Suspicious APIs (DexLoading/NativeCode) -> ถึงจะให้ **"ปลอดภัย (Green)"** ได้จริง

3. **The "VirusTotal Reality" Rule:**
   - หาก VirusTotal ตรวจพบ > 3 เจ้า -> ยืนยันตามนั้น (Red)
   - **แต่หาก VirusTotal = 0 (Undetected):** ห้ามด่วนสรุปว่าปลอดภัย! ให้กลับไปดู Code Behavior (กฎข้อ 1) และ Permission อีกครั้ง ถ้ามี Code แปลกๆ ให้ถือว่าเป็น **Zero-Day Malware** (มัลแวร์ใหม่ล่าสุดที่แอนตี้ไวรัสยังไม่รู้จัก)

4. **The "Context Mismatch" Rule:**
   - ตรวจสอบความสมเหตุสมผลของ Permission และ API เทียบกับประเภทแอป (`category_guess`)
   - ตัวอย่าง: แอป "Flashlight" หรือ "Camera" ไม่ควรขอสิทธิ์ `READ_CONTACTS`, `SEND_SMS` หรือมี `api_sql_database` ที่ซับซ้อน

Output Format (JSON Only):
{
  "app_info": {
    "name": "ชื่อแอป",
    "category_guess": "ประเภทแอป (เดาจากชื่อ/พฤติกรรม)",
    "original_name": "ชื่อไฟล์ดั้งเดิม"
  },
  "verdict": {
    "status": "ข้อความสั้นๆ (เช่น 'อันตราย: พบพฤติกรรม Dropper' หรือ 'ปลอดภัยหายห่วง')",
    "color": "green / yellow / red",
    "score": 0-100,
    "action_text": "คำแนะนำสำหรับผู้ใช้ (เช่น 'ห้ามติดตั้งเด็ดขาด พบโค้ดโหลดมัลแวร์แฝงอยู่' หรือ 'ติดตั้งได้เลย')"
  },
  "simple_explanation": "คำอธิบายภาษามนุษย์ เข้าใจง่าย บอกเหตุผลหลักที่ให้คะแนนเท่านี้ (เช่น 'แม้แอนตี้ไวรัสจะตรวจไม่เจอ แต่ AI พบชุดคำสั่ง DexClassLoader ซึ่งมักใช้ในการแอบโหลดไวรัสเข้าเครื่องทีหลัง')",
  "warning_points": [
    "ลิสต์จุดน่าสงสัย (ภาษาไทย) เช่น 'มีการใช้ DexClassLoader เพื่อโหลดโค้ดภายนอก'",
    "แอปกล้องถ่ายรูปแต่มีการเรียกใช้ Database SMS",
    "มีการซ่อนโค้ดด้วย Base64 จำนวนมาก"
  ],
  "tool_analysis": {
    "virustotal": "สรุปผล VT (เช่น '0/76 (แต่ยังวางใจไม่ได้)')",
    "mobsf": "สรุปผล Code Analysis (เน้นสิ่งที่เจอใน code_behavior)",
    "cape": "ผล Sandbox (ถ้ามี)"
  }
}
"""

class GeminiAPICall:
    def __init__(self):
        self.api_keys = self._load_api_keys()
        
        if len(self.api_keys)<=0:
            raise Exception("No Gemini API Key found. Please set GEMINI_API_KEY1 environment variable.")
        
        self.current_key_index = 0
        self.current_model_index = 0

        self.models = [
            "gemini-2.5-flash",           # แนะนำสูงสุด - แม่นยำและเร็ว
            "gemini-2.0-flash",           # สมดุลดี
            "gemini-2.0-flash-001",       # ทางเลือกสำรอง
            # กลุ่ม Economy (เร็วแต่แม่นยำน้อยกว่า)
            "gemini-2.5-flash-lite",
            "gemini-2.0-flash-lite",
            "gemini-2.0-flash-lite-001",
        ]
        
        self.current_model_index = 0
        self.model = self.models[self.current_model_index]

        self.AI = genai.Client(api_key=self.api_keys[self.current_key_index])
        self.max_retries = 3  # จำนวนครั้งที่จะลองใหม่ต่อโมเดล
        self.retry_delay = 2  # วินาทีที่จะรอก่อนลองใหม่
        self.rate_limit_delay = 4  # วินาทีที่รอหลังแต่ละ request (15 RPM = 60/15 = 4s)

    def _load_api_keys(self):
        keys = []
        i = 1
        while True:
            key = os.getenv(f"GEMINI_API_KEY{i}")
            if key:
                keys.append(key)
                i += 1
            else:
                break
        return keys

    def _switch_model(self):
        self.current_model_index = (self.current_model_index + 1) % len(self.models)
        self.model = self.models[self.current_model_index]
        print(f"Switch Model: {self.model}")

    def _switch_api_key(self):
        self.current_key_index = self.current_key_index+1
        self.current_api_key = self.api_keys[self.current_key_index]

        if self.current_api_key is None:
            self.current_key_index = 0

        self.AI = genai.Client(api_key=self.current_api_key)

        self.current_model_index = 0
        self.model = self.models[self.current_model_index]

        print(f"Switch API Key : {self.current_key_index + 1} Start Model: {self.model}")

    def _print_usage(self, res):
        print('*'*100)
        if res.usage_metadata:
            print(f"Model: {self.model}")
            print(f"Prompt Tokens: {res.usage_metadata.prompt_token_count}")
            print(f"Candidates Tokens: {res.usage_metadata.candidates_token_count}")
            print(f"Total Tokens: {res.usage_metadata.total_token_count}")
        else:
            print("No usage metadata found.")
        print('*'*100)

    def AnalysisGemini(self, content):
        models_tried_in_current_key = 0
        keys_tried = 0
        max_keys = len(self.api_keys)

        while keys_tried < max_keys:
            retry_count = 0

            while retry_count < self.max_retries:
                try:
                    print(f"[API Key #{self.current_key_index + 1}] Use Model: {self.model} (Round {retry_count + 1}/{self.max_retries})")

                    res = self.AI.models.generate_content(
                        model=self.model,
                        contents=str(f"นี่คือข้อมูล Report ที่ต้องวิเคราะห์:{json.dumps(content)}"),
                        config=types.GenerateContentConfig(system_instruction=system_prompt()),
                    )

                    # สำเร็จ - แสดงผลและ return
                    self._print_usage(res)
                    response = extract_json(res.text)
                    print(f"Analysis successfully! By: {self.model} (API Key #{self.current_key_index + 1})")

                    time.sleep(self.rate_limit_delay)

                    return response

                except ServerError as e:
                    error_msg = str(e)
                    print(f"ServerError: {error_msg}")

                    # ตรวจสอบว่าเป็น 503 overload หรือไม่
                    if "503" in error_msg or "overloaded" in error_msg.lower():
                        retry_count += 1

                        if retry_count < self.max_retries:
                            # พยายามดึงเวลา retry ที่แนะนำจาก error message
                            retry_seconds = None
                            try:
                                match = re.search(r'retry in (\d+\.?\d*)s', error_msg)
                                if match:
                                    retry_seconds = float(match.group(1))
                            except:
                                pass

                            # ใช้ suggested delay ถ้ามี ไม่งั้นใช้ default
                            wait_time = retry_seconds if retry_seconds else (self.retry_delay * retry_count)
                            print(f"Wait {wait_time}s before retrying...")
                            time.sleep(wait_time)
                        else:
                            print(f"Model {self.model} Max round {self.max_retries}")
                            break
                    else:
                        print(f"error : {error_msg}")
                        break

                except ClientError as e:
                    error_msg = str(e)
                    print(f"ClientError: {error_msg}")

                    # ตรวจสอบว่าเป็น 429 quota exceeded หรือไม่
                    if "429" in error_msg or "RESOURCE_EXHAUSTED" in error_msg or "quota" in error_msg.lower():
                        # พยายามดึงเวลา retry จาก error message
                        retry_seconds = None
                        try:
                            match = re.search(r'retry in (\d+\.?\d*)s', error_msg)
                            if match:
                                retry_seconds = float(match.group(1))
                        except:
                            pass

                        # สลับไปใช้โมเดลอื่นทันที
                        print(f"Model {self.model} quota exceeded. Switching to next model...")
                        if retry_seconds:
                            print(f"Suggested retry delay: {retry_seconds}s")
                            # รอตาม suggested delay ก่อนสลับโมเดล (ป้องกันโมเดลใหม่โดนบล็อกทันที)
                            wait_time = min(retry_seconds, 20)  # จำกัดไม่เกิน 20 วินาที
                            print(f"Waiting {wait_time}s before switching model...")
                            time.sleep(wait_time)
                        else:
                            # ถ้าไม่มี suggested delay ให้รอ 5 วินาที
                            print(f"Waiting 5s before switching model...")
                            time.sleep(5)

                        break  # ออกจาก retry loop เพื่อสลับโมเดล
                    else:
                        # ClientError อื่นๆ ที่ไม่ใช่ quota
                        print(f"Non-quota ClientError, stopping...")
                        break

                except Exception as e:
                    print(f"Unexpected Error: {type(e).__name__}: {str(e)}")
                    retry_count += 1

                    if retry_count < self.max_retries:
                        wait_time = self.retry_delay * retry_count
                        print(f"Wait {wait_time} secound Tey again...")
                        time.sleep(wait_time)
                    else:
                        break

            # ลองโมเดลถัดไป
            models_tried_in_current_key += 1

            # ถ้าลองโมเดลทั้งหมดใน API Key ปัจจุบันแล้ว
            if models_tried_in_current_key >= len(self.models):
                keys_tried += 1

                # ถ้ายังมี API Key อื่นให้ลอง
                if keys_tried < max_keys:
                    print("="*100)
                    print(f"All models in API Key #{self.current_key_index + 1} exhausted. Switching to next API Key...")
                    print("="*100)
                    self._switch_api_key()
                    models_tried_in_current_key = 0  # รีเซ็ต counter
                else:
                    # หมด API Key แล้ว
                    break
            else:
                # ยังมีโมเดลให้ลองใน API Key ปัจจุบัน
                self._switch_model()

        # ถ้าลองทุก API Key และทุกโมเดลแล้วยังไม่สำเร็จ
        error_response = {
            "error": "All API keys and models failed",
            "reason": f"Tried {len(self.api_keys)} API key(s) with {len(self.models)} model(s) each",
            "api_keys_count": len(self.api_keys),
            "models_tried": self.models,
            "suggestion": "Please check your API keys, network connection, or try again later."
        }
        print(f"Failed all API keys and models: {json.dumps(error_response, ensure_ascii=False)}")
        return error_response
    
    def testPrompt(self, content):
        # model = "gemini-2.5-flash-lite"
        model = "gemini-2.5-flash"
        AI = genai.Client(api_key=os.getenv("GEMINI_API_KEY1"))
        content = str(f"นี่คือข้อมูล Report ที่ต้องวิเคราะห์:{json.dumps(content)}")
        token_check = AI.models.count_tokens(
            model=model,
            contents=content
        )
        print(token_check)
        res = AI.models.generate_content(
            model=model,
            contents=content,
            config=types.GenerateContentConfig(system_instruction=system_prompt()),
        )
        response = extract_json(res.text)
        return response

Gemini = None
def GeminiAPI():
    global Gemini
    if Gemini is None:
        Gemini = GeminiAPICall()
    return Gemini


# g = GeminiAPI()

# with open('z-report3-result.json', 'r', encoding='utf-8') as f:
#     data = json.load(f)
#     response = g.testPrompt(data)
#     print(f"gemini response : {response}")
#     with open('z-report4-gemini.json', 'w', encoding='utf-8') as wf:
#         response = response.replace("```json", "").replace("```", "").strip()
#         response = json.loads(response)
#         wf.write(json.dumps(response,indent=4))
#         wf.close()
#     f.close()
    