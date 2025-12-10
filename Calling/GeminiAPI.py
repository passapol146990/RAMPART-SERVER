import os
from dotenv import load_dotenv
from google import genai
from google.genai import types
from Calling.prompt.system_promtp import system_prompt
from utils.extract_json import extract_json
import json

load_dotenv()

class GeminiAPICall:
    def __init__(self):
        self.model = "gemini-2.5-flash-lite"
        self.AI = genai.Client(api_key=os.getenv("GEMINI_API"))
    
    def AnalysisGemini(self,content):
        res = self.AI.models.generate_content(
            model=self.model,
            contents=str(f"นี่คือข้อมูล Report ที่ต้องวิเคราะห์:{json.dumps(content)}"),
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
    