from calling.GeminiAPI import GeminiAPI
# import os
import json
from utils.clearn_report import clean_mobsf_report

# json_files = [f for f in os.listdir(folder) if f.endswith(".json")]
# file = json_files[1]
# print(f"Select report : ",file)
# print('*'*100)



def LLM(file):
    user_selected_report = {
        "virustotal": None,
        "mobsf": None,
        "cape_sandbox": None
    }
    with open(f"{file}", 'r', encoding="utf-8") as rf:
        jsonf = json.loads(rf.read())
        print(f"Mosb Report : {jsonf}")
        print('*'*100)
        user_selected_report["mobsf"] = json.dumps(clean_mobsf_report(jsonf))
        rf.close()
    # with open(f"{file}", 'r', encoding="utf-8") as rf:
    #     jsonf = json.loads(rf.read())
    #     print(f"VirusTotal Report : {jsonf}")
    #     print('*'*100)
    #     user_selected_report["virustotal"] = json.dumps(jsonf)
    #     rf.close()


    response = GeminiAPI().AnalysisGemini(user_selected_report)
    print(f"gemini response : {response}")
    if isinstance(response, str):
        clean_str = response.replace("```json", "").replace("```", "").strip()
        try:
            data_to_save = json.loads(clean_str)
        except json.JSONDecodeError:
            print("Warning: Response ไม่ใช่ JSON ที่สมบูรณ์ บันทึกเป็น Text ธรรมดาแทน")
            data_to_save = response
    else:
        data_to_save = response
    try:
        with open('report_llm.json', 'w', encoding='utf-8') as f:
            json.dump(
                data_to_save, 
                f, 
                ensure_ascii=False, 
                indent=4           
            )
        print("success")
    except Exception as e:
        print(f"Error : {e}")

fileName = "Killer Sudoku-mob.json"
LLM(fileName)




