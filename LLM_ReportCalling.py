from Calling.GeminiAPI import GeminiAPI
import os
import json

# json_files = [f for f in os.listdir(folder) if f.endswith(".json")]
# file = json_files[1]
# print(f"Select report : ",file)
# print('*'*100)


user_selected_report = {
    "virustotal": None,
    "mobsf": None,
    "cape_sandbox": None
}

with open("./Files/report/mobsf/re/7f1a0e43-0790-48d5-9e8a-572094cc5243_mobsf.json", 'r', encoding="utf-8") as rf:
    jsonf = json.loads(rf.read())
    print(f"Mosb Report : {jsonf}")
    print('*'*100)
    user_selected_report["mobsf"] = json.dumps(jsonf)
    rf.close()
with open("./Files/report/virustotal/re/Calculator_9.0 (827797324)_APKPure.json", 'r', encoding="utf-8") as rf:
    jsonf = json.loads(rf.read())
    print(f"VirusTotal Report : {jsonf}")
    print('*'*100)
    user_selected_report["virustotal"] = json.dumps(jsonf)
    rf.close()


# # วิเคราะห์ด้วย Gemini
response = GeminiAPI().AnalysisGemini(user_selected_report)
print(f"Gemini Analyser : {response}")