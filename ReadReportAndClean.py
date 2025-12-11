from utils.clearn_report import clean_mobsf_report, clean_virustotal_smart
import json
import os

def mobsf():
    folder = "./Files/report/mobsf/"
    json_files = [f for f in os.listdir(folder) if f.endswith(".json")]
    for file_path in json_files:
        with open(f"{folder}{file_path}",'r',encoding="utf-8") as rf:
            jsonf = json.loads(rf.read())
            print(f"app_name : {jsonf.get("app_name")}")
            x = clean_mobsf_report(jsonf)
            with open(f"{folder}/re/{file_path}",'w',encoding="utf-8") as re:
                re.write(json.dumps(x))
                re.close()
            rf.close()


def virustotal():
    folder = "./Files/report/virustotal/"
    json_files = [f for f in os.listdir(folder) if f.endswith(".json")]
    print(json_files)
    for file_path in json_files:
        with open(f"{folder}{file_path}",'r',encoding="utf-8") as rf:
            jsonf = json.loads(rf.read())
            print(f"app_name : {jsonf.get("data",{}).get('attributes').get('names')[0]}")
            x = clean_virustotal_smart(jsonf)
            with open(f"{folder}/re/{file_path}",'w',encoding="utf-8") as re:
                re.write(json.dumps(x))
                re.close()
            rf.close()

virustotal()
mobsf()

