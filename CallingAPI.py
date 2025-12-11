from Calling.VirusTotal import VirusTotal
import json

def virustotal():
    virustotal = VirusTotal()
    folder = "./Files/files/"
    
    file = "Calculator_9.0 (827797324)_APKPure"
    print(f"File Name : {file}.apk")
    print('*'*100)

    x = virustotal.upload_file(f"{folder}{file}.apk")
    print(x["data"]['id'])
    print('*'*100)
    y = virustotal.get_report(x["data"]['id'])
    print(y)

    with open(f"./Files/report/virustotal/{file}.json", 'w', encoding="utf-8") as wf:
        wf.write(json.dumps(y))
        wf.close()

