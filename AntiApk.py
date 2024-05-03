import vt
from hashlib import sha256
from apkutils import APK
import shutil
import os
import subprocess
from androguard import misc
import tkinter
import tkinter.filedialog
import json
import re



m = tkinter.Tk()
m.geometry("750x500")
m.configure(bg="#212121")

global count
count = 0
def analyzeFile():
    #Gets Hash of APK file


    h256 = sha256()
    file = tkinter.filedialog.askopenfilename()
    openfile = open(file,"rb")
    h256.update(openfile.read())
    hashIs = h256.hexdigest()


    a, d, dx = misc.AnalyzeAPK(file)

    activities = a.get_activities()
    permissions = a.get_permissions()


    print("Activities:")
    for activ in activities:
        print(activ)

    riskValue = 0
    riskChart = open("MaliciousHooks.txt","r")
    riskChartData = riskChart.readlines()

    riskPerms = ""

    print("Permissions:")
    for perm in permissions:
        print(perm)
        for risk in riskChartData:

            riskSplit = risk.split("\n")
            if riskSplit[0] in perm:
                riskPerms = riskPerms + "\n" + perm
                riskValue = riskValue + 20

    #Uses VirusTotal API to get a basic scan of APK
    client = vt.Client("e91ea733de870c7f278eed81e94cbbd458f212e85ab581ba0fc82302a36b5564")
    file = client.get_object("/files/" + h256.hexdigest())
    client.close()


    maliciousDetect = str(file.last_analysis_stats)
    maliciousDetect = re.findall(r'\d+', maliciousDetect)


    if riskValue > 100:
        riskValue = 100


    riskFile = open("Risk.txt","w")

    riskFile.write(str(len(permissions)) + "\n")
    riskFile.write(str(maliciousDetect[0]) + "\n")
    riskFile.write(str(riskValue))

    print("Amount of perms: " + str(len(permissions)))
    print("Virus Total: " + str(maliciousDetect[0]))
    print("RiskValue: " + str(riskValue))

    riskFile.close();

    p = subprocess.run(["python", "Fuzzy.py"])

    riskFile = open("Risk.txt","r")
    riskData = riskFile.read();
    riskFile.close()

    if float(riskData) < 40:
        isMalware = "No malicious intent detected."
    elif float(riskData) < 60:
        isMalware = "Medium risk of malicious intent be cautious."
    elif float(riskData) <= 100:
        isMalware = "Highly likely to be malware take extreme caution."

    riskData = round(float(riskData), 0)
    finished = "\n\n" + "Malware Analysis\n " + "Amount of perms: " + str(len(permissions)) + "\n" + "Virus Total: " + str(maliciousDetect[0]) + "\n" + "Score: " + str(riskData) + "\n" + isMalware

    outputFile = open(hashIs + "_Log.txt","w")
    outputFile.write("Permissions: \n")
    for perm in permissions:
        outputFile.write(perm + "\n")

    outputFile.write("Potentially Malicious Permissions: ")
    outputFile.write(riskPerms + "\n")

    outputFile.write("VirusTotal Score: " + str(maliciousDetect[0]) +"\n")
    outputFile.write("Amount of Permissions: " + str(len(permissions)) + "\n")
    outputFile.write(isMalware)
    outputFile.close()

    count =+ 100
    l = tkinter.Label(m,bg="#0d0d0d",fg="white", text = finished)
    l.place(x=count,y=0)


m.title("Malware Analysis")


header = tkinter.Label(m,font=("Arial",26),fg="white",bg="#212121",text="Anti APK")
button = tkinter.Button(m, text='Upload', width=25, command=analyzeFile)
button.place(x=450,y=250)
header.place(x=470,y=200)



 
m.mainloop()

