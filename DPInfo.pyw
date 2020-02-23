import requests
import tkinter
import json
from tkinter import messagebox
from tkinter import ttk
import urllib3
urllib3.disable_warnings()
#Parameters
BaseURL = 'https://10.24.15.250:5551/'
Username = 'aviel'
Password = 'avie1!'
#End
#DPOnline Check
try:
    isOnline = requests.get(BaseURL,verify=False,timeout=3)
except:
    Error = tkinter.messagebox.showerror('Datapower Information','Datapower : Offline')
    exit()
#End
MainWindow = tkinter.Tk()
MainWindow.title('Datapower Informative Tool')
MainWindow.geometry("500x280")
tabs = tkinter.ttk.Notebook(MainWindow)
#Add Tabs
BasicTab = tkinter.Frame(tabs)
MGMTTab = tkinter.Frame(tabs)
tabs.add(BasicTab, text='Basic')
tabs.add(MGMTTab, text='Management')
#End
tabs.pack(expand=1, fill='both')

Firmware = requests.get(BaseURL+'mgmt/status/default/FirmwareVersion3',auth=(Username,Password),verify=False,timeout=3)
FirmwareVersion = json.loads(Firmware.text)['FirmwareVersion3']['Version']
Serial = json.loads(Firmware.text)['FirmwareVersion3']['Serial']
Model = json.loads(Firmware.text)['FirmwareVersion3']['ModelType']
CPU = requests.get(BaseURL+'mgmt/status/default/CPUUsage',auth=(Username,Password),verify=False,timeout=3)
CPUUsage = json.loads(CPU.text)['CPUUsage']['tenSeconds']
UP = requests.get(BaseURL+'mgmt/status/default/DateTimeStatus',auth=(Username,Password),verify=False,timeout=3)
UPTime = json.loads(UP.text)['DateTimeStatus']['uptime2']
Memory = requests.get(BaseURL+'mgmt/status/default/MemoryStatus',auth=(Username,Password),verify=False,timeout=3)
MemoryMax = int(round(json.loads(Memory.text)['MemoryStatus']['TotalMemory']/1000000, 0))
MemoryUsed = int(round(json.loads(Memory.text)['MemoryStatus']['UsedMemory']/1000000, 0))

tkinter.Label(BasicTab,text='Firmware: {}'.format(FirmwareVersion)).place(relx=0.01,rely=0.1,anchor='w')
tkinter.Label(BasicTab,text='Serial: {}'.format(Serial)).place(relx=0.01,rely=0.2,anchor='w')
tkinter.Label(BasicTab,text='Model: {}'.format(Model)).place(relx=0.01,rely=0.3,anchor='w')
tkinter.Label(BasicTab,text='UP-Time: {}'.format(UPTime)).place(relx=0.01,rely=0.4,anchor='w')
tkinter.Label(BasicTab,text='Memory: {}/{} GB'.format(MemoryUsed,MemoryMax)).place(relx=0.01,rely=0.7,anchor='w')

MGMT = requests.get(BaseURL+'mgmt/status/default/ServicesStatus',auth=(Username,Password),verify=False,timeout=3)
for i in range(3):
    tmp = json.loads(MGMT.text)['ServicesStatus'][i]['ServiceName']
    if tmp == 'web-mgmt':
        WebGUI_IP = json.loads(MGMT.text)['ServicesStatus'][i]['LocalIP']
        WebGUI_PORT = json.loads(MGMT.text)['ServicesStatus'][i]['LocalPort']
    if tmp == 'rest-mgmt':
        REST_IP = json.loads(MGMT.text)['ServicesStatus'][i]['LocalIP']
        REST_PORT = json.loads(MGMT.text)['ServicesStatus'][i]['LocalPort']
    if tmp == 'rest-mgmt':
        XML_IP = json.loads(MGMT.text)['ServicesStatus'][1]['LocalIP']
        XML_PORT = json.loads(MGMT.text)['ServicesStatus'][1]['LocalPort']



tkinter.Label(MGMTTab,text='REST API: {}:{}'.format(REST_IP,REST_PORT)).place(relx=0.01,rely=0.1,anchor='w')
tkinter.Label(MGMTTab,text='SOAP API: {}:{}'.format(XML_IP,XML_PORT)).place(relx=0.01,rely=0.2,anchor='w')
tkinter.Label(MGMTTab,text='Web GUI: {}:{}'.format(WebGUI_IP,WebGUI_PORT)).place(relx=0.01,rely=0.3,anchor='w')

MainWindow.mainloop()
