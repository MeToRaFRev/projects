import requests
import tkinter
import json
import webbrowser
import base64
from tkinter import messagebox
from tkinter import simpledialog
from tkinter import ttk
import urllib3
import re
urllib3.disable_warnings()
#Parameters
BaseURL = 'https://192.168.104.73:5554/'
Username = 'rest-test'
Password = '123321123'
Virtual = False
#End
#DPOnline Check
try:
    isOnline = requests.get(BaseURL,verify=False,timeout=1)
except:
    Error = tkinter.messagebox.showerror('Datapower Information','Datapower : Offline')
    exit()

try:
        resp = requests.get(BaseURL+'mgmt/status/default/Hypervisor3',auth=(Username,Password),verify=False,timeout=1)
        UUID = json.loads(resp.text)['Hypervisor3']['UUID']
        Virtual=True
except:
    pass
#End
MainWindow = tkinter.Tk()
MainWindow.geometry("500x280")
MainWindow.resizable(False,False)
tabs = tkinter.ttk.Notebook(MainWindow)
#Add Tabs
systemTab = tkinter.Frame(tabs)
mgmtTab = tkinter.Frame(tabs)
dnsTab = tkinter.Frame(tabs)
ethernetTab = tkinter.Frame(tabs)
certificateTab = tkinter.Frame(tabs)
mpgwTab = tkinter.Frame(tabs)

tabs.add(systemTab, text='System')
tabs.add(mgmtTab, text='Management')
tabs.add(dnsTab, text='DNS')
tabs.add(ethernetTab, text='Ethernet')
tabs.add(certificateTab, text='Certificates')
tabs.add(mpgwTab, text='MPGW')
#End
tabs.pack(expand=1, fill='both')

def AdvStorage(Storage):
    FreeEncrypted = json.loads(Storage.text)['FilesystemStatus']['FreeEncrypted']
    TotalEncrypted = json.loads(Storage.text)['FilesystemStatus']['TotalEncrypted']
    FreeTemporary = json.loads(Storage.text)['FilesystemStatus']['FreeTemporary']
    TotalTemporary = json.loads(Storage.text)['FilesystemStatus']['TotalTemporary']
    FreeInternal = json.loads(Storage.text)['FilesystemStatus']['FreeInternal']
    TotalInternal = json.loads(Storage.text)['FilesystemStatus']['TotalInternal']
    tkinter.messagebox.showinfo('Advanced Storage','Free Encrypted: {} MB\nTotal Encrypted: {} MB\nFree Temporary: {} MB\nTotal Temporary: {} MB\nFree Internal: {} MB\nTotal Internal: {} MB'.format(FreeEncrypted,TotalEncrypted,FreeTemporary,TotalTemporary,FreeInternal,TotalInternal))

DatapowerDefault = requests.get(BaseURL+'mgmt/status/',auth=(Username,Password),verify=False,timeout=3)
if "'FirmwareVersion'" in json.loads(DatapowerDefault.text)['_links']:
    Firmware = requests.get(BaseURL+'mgmt/status/default/FirmwareVersion',auth=(Username,Password),verify=False,timeout=3)
if "'FirmwareVersion2'" in json.loads(DatapowerDefault.text)['_links']:
    Firmware = requests.get(BaseURL+'mgmt/status/default/FirmwareVersion2',auth=(Username,Password),verify=False,timeout=3)
if "FirmwareVersion3" in json.loads(DatapowerDefault.text)['_links']:
    Firmware = requests.get(BaseURL+'mgmt/status/default/FirmwareVersion3',auth=(Username,Password),verify=False,timeout=3)

VirtualData = requests.get(BaseURL+'mgmt/status/default/Hypervisor3',auth=(Username,Password),verify=False,timeout=3)
FirmwareVersion = json.loads(Firmware.text)['FirmwareVersion3']['Version']
Model = json.loads(Firmware.text)['FirmwareVersion3']['ModelType']
CPU = requests.get(BaseURL+'mgmt/status/default/CPUUsage',auth=(Username,Password),verify=False,timeout=3)
if '"CPUUsage"' in CPU.text:
    CPUUsage = json.loads(CPU.text)['CPUUsage']['tenSeconds']
else:
    CPUUsage = 'NaN'
UP = requests.get(BaseURL+'mgmt/status/default/DateTimeStatus',auth=(Username,Password),verify=False,timeout=3)
UPTime = json.loads(UP.text)['DateTimeStatus']['uptime2']
Time = json.loads(UP.text)['DateTimeStatus']['time'].split(' ')
MainWindow.title('Datapower Information Tool : {}'.format(Time[3]))
Memory = requests.get(BaseURL+'mgmt/status/default/MemoryStatus',auth=(Username,Password),verify=False,timeout=3)
if '"MemoryStatus"' in Memory.text:
    MemoryMax = int(round(json.loads(Memory.text)['MemoryStatus']['TotalMemory']/1000000, 0))
    MemoryUsed = int(round(json.loads(Memory.text)['MemoryStatus']['UsedMemory']/1000000, 0))
else:
    MemoryMax = 'NaN'
    MemoryUsed = 'NaN'

Storage = requests.get(BaseURL+'mgmt/status/default/FilesystemStatus',auth=(Username,Password),verify=False,timeout=3)
TotalEncrypted = round(json.loads(Storage.text)['FilesystemStatus']['TotalEncrypted']/1000, 2)
UsedEncrypted = round(TotalEncrypted - round(json.loads(Storage.text)['FilesystemStatus']['FreeEncrypted']/1000, 1),1)

#System Tab Start
if Virtual==False:
    Serial = json.loads(Firmware.text)['FirmwareVersion3']['Serial']
    tkinter.Label(systemTab,text='Machine: Physical').place(relx=0.01,rely=0.1,anchor='w')
    tkinter.Label(systemTab,text='Serial: {}'.format(Serial)).place(relx=0.01,rely=0.3,anchor='w')
if Virtual==True:
    UUID = json.loads(VirtualData.text)['Hypervisor3']['UUID']
    tkinter.Label(systemTab,text='Machine: Virtual').place(relx=0.01,rely=0.1,anchor='w')
    tkinter.Label(systemTab,text='UUID: {}'.format(UUID)).place(relx=0.01,rely=0.3,anchor='w')

Licensed = 'No'
LicenseCheck = requests.get(BaseURL+'mgmt/status/default/LicenseStatus',auth=(Username,Password),verify=False,timeout=3)
Checked = False
for LChecker in json.loads(LicenseCheck.text)['LicenseStatus']:
    if LChecker['Feature'] == 'IDG':
        if LChecker['Available'] == 'Yes':
            Checked = True
if Checked:
    Licensed = 'Yes'

NTP = requests.get(BaseURL+'mgmt/status/default/NTPRefreshStatus',auth=(Username,Password),verify=False,timeout=3)
if '"NTPRefreshStatus"' in NTP.text:
    NTPRefresh = json.loads(NTP.text)['NTPRefreshStatus']['LastRefreshIndex']
else:
    NTPRefresh = 'NaN'


tkinter.Label(systemTab,text='Firmware: {}'.format(FirmwareVersion)).place(relx=0.01,rely=0.2,anchor='w')
tkinter.Label(systemTab,text='Model: {}'.format(Model)).place(relx=0.01,rely=0.4,anchor='w')
tkinter.Label(systemTab,text='UP-Time: {}'.format(UPTime)).place(relx=0.01,rely=0.5,anchor='w')
tkinter.Label(systemTab,text='Memory: {}/{} GB'.format(MemoryUsed,MemoryMax)).place(relx=0.01,rely=0.6,anchor='w')
tkinter.Label(systemTab,text='CPU: {}%'.format(CPUUsage)).place(relx=0.01,rely=0.7,anchor='w')
tkinter.Button(systemTab,text='Storage: {}/{} GB'.format(UsedEncrypted,TotalEncrypted),relief='flat',command=lambda:AdvStorage(Storage)).place(relx=0.01,rely=0.7,anchor='w')
tkinter.Label(systemTab,text='License: {}'.format(Licensed)).place(relx=0.01,rely=0.8,anchor='w')
tkinter.Label(systemTab,text='NTP Server: '+NTPRefresh).place(relx=0.6,rely=0.1,anchor='w')
systemTab.focus()
#System Tab End

MGMT = requests.get(BaseURL+'mgmt/status/default/ServicesStatus',auth=(Username,Password),verify=False,timeout=3)
WebGUI_IP = '';WebGUI_PORT = '';REST_IP = '';REST_PORT = '';XML_IP = '';XML_PORT = ''

#Management Tab Start
tkinter.Label(mgmtTab,text='Management Interfaces:').place(relx=0.01,rely=0.05,anchor='w')
def openGUI(IP,PORT):
    webbrowser.open_new('https://'+str(IP)+':'+str(PORT))

for i in range(3):
    tmp = json.loads(MGMT.text)['ServicesStatus'][i]['ServiceName']
    if tmp == 'web-mgmt':
        WebGUI_IP = json.loads(MGMT.text)['ServicesStatus'][i]['LocalIP']
        WebGUI_PORT = json.loads(MGMT.text)['ServicesStatus'][i]['LocalPort']
        tkinter.Button(mgmtTab,relief='flat',command=lambda:openGUI(WebGUI_IP,WebGUI_PORT),text='Web GUI: {}:{}'.format(WebGUI_IP,WebGUI_PORT)).place(relx=0.01,rely=0.15,anchor='w')
    if tmp == 'rest-mgmt':
        REST_IP = json.loads(MGMT.text)['ServicesStatus'][i]['LocalIP']
        REST_PORT = json.loads(MGMT.text)['ServicesStatus'][i]['LocalPort']
        tkinter.Button(mgmtTab,relief='flat',command=lambda:openGUI(REST_IP,REST_PORT),text='REST API: {}:{}'.format(REST_IP,REST_PORT)).place(relx=0.01,rely=0.25,anchor='w')
    if tmp == 'xml-mgmt':
        XML_IP = json.loads(MGMT.text)['ServicesStatus'][i]['LocalIP']
        XML_PORT = json.loads(MGMT.text)['ServicesStatus'][i]['LocalPort']
        tkinter.Button(mgmtTab,relief='flat',command=lambda:openGUI(XML_IP,XML_PORT),text='SOAP API: {}:{}'.format(XML_IP,XML_PORT)).place(relx=0.01,rely=0.35,anchor='w')

Users = requests.get(BaseURL+'mgmt/status/default/ActiveUsers',auth=(Username,Password),verify=False,timeout=3)
usersList = tkinter.Listbox(mgmtTab)
usersList.place(relx=0.775,rely=0.55,anchor='center',relwidth=0.45,relheight=0.9)
tkinter.Label(mgmtTab,text='Active Users').place(relx=0.775,rely=0.05,anchor='center')
if type(json.loads(Users.text)['ActiveUsers']) == list:
    for user in json.loads(Users.text)['ActiveUsers']:
        if user['name'] == '':
            usersList.insert('end','IDG : '+user['address']+' → '+user['connection'])
        else:
            usersList.insert('end',user['name']+' : '+user['address']+' → '+user['connection'])
else:
    if json.loads(Users.text)['ActiveUsers']['name'] == '':
        usersList.insert('end','IDG : '+user['address']+' → '+user['connection'])
    else:
        usersList.insert('end',json.loads(Users.text)['ActiveUsers']['name']+' : '+json.loads(Users.text)['ActiveUsers']['address']+' → '+json.loads(Users.text)['ActiveUsers']['connection'])

mgmtTab.focus()
#Management Tab End
#DNS Tab Start
def resetDnsList(dnsList):
    dnsList.config(state='normal')
    dnsList.delete('0','end')
    if "DNSCacheHostStatus4" in json.loads(DNSCacheHostStatus4.text):
        for dns in json.loads(DNSCacheHostStatus4.text)['DNSCacheHostStatus4']:
            dnsList.insert('end',dns['Hostname']+' → '+dns['IPAddress'])
    else:
        dnsList.insert('end','No DNS was found')
        dnsList.config(state='disabled')

def searchDnsList(dnsList,term):
    exist = False
    arrayOfDns = str(dnsList.get('0','end')).replace('(','').replace(')','').replace("'",'').split(',')
    dnsList.delete('0','end')
    for DNS in arrayOfDns:
        DNS = DNS.lstrip()
        if term in DNS:
            dnsList.insert('end',DNS)
            exist = True
    if not exist:
        resetDnsList(dnsList)

dnsList = tkinter.Listbox(dnsTab)
dnsList.place(relx=0.75,rely=0.55,anchor='center',relwidth=0.5,relheight=0.9)
tkinter.Label(dnsTab,text='DNS Static Hosts').place(relx=0.75,rely=0.05,anchor='center')
aliasList = tkinter.Listbox(dnsTab)
aliasList.place(relx=0.25,rely=0.675,anchor='center',relwidth=0.5)
tkinter.Label(dnsTab,text='Aliases').place(relx=0.25,rely=0.3,anchor='center')
DNSCacheHostStatus4 = requests.get(BaseURL+'mgmt/status/default/DNSCacheHostStatus4',auth=(Username,Password),verify=False,timeout=3)
DNSSearchDomainStatus = requests.get(BaseURL+'mgmt/status/default/DNSSearchDomainStatus',auth=(Username,Password),verify=False,timeout=3)
if "DNSSearchDomainStatus" in json.loads(DNSSearchDomainStatus.text):
    dnsDomain = json.loads(DNSSearchDomainStatus.text)['DNSSearchDomainStatus']['SearchDomain']
else:
    dnsDomain = 'NaN'
Aliases = requests.get(BaseURL+'mgmt/status/default/DNSStaticHostStatus',auth=(Username,Password),verify=False,timeout=3)
for alias in json.loads(Aliases.text)['DNSStaticHostStatus']:
    aliasList.insert('end',alias['Hostname']+' → '+alias['IPAddress'])

def DNSServers():
    DNSServ = requests.get(BaseURL+'mgmt/status/default/DNSNameServerStatus2',auth=(Username,Password),verify=False,timeout=3)
    DNSS = ''
    for dnsSer in json.loads(DNSServ.text)['DNSNameServerStatus2']:
        DNSS = DNSS + dnsSer['IPAddress'] +'\n'
    tkinter.messagebox.showinfo('DNS Servers',DNSS)

resetDnsList(dnsList)
searchEntry = tkinter.Entry(dnsTab)
searchEntry.place(relx=0.01,rely=0.15,anchor='w')
searchButton = tkinter.Button(dnsTab,text='Search →',command=lambda:searchDnsList(dnsList,searchEntry.get()))
searchButton.place(relx=0.25,rely=0.15,anchor='w',relheight=0.075)
resetButton = tkinter.Button(dnsTab,text='Reset',command=lambda:resetDnsList(dnsList))
resetButton.place(relx=0.375,rely=0.15,anchor='w',relheight=0.075)
tkinter.Button(dnsTab,relief='flat',command=lambda:DNSServers(),text='Domain: '+dnsDomain).place(relx=0.01,rely=0.01)
dnsTab.focus()
#DNS Tab End
#Ethernet Tab Start

def Ping():
    data = {"Ping":{"RemoteHost":""}}
    if not DNSResolve.get():
        if re.match('^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$',IP_Entry.get()):
            data['Ping']['RemoteHost'] = IP_Entry.get()
            Ping_Button.config(cursor='wait')
            resp = requests.post(BaseURL+'mgmt/actionqueue/default',json=data,auth=(Username,Password),verify=False)
            if 'Operation completed' in resp.text:
                Alert_Label.config(text='Operation Successful',fg='green')
                Ping_Button.config(cursor='arrow')
            elif 'Host unreachable' in resp.text:
                Alert_Label.config(text='Operation Failed - host unreachable',fg='red')
                Ping_Button.config(cursor='arrow')
            elif 'Failed to resolve host name' in resp.text:
                Alert_Label.config(text='Operation Failed - cant resolve Hostname',fg='red')
                Ping_Button.config(cursor='arrow')
            else:
                Alert_Label.config(text='Operation Failed',fg='red')
                Ping_Button.config(cursor='arrow')
        else:
            tkinter.messagebox.showerror('Error','IPv4 is not valid (0.0.0.0 - 255.255.255.255)')
    if DNSResolve.get():
        if re.match('^[^:\/\/]+$',IP_Entry.get()):
            data['Ping']['RemoteHost'] = IP_Entry.get()
            Ping_Button.config(cursor='wait')
            resp = requests.post(BaseURL+'mgmt/actionqueue/default',json=data,auth=(Username,Password),verify=False)
            if 'Operation completed' in resp.text:
                Alert_Label.config(text='URL has been resolved successfuly',fg='green')
                Ping_Button.config(cursor='arrow')
            elif 'Failed to resolve host name' in resp.text:
                Alert_Label.config(text='Operation Failed - cannot resolve hostname',fg='red')
                Ping_Button.config(cursor='arrow')
            else:
                Alert_Label.config(text='Operation Failed',fg='red')
                Ping_Button.config(cursor='arrow')
        else:
            tkinter.messagebox.showerror('Error','URL is not valid (must be the url only)')

def Telnet():
        data = {"TCPConnectionTest":{"RemoteHost":"","RemotePort":""}}
        if re.match('^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}:[0-9]{1,5}$',URL_Entry.get()):
            IP = URL_Entry.get().split(':')[0]
            PORT = URL_Entry.get().split(':')[1]
            data['TCPConnectionTest']['RemoteHost'] = IP
            data['TCPConnectionTest']['RemotePort'] = PORT
            Telnet_Button.config(cursor='wait')
            resp = requests.post(BaseURL+'mgmt/actionqueue/default',json=data,auth=(Username,Password),verify=False)
            if 'Operation completed' in resp.text:
                Alert_Label.config(text='Operation Successful',fg='green')
                Telnet_Button.config(cursor='arrow')
            elif 'connection refused' in resp.text:
                Alert_Label.config(text='Operation Failed - connection refused',fg='red')
                Telnet_Button.config(cursor='arrow')
            elif 'Port is out-of-range' in resp.text:
                Alert_Label.config(text='Operation Failed - Port is out-of-range',fg='red')
                Telnet_Button.config(cursor='arrow')
            else:
                Alert_Label.config(text='Operation Failed',fg='red')
                Telnet_Button.config(cursor='arrow')
        else:
            tkinter.messagebox.showerror('Error','IPv4 or port are not valid (0.0.0.0:0 - 255.255.255.255:65535)')

IP_Entry = tkinter.Entry(ethernetTab)
Ping_Button = tkinter.Button(ethernetTab,text='Ping',command=lambda:Ping())
Alert_Label = tkinter.Label(ethernetTab,text='')
DNSResolve = tkinter.BooleanVar(ethernetTab)
DNSResolve_Checkbox = tkinter.Checkbutton(ethernetTab,padx=0.1 ,text='DNS Resolve', variable = DNSResolve, onvalue = True, offvalue = False)
IP_Entry.place(relx=0.25,rely=0.6,anchor='w')
Ping_Button.place(relx=0.43,rely=0.7,anchor='w')
DNSResolve_Checkbox.place(relx=0.24,rely=0.7,anchor='w')
Alert_Label.place(relx=0.525,rely=0.9,anchor='center')

URL_Entry = tkinter.Entry(ethernetTab)
Telnet_Button = tkinter.Button(ethernetTab,text='Telnet',command=lambda:Telnet())
URL_Entry.place(relx=0.575,rely=0.6,anchor='w')
Telnet_Button.place(relx=0.735,rely=0.7,anchor='w')



interfaces = requests.get(BaseURL+'mgmt/status/default/EthernetInterfaceStatus',auth=(Username,Password),verify=False,timeout=3)
CPM = requests.get(BaseURL+'mgmt/status/default/ConnectionsAccepted',auth=(Username,Password),verify=False,timeout=3)
if '"ConnectionsAccepted"' in CPM.text:
    CPM_Param = str(json.loads(CPM.text)['ConnectionsAccepted']['oneMinute'])
else:
    CPM_Param = 'NaN'

Estab = requests.get(BaseURL+'mgmt/status/default/TCPSummary',auth=(Username,Password),verify=False,timeout=3)
ports = requests.get(BaseURL+'mgmt/status/default/TCPTable',auth=(Username,Password),verify=False,timeout=3)
IP_Label = tkinter.Label(ethernetTab,text='IP: 0.0.0.0')
IP_Label.place(relx=0.2,rely=0.05,anchor='w')
MAC_Label = tkinter.Label(ethernetTab,text='MAC: 00:00:00:00:00:00')
MAC_Label.place(relx=0.2,rely=0.15,anchor='w')
PORTS_Label = tkinter.Label(ethernetTab,text='PORTS')
PORTS_Label.place(relx=0.9,rely=0.05,anchor='w')
CPM_Label = tkinter.Label(ethernetTab,text='CPM: '+CPM_Param)
CPM_Label.place(relx=0.2,rely=0.25,anchor='w')
EstablishedConn = tkinter.Label(ethernetTab,text='Established: '+str(json.loads(Estab.text)['TCPSummary']['established']))
EstablishedConn.place(relx=0.2,rely=0.35,anchor='w')
ListeningConn = tkinter.Label(ethernetTab,text='Listening: '+str(json.loads(Estab.text)['TCPSummary']['listen']))
ListeningConn.place(relx=0.2,rely=0.45,anchor='w')

def showInfo():
    interfaceName = interfaceList.get(str(interfaceList.curselection()).replace(',','').replace('(','').replace(')',''))
    if "EthernetInterfaceStatus" in json.loads(interfaces.text):
        for interface in json.loads(interfaces.text)['EthernetInterfaceStatus']:
            if interfaceName == interface['Name']:
                IP_Label.config(text='IP: '+interface['IP'])
                MAC_Label.config(text='MAC: '+interface['MACAddress'])
    else:
        IP_Label.config(text='IP: NaN')
        MAC_Label.config(text='MAC: ')

def showPort():
    for port in json.loads(ports.text)['TCPTable']:
        portNum = portList.get(str(portList.curselection()).replace(',','').replace('(','').replace(')',''))
        if port['state'] == 'listen':
            if port['localPort'] == portNum:
                if 'HTTPSS' in port['serviceClass']:
                    tkinter.messagebox.showinfo('HTTP - '+str(portNum),'Local IP: {}\nLocal Port: {}\nRemote IP: {}\nRemote Port: {}\nDomain: {}\nService: {}'.format(port['localIP'],port['localPort'],port['remoteIP'],port['remotePort'],port['serviceDomain'],port['serviceName']))
                elif 'HTTPS' in port['serviceClass']:
                    tkinter.messagebox.showinfo('HTTPS - '+str(portNum),'Local IP: {}\nLocal Port: {}\nRemote IP: {}\nRemote Port: {}\nDomain: {}\nService: {}'.format(port['localIP'],port['localPort'],port['remoteIP'],port['remotePort'],port['serviceDomain'],port['serviceName']))
                else:
                    tkinter.messagebox.showinfo('Unknown - '+str(portNum),'Local IP: {}\nLocal Port: {}\nRemote IP: {}\nRemote Port: {}\nDomain: {}\nService: {}'.format(port['localIP'],port['localPort'],port['remoteIP'],port['remotePort'],port['serviceDomain'],port['serviceName']))

interfaceList = tkinter.Listbox(ethernetTab,selectmode='single')
interfaceList.place(relx=0.1,rely=0.45,anchor='center',relheight=0.9,relwidth=0.2)
portList = tkinter.Listbox(ethernetTab,selectmode='single')
portList.place(relx=0.95,rely=0.5,anchor='center',relheight=0.8,relwidth=0.15)
showPortButton = tkinter.Button(ethernetTab,text='Adv Info',command=lambda:showPort())
showPortButton.place(relx=0.935,rely=0.95,anchor='center',relheight=0.075,relwidth=0.1)
showInfoButton = tkinter.Button(ethernetTab,text='Show Info',command=lambda:showInfo())
showInfoButton.place(relx=0.1,rely=0.95,anchor='center',relheight=0.075)
for interface in json.loads(interfaces.text)['EthernetInterfaceStatus']:
    interfaceList.insert('end',interface['Name'])
for port in json.loads(ports.text)['TCPTable']:
    if port['state'] == 'listen':
        portList.insert('end',port['localPort'])

ethernetTab.focus()
#Ethernet Tab Stop
#Certificate Tab Start
Thumbprint_Label = tkinter.Label(certificateTab,text='Thumbprint:')
Thumbprint_Label.place(relx=0.6,rely=0.1,anchor='c')
Thumbprint_Entry = tkinter.Entry(certificateTab,state='disabled')
Thumbprint_Entry.place(relx=0.6,rely=0.175,anchor='c',relwidth=0.5)
Serial_Label = tkinter.Label(certificateTab,text='Serial:')
Serial_Label.place(relx=0.6,rely=0.25,anchor='c')
Serial_Entry = tkinter.Entry(certificateTab,state='disabled')
Serial_Entry.place(relx=0.6,rely=0.325,anchor='c',relwidth=0.5)
Issuer_Label = tkinter.Label(certificateTab,text='Issuer:')
Issuer_Label.place(relx=0.6,rely=0.4,anchor='c')
Issuer_Entry = tkinter.Entry(certificateTab,state='disabled')
Issuer_Entry.place(relx=0.6,rely=0.475,anchor='c',relwidth=0.5)
NotBefore_Label = tkinter.Label(certificateTab,text='NotBefore:')
NotBefore_Label.place(relx=0.6,rely=0.55,anchor='c')
NotBefore_Entry = tkinter.Entry(certificateTab,state='disabled')
NotBefore_Entry.place(relx=0.6,rely=0.625,anchor='c',relwidth=0.5)
NotAfter_Label = tkinter.Label(certificateTab,text='NotBefore:')
NotAfter_Label.place(relx=0.6,rely=0.7,anchor='c')
NotAfter_Entry = tkinter.Entry(certificateTab,state='disabled')
NotAfter_Entry.place(relx=0.6,rely=0.775,anchor='c',relwidth=0.5)

def viewCrt():
    ccrt = certsList.get(str(certsList.curselection()).replace(',','').replace('(','').replace(')',''))
    choosen = {"ViewCertificateDetails":{"CertificateObject": ""}}
    choosen['ViewCertificateDetails']['CertificateObject'] = ccrt
    choosen = json.dumps(json.loads(str(choosen).replace("'",'"')),indent=1)
    crt = requests.post(BaseURL+'mgmt/actionqueue/default',data=choosen,auth=(Username,Password),verify=False,timeout=3)
    cert = json.loads(crt.text)['CryptoCertificate']['CertificateDetails']
    Thumbprint_Entry.config(state='normal')
    Thumbprint_Entry.delete(0,'end')
    Thumbprint_Entry.insert('end','{}'.format(cert['fingerprint-sha1']))
    Thumbprint_Entry.config(state='readonly')
    Serial_Entry.config(state='normal')
    Serial_Entry.delete(0,'end')
    Serial_Entry.insert('end','{}'.format(cert['SerialNumber']['value']))
    Serial_Entry.config(state='readonly')
    Issuer_Entry.config(state='normal')
    Issuer_Entry.delete(0,'end')
    Issuer_Entry.insert('end','{}'.format(cert['Issuer']['value']))
    Issuer_Entry.config(state='readonly')
    NotBefore_Entry.config(state='normal')
    NotBefore_Entry.delete(0,'end')
    NotBefore_Entry.insert('end','{}'.format(cert['NotBefore']['value']))
    NotBefore_Entry.config(state='readonly')
    NotAfter_Entry.config(state='normal')
    NotAfter_Entry.delete(0,'end')
    NotAfter_Entry.insert('end','{}'.format(cert['NotAfter']['value']))
    NotAfter_Entry.config(state='readonly')


Certificate_data = requests.get(BaseURL+'mgmt/config/default/CryptoCertificate',auth=(Username,Password),verify=False,timeout=3)
certsList = tkinter.Listbox(certificateTab,selectmode='single')
certsList.place(relx=0.01,rely=0.4,anchor='w',relwidth=0.25,relheight=0.8)
for cert in json.loads(Certificate_data.text)['CryptoCertificate']:
    certsList.insert('end',cert['name'])
tkinter.Button(certificateTab,text='View Certificate',command=lambda:viewCrt()).place(relx=0.13,rely=0.9,anchor='c')

#Certificate Tab Stop
#MPGW Tab Start
def changeList(*args):
    MPGW_data = requests.get(BaseURL+'mgmt/config/{}/MultiProtocolGateway'.format(domain.get()),auth=(Username,Password),verify=False,timeout=3)
    MPGW_data = json.loads(MPGW_data.text)['MultiProtocolGateway']
    mpgwList.delete(0,'end')
    if type(MPGW_data) == list:
        for mpgw in MPGW_data:
            mpgwList.insert('end',mpgw['name'])
    if type(MPGW_data) == dict:
        mpgwList.insert('end',MPGW_data['name'])

def changeName():
    choosenMPGW = mpgwList.get(str(mpgwList.curselection()).replace(',','').replace('(','').replace(')',''))
    choosenDomain = domain.get()
    newName = tkinter.simpledialog.askstring('Name','MPGW Name:')
    if not re.match('^[a-zA-Z0-9_-]*$',newName):
        tkinter.messagebox.showerror('Error','Name of MPGW cannot have any character but english letters , numbers and _ -')
        return

    cfgFile = requests.get(BaseURL+'mgmt/filestore/{}/config/{}.cfg'.format(choosenDomain,choosenDomain),auth=(Username,Password),verify=False,timeout=3)
    cfgFile = base64.b64decode(json.loads(cfgFile.text)['file']).decode('ascii')
    if not allObjects.get():
        cfgFile = cfgFile.replace('mpgw "{}"'.format(choosenMPGW),'mpgw "{}"'.format(newName))
    if allObjects.get():
        cfgFile = cfgFile.replace('mpgw "{}"'.format(choosenMPGW),'mpgw "{}"'.format(newName))
        cfgFile = cfgFile.replace('policy-attachments "{}"'.format(choosenMPGW),'policy-attachments "{}"'.format(newName))
        cfgFile = cfgFile.replace('front-protocol {}'.format(choosenMPGW),'front-protocol {}'.format(newName))
        cfgFile = cfgFile.replace('policy-attachments {}'.format(choosenMPGW),'policy-attachments {}'.format(newName))
        cfgFile = cfgFile.replace('source-http "{}"'.format(choosenMPGW),'source-http "{}"'.format(newName))
        cfgFile = cfgFile.replace('mpgw "{}"'.format(choosenMPGW),'mpgw "{}"'.format(newName))

    cfgFile = base64.b64encode(cfgFile.encode('ascii'))
    data = {"file":{"name":"","content":""}}
    dato = {"RestartDomain":{"Domain":""}}
    dato["RestartDomain"]["Domain"] = choosenDomain
    fileName = choosenDomain+'.cfg'
    data["file"]["name"] = fileName
    data["file"]["content"] = cfgFile.decode('ascii')
    changedName = requests.put(BaseURL+'mgmt/filestore/{}/config/{}.cfg'.format(choosenDomain,choosenDomain),json=data,auth=(Username,Password),verify=False,timeout=3)
    restartDomain = requests.post(BaseURL+'mgmt/actionqueue/{}'.format(choosenDomain),json=dato,auth=(Username,Password),verify=False,timeout=3)


Domains_data = requests.get(BaseURL+'mgmt/status/default/DomainStatus',auth=(Username,Password),verify=False,timeout=3)
DomainsJSON = json.loads(Domains_data.text)['DomainStatus']
Domains = []
mpgwList = tkinter.Listbox(mpgwTab,selectmode='single')
mpgwList.place(relx=0.01,rely=0.55,anchor='w',relwidth=0.35,relheight=0.9)
for Domain in DomainsJSON:
    Domains.append(Domain['Domain'])
domain = tkinter.StringVar(mpgwTab)
domain.set("default")
Domains_List = tkinter.OptionMenu(mpgwTab,domain,*Domains)
Domains_List.place(relx=0.18,rely=0.05,anchor='c',relheight=0.1)
domain.trace('w',changeList)
allObjects = tkinter.BooleanVar(mpgwTab)
allObjects_Checkbox = tkinter.Checkbutton(mpgwTab,text='Child Objects', variable = allObjects,onvalue = True, offvalue = False)
allObjects_Checkbox.place(relx=0.55,rely=0.155,anchor='w')
changeName_Button = tkinter.Button(mpgwTab,text='Change Name',command=lambda:changeName())
changeName_Button.place(relx=0.37,rely=0.155,anchor='w')
#MPGW Tab Stop

MainWindow.mainloop()
