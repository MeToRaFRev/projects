# Required Libs
import requests
import json
import tkinter
import tkinter.ttk
import base64
from tkinter import filedialog
from tkinter import messagebox
# self-signed certs
import urllib3
urllib3.disable_warnings()
#read config
with open('Cred.json') as file:
    Cred = json.load(file)
with open('DPConfig.json') as DPfile:
    DPConfig = json.load(DPfile)
url = 'https://'+DPConfig['IP']+':'+DPConfig['PORT']+'/mgmt/filestore/'+DPConfig['DOMAIN']+'/local/Services/'

def Login_Pressed():
    auth = False
    #entries
    output = 'Missing Entries:'
    if loginUser.get() == '' or loginUser.get() is None:
        output = output + '\n' + 'Username'
    if loginPass.get() == '' or loginPass.get() is None:
        output = output + '\n' + 'Password'
    if output != 'Missing Entries:':
        tkinter.messagebox.showerror('Error',output)
        return
    #end of entries
    #auth
    for user in Cred['Users']:
        if loginUser.get() == user['Username'] and loginPass.get() == user['Password']:
            auth = True
            login.withdraw()
            Services_List(user)
    if auth == False:
        tkinter.messagebox.showerror('Error','Wrong Credentials')

    #end of auth
def previousWindow(currentWindow,lastWindow):
    currentWindow.withdraw()
    lastWindow.update()
    lastWindow.deiconify()

def Services_List(user):
    yGrid=0.05
    service = tkinter.Toplevel()
    service.title('File MGMT')
    service.iconbitmap(r'images/icon.ico')
    service.config(bg='snow')
    # backgroundImage = tkinter.PhotoImage(file=r'images\wood.png')
    # back = tkinter.Label(service,image=backgroundImage)
    # back.place(relx=0,rely=0,relwidth=1,relheight=1)
    service.attributes("-fullscreen", True)
    DP = tkinter.Label(service,text = 'Datapower : Offline ↓',font=('Ariel', 11),fg="red",bg='snow')
    DP.place(relx=0.5,rely=0.05,anchor='center')
    tkinter.Button(service,text = '↺',command=lambda:DPOnline(DP),bg='royalblue',activebackground='royalblue4').place(relx=0.44,rely=0.05,anchor='center')
    tkinter.Button(service,text='X',command=lambda:quit(),bg='royalblue',activebackground='royalblue4').place(relx=0.98,rely=0.05,anchor='center')
    tkinter.Button(service,text = '←',command=lambda:previousWindow(service,login),bg='royalblue',activebackground='royalblue4').place(relx=0.96,rely=0.05,anchor='center')
    DPOnline(DP)
    for srv in user['Services']:
        yGrid = yGrid + 0.05
        tkinter.Button(service, text = srv,command=lambda srv=srv:serviceSearch(srv,service),bg='royalblue',activebackground='royalblue4',relief='groove').place(relx=0.5,rely=yGrid,anchor='center')

def DPOnline(DP):
    DPOnlineURL = 'https://'+DPConfig['IP']+':'+DPConfig['PORT']+'/mgmt/status/'
    try:
        DPOnline = requests.get(DPOnlineURL,auth=(DPConfig['DPUSER'], DPConfig['DPPASS']), verify=False)
        if DPOnline.status_code == 200:
            DP.config(fg="green",font=('Ariel', 11),text = 'Datapower : Online ↑')
    except:
        DP.config(fg="red",font=('Ariel', 11),text = 'Datapower : Offline ↓')

def refreshSearch(filesWindow,srv,service):
    filesWindow.withdraw()
    serviceSearch(srv,service)

def serviceSearch(srv,service):
    jsvUrl = url+srv+'/jsv'
    service.withdraw()
    filesWindow = tkinter.Tk()
    filesWindow.attributes("-fullscreen", True)
    filesWindow.title('File MGMT')
    filesWindow.iconbitmap(r'images/icon.ico')
    filesWindow.config(bg='snow')
    tkinter.Button(filesWindow,text = 'X',command=lambda:quit(),bg='royalblue',activebackground='royalblue4').place(relx=0.98,rely=0.02)
    tkinter.Button(filesWindow,text = '←',command=lambda:previousWindow(filesWindow,service),bg='royalblue',activebackground='royalblue4').place(relx=0.96,rely=0.02)
    tkinter.Button(filesWindow,text = '↺',command=lambda:refreshSearch(filesWindow,srv,service),bg='royalblue',activebackground='royalblue4').place(relx=0.94,rely=0.02)
    getLabel = tkinter.Label(filesWindow,text='GET',bg='snow').place(relx=0.25,rely=0.025,anchor='center')
    postLabel = tkinter.Label(filesWindow,text='POST',bg='snow').place(relx=0.75,rely=0.025,anchor='center')
    verticalLine = tkinter.ttk.Separator(filesWindow,orient='vertical').place(relx=0.5, rely=0, relheight=1)
    HorizontalLine = tkinter.ttk.Separator(filesWindow).place(relx=0, rely=0.075, relwidth=1)
    getAdd = tkinter.Button(filesWindow,text = '  +  ',command=lambda:Add(jsvUrl+'/get',filesWindow,srv,service),bg='royalblue',activebackground='royalblue4',relief='groove',state='disabled')
    getAdd.place(relx=0.25,rely=0.055,anchor='center')
    postAdd = tkinter.Button(filesWindow,text = '  +  ',command=lambda:Add(jsvUrl+'/post',filesWindow,srv,service),bg='royalblue',activebackground='royalblue4',relief='groove',state='disabled')
    postAdd.place(relx=0.75,rely=0.055,anchor='center')
    getFolderResponse = requests.get(jsvUrl+'/get',auth=(DPConfig['DPUSER'], DPConfig['DPPASS']), verify=False)
    postFolderResponse = requests.get(jsvUrl+'/post',auth=(DPConfig['DPUSER'], DPConfig['DPPASS']), verify=False)
    if getFolderResponse.status_code == 200:
        getLabel = tkinter.Label(filesWindow,text='Directory Doesn\'t Exist',bg='snow').place(relx=0.25,rely=0.1,anchor='center')
        getAdd.config(state='enabled')
    if postFolderResponse.status_code == 200:
        postLabel = tkinter.Label(filesWindow,text='Directory Doesn\'t Exist',bg='snow').place(relx=0.75,rely=0.1,anchor='center')
        postAdd.config(state='enabled')
    #get folder
    getFiles = json.loads(json.dumps(json.loads(getFolderResponse.text)['filestore']['location']['file'],indent=1))
    g=0
    yGrid=0.11
    if type(getFiles) == dict:
        tkinter.Button(filesWindow, text = getFiles['name'],command=lambda:fileMenu(getFiles['name'],filesWindow,jsvUrl+'/get',srv,service),bg='royalblue',activebackground='royalblue4',relief='groove').place(relx=0.25,rely=yGrid,anchor='center')
    else:
        for file in getFiles:
            tkinter.Button(filesWindow, text = getFiles[g]['name'],command=lambda g=g:fileMenu(getFiles[g]['name'],filesWindow,jsvUrl+'/get',srv,service),bg='royalblue',activebackground='royalblue4',relief='groove').place(relx=0.25,rely=yGrid,anchor='center')
            g=g+1
            yGrid=yGrid+0.05
    #post folder
    postFiles = json.loads(json.dumps(json.loads(postFolderResponse.text)['filestore']['location']['file'],indent=1))
    p=0
    yGrid=0.11
    if type(postFiles) == dict:
        tkinter.Button(filesWindow, text = postFiles['name'],command=lambda:fileMenu(postFiles['name'],filesWindow,jsvUrl+'/post',srv,service),bg='royalblue',activebackground='royalblue4',relief='groove').place(relx=0.75,rely=yGrid,anchor='center')
    else:
        for file in postFiles:
            tkinter.Button(filesWindow, text = postFiles[p]['name'],command=lambda p=p:fileMenu(postFiles[p]['name'],filesWindow,jsvUrl+'/post',srv,service),bg='royalblue',activebackground='royalblue4',relief='groove').place(relx=0.75,rely=yGrid,anchor='center')
            p=p+1
            yGrid=yGrid+0.05

def Add(folderUrl,filesWindow,srv,service):
    filePath = tkinter.filedialog.askopenfilename(defaultextension='*',filetypes = [("All files", "*.*"),('Text file','*.txt')])
    with open (filePath, "rb") as inputFile:
        fileName = filePath.split('/')
        fileName = fileName[-1]
        fixedEncodedFile = base64.b64encode(inputFile.read()).decode('ascii')
        response = requests.post(folderUrl,json={"file": {"name":fileName,"content":fixedEncodedFile}},auth=(DPConfig['DPUSER'], DPConfig['DPPASS']), verify=False)
        if response.status_code == 201:
            tkinter.messagebox.showinfo('UPLOAD : Successful','The file '+fileName+' has been uploaded!')
            refreshSearch(filesWindow,srv,service)
        elif response.status_code == 409:
            tkinter.messagebox.showerror('UPLOAD : Error','The file '+fileName+' already exists!')
        else:
            tkinter.messagebox.showerror('UPLOAD : Error','Something went wrong!')

def fileMenu(file,filesWindow,folderUrl,srv,service):
    filesWindow.withdraw()
    fileMenuWindow = tkinter.Tk()
    fileMenuWindow.attributes("-fullscreen", True)
    fileMenuWindow.title('File MGMT')
    fileMenuWindow.iconbitmap(r'images/icon.ico')
    fileMenuWindow.config(bg='snow')
    fileUrl = folderUrl + '/' + file
    tkinter.Button(fileMenuWindow,text = 'X',command=lambda:quit(),bg='royalblue',activebackground='royalblue4').place(relx=0.98,rely=0.02)
    tkinter.Button(fileMenuWindow,text = '←',command=lambda:previousWindow(fileMenuWindow,filesWindow),bg='royalblue',activebackground='royalblue4').place(relx=0.96,rely=0.02)
    tkinter.Label(fileMenuWindow,text = "File Menu",bg='snow').place(relx=0.5,rely=0.025,anchor='center')
    tkinter.Label(fileMenuWindow,text = file,bg='snow').place(relx=0.5,rely=0.05,anchor='center')
    tkinter.Button(fileMenuWindow,text = "Download",command=lambda:Download(fileUrl),bg='royalblue',activebackground='royalblue4',relief='groove').place(relx=0.5,rely=0.1,anchor='center')
    tkinter.Button(fileMenuWindow,text = "Replace",command=lambda:Put(fileUrl),bg='royalblue',activebackground='royalblue4',relief='groove').place(relx=0.5,rely=0.15,anchor='center')
    tkinter.Button(fileMenuWindow,text = "Delete",command=lambda:Delete(fileUrl,fileMenuWindow,filesWindow,srv,service),bg='royalblue',activebackground='royalblue4',relief='groove').place(relx=0.5,rely=0.2,anchor='center')
    tkinter.Button(fileMenuWindow,text = "View",command=lambda:View(fileUrl,fileMenuWindow),bg='royalblue',activebackground='royalblue4',relief='groove').place(relx=0.5,rely=0.25,anchor='center')

def Delete(fileUrl,fileMenuWindow,filesWindow,srv,service):
    response = requests.delete(fileUrl,auth=(DPConfig['DPUSER'], DPConfig['DPPASS']), verify=False)
    if response.status_code == 200:
        tkinter.messagebox.showinfo('DELETE : Successful','The file has been deleted!')
        fileMenuWindow.withdraw()
        filesWindow.update()
        filesWindow.deiconify()
        refreshSearch(filesWindow,srv,service)
    else:
        tkinter.messagebox.showerror('DELETE : Error','Something went wrong!')

def Put(fileUrl):
    path = tkinter.filedialog.askopenfilename(defaultextension='*',filetypes = [("All files", "*.*"),('Text file','*.txt')])
    with open (path, "rb") as inputFile:
        fileName = path.split('/')
        fileName = fileName[-1]
        chosenFileName = fileUrl.split('/')
        chosenFileName = chosenFileName[-1]
        if chosenFileName != fileName:
            tkinter.messagebox.showerror('Wrong File','The chosen file isnt the same as the one being replaced!')
            return
        fixedEncodedFile = base64.b64encode(inputFile.read()).decode('ascii')
        response = requests.put(fileUrl,json={"file": {"name":fileName,"content":fixedEncodedFile}},auth=(DPConfig['DPUSER'], DPConfig['DPPASS']), verify=False)
        if response.status_code == 200:
            tkinter.messagebox.showinfo('PUT : Successful','The file '+fileName+' has been updated!')
        else:
            tkinter.messagebox.showerror('PUT : Error','Something went wrong!')

def View(fileUrl,fileMenuWindow):
    global viewToggle
    response = requests.get(fileUrl,auth=(DPConfig['DPUSER'], DPConfig['DPPASS']), verify=False)
    flatFile = base64.b64decode(json.loads(response.content)['file'])
    viewBox = tkinter.Text(fileMenuWindow,width=150,highlightbackground='black',highlightthickness=1)
    try:
        viewBox.insert('1.0',json.dumps(json.loads(flatFile),indent=1))
    except:
        viewBox.insert('1.0',(flatFile))
    viewBox.place(relx=0.5,rely=0.35,anchor='n')

def Download(fileUrl):
    folderToSave = tkinter.filedialog.askdirectory()
    response = requests.get(fileUrl,auth=(DPConfig['DPUSER'], DPConfig['DPPASS']), verify=False)
    flatFile = base64.b64decode(json.loads(response.content)['file'])
    chosenFileName = fileUrl.split('/')
    chosenFileName = chosenFileName[-1]
    fileSave = open(folderToSave+'/'+chosenFileName, 'wb')
    fileSave.write(flatFile)
    fileSave.close()
    tkinter.messagebox.showinfo('DOWNLOAD : Successful','The file '+chosenFileName+' has been downloaded to: \n'+folderToSave)


login = tkinter.Tk()
login.title('File MGMT')
login.iconbitmap(r'images/icon.ico')
login.geometry('250x125+550+300')
tkinter.Label(login, text = "Tangram's Datapower\n File Managment",bg='snow').place(relx=0.47,rely=0.15,anchor='center')
login.config(bg='snow')
tkinter.Label(login, text = "Username:",bg='snow').place(relx=0.225,rely=0.4,anchor='center')
loginUser = tkinter.Entry(login)
loginUser.focus_force()
loginUser.place(relx=0.6,rely=0.4,anchor='center')
tkinter.Label(login, text = "Password:",bg='snow').place(relx=0.225,rely=0.6,anchor='center') #'password' is placed on position 10 (row - 1 and column - 0)
loginPass = tkinter.Entry(login,relief='groove',show="*")
loginPass.place(relx=0.6,rely=0.6,anchor='center')
LoginButton = tkinter.Button(login, text = 'Connect',command=lambda: Login_Pressed(),height=1,width=25,relief='groove',bg='royalblue',activebackground='royalblue4')
LoginButton.place(relx=0.5,rely=0.825,anchor='center')
login.mainloop()
