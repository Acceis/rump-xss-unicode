Squelette de support de présentation [Marp][marp] avec un thème ACCEIS.

## Installer Marp CLI

TL;DR :

```shell
npm install -g @marp-team/marp-cli
```

Autres méthodes d'installation avec [npm ou docker](https://github.com/marp-team/marp-cli#try-it-now) ou des [gestionnaires de packages ou binaires](https://github.com/marp-team/marp-cli#install).

## Installer l'extension _Marp for VS Code_

Marp for VS Code :

- [Open VSX](https://open-vsx.org/extension/marp-team/marp-vscode) (pour code, code-oss, vscodium)
- [VSCode Marketplace](https://marketplace.visualstudio.com/items?itemName=marp-team.marp-vscode) (pour MS VSCode)

## Générer le support en PDF

```shell
marp docs/slides.md --pdf --allow-local-files --theme-set docs/themes
```

## Générer le support en HTML

```shell
marp docs/slides.md --theme-set docs/themes
```

Note : le CSS est contenu dans le HTML mais pas les images qui restent dans le dossier `assets`. Attention donc si vous voulez livrer le HTML ou le déplacer.

## Rendu du support HTML en direct

```shell
marp docs/slides.md -s -I ./docs
```

## Documentation

[La syntaxe](https://marpit.marp.app/markdown)

[marp]:https://marp.app/