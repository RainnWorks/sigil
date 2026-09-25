# Image sources

The SVGs here are the sources. The PNGs in `assets/` are rendered from them with
`rsvg-convert` (`brew install librsvg`):

```sh
rsvg-convert -w 1024 -h 1024 src/icon.svg         -o icon-1024.png
rsvg-convert -w 1600            src/hero.svg      -o hero.png
rsvg-convert -w 1600            src/how-it-works.svg -o how-it-works.png
```

The macOS icon file is built from `icon-1024.png`:

```sh
mkdir Sigil.iconset
for s in 16 32 64 128 256 512 1024; do
  sips -z $s $s icon-1024.png --out Sigil.iconset/icon_${s}x${s}.png
done
iconutil -c icns Sigil.iconset -o Sigil.icns
```

`apps/mac/Sigil/App/Sigil.icns` is a copy of `assets/Sigil.icns`. Replace both
when the icon changes.

No image model drew any of this. Every mark is SVG, so the text stays spelled
correctly and the images can be remade at any size.
