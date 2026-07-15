# IPMI Desktop Manager - Icon Generation

To generate the required app icons, run from the `src-tauri` directory:

```bash
# If you have ImageMagick installed:
convert icon.svg -resize 32x32 icons/32x32.png
convert icon.svg -resize 128x128 icons/128x128.png
convert icon.svg -resize 256x256 icons/128x128@2x.png
convert icon.svg -resize 256x256 icons/icon.ico
convert icon.svg -resize 512x512 icons/icon.icns

# Or use the Tauri icon generation tool:
npx @tauri-apps/cli icon icon.svg
```

Replace `icon.svg` with your actual app icon design.
