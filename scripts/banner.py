"""Pixel blackletter wordmark and an original source-to-evidence path mark."""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"


def logo(size=256):
    mark = Image.new("L", (256, 256), 0)
    draw = ImageDraw.Draw(mark)
    draw.line([(48, 58), (128, 58), (128, 128), (208, 128)], fill=230, width=8)
    draw.line([(48, 198), (128, 198), (128, 128)], fill=130, width=8)
    for x, y in [(48, 58), (48, 198), (208, 128)]:
        draw.rectangle((x - 17, y - 17, x + 17, y + 17), fill=0, outline=240, width=6)
    draw.ellipse((117, 117, 139, 139), fill=240)
    return mark.resize((size, size), Image.Resampling.NEAREST)


def main():
    image = Image.new("L", (1280, 400), 0)
    draw = ImageDraw.Draw(image)
    for y in range(40, 370, 24):
        for x in range(26, 1254, 24):
            if x < 220 or x > 1060:
                shade = int(65 * abs(x - 640) / 640)
                draw.point((x, y), fill=shade)
    image.paste(logo(108), (54, 139))
    small = Image.new("L", (300, 60), 0)
    ImageDraw.Draw(small).text((150, 30), "loadpath", font=ImageFont.truetype(str(ROOT / "docs/art/UnifrakturMaguntia-Book.ttf"), 48), fill=255, anchor="mm")
    small = small.point(lambda value: 255 if value > 110 else 0).resize((900, 180), Image.Resampling.NEAREST)
    image.paste(235, (190, 54), small)
    draw = ImageDraw.Draw(image)
    mono = ImageFont.truetype(MONO, 21)
    for i, line in enumerate(("trace the loader. question the coverage.", "source → artifact → scanner · offline · SARIF")):
        draw.text((640, 271 + i * 34), line, font=mono, fill=170, anchor="mm")
    image.save(ROOT / "docs/screenshots/banner.png", optimize=True)
    logo().save(ROOT / "docs/art/logo.png", optimize=True)
    print("Wrote docs/screenshots/banner.png and docs/art/logo.png")


if __name__ == "__main__":
    main()
