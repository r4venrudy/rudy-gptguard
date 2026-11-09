"""Package a framework-dependent GPTGuard build with fixed ZIP metadata."""
from argparse import ArgumentParser
from hashlib import sha256
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = "gptguard-0.1.0-preview-portable.zip"
BINARY_FILES = ("gptguard.dll", "gptguard.deps.json", "gptguard.runtimeconfig.json")
DOC_FILES = ("LICENSE", "README.md", "assets/banner.svg", "examples/make_images.py")


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("publish", type=Path)
    parser.add_argument("dist", type=Path)
    args = parser.parse_args()

    entries = {f"bin/{name}": (args.publish / name).read_bytes() for name in BINARY_FILES}
    entries.update({name: (ROOT / name).read_bytes().replace(b"\r\n", b"\n") for name in DOC_FILES})
    args.dist.mkdir(parents=True, exist_ok=True)
    output = args.dist / BUNDLE
    with ZipFile(output, "w") as package:
        for name, content in sorted(entries.items()):
            info = ZipInfo(name, (2020, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            package.writestr(info, content, compress_type=ZIP_DEFLATED, compresslevel=9)
    digest = sha256(output.read_bytes()).hexdigest()
    (args.dist / "SHA256SUMS.txt").write_bytes(f"{digest}  {BUNDLE}\n".encode("ascii"))
    print(f"{digest}  {BUNDLE}")


if __name__ == "__main__":
    main()
