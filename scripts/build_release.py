#!/usr/bin/env python3
"""Build and package the supported targets using an explicit file allowlist."""
import argparse
import datetime
import hashlib
import io
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TARGETS = [(system, arch) for system in ("linux", "darwin", "windows") for arch in ("amd64", "arm64")]


def package_files():
    files = [ROOT / name for name in ("README.md", "LICENSE", "NOTICE", "THIRD_PARTY_NOTICES")]
    for folder in ("examples", "docs"):
        files.extend(p for p in (ROOT / folder).rglob("*") if p.is_file())
    return sorted(files)


def archive(path, name, binary, epoch, windows):
    entries = [(binary.name, binary.read_bytes(), 0o755)]
    entries.extend((str(p.relative_to(ROOT)).replace(os.sep, "/"), p.read_bytes(), 0o644) for p in package_files())
    if windows:
        stamp = datetime.datetime.fromtimestamp(max(epoch, 315532800), datetime.timezone.utc).timetuple()[:6]
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as output:
            for filename, data, mode in entries:
                info = zipfile.ZipInfo(name + "/" + filename, stamp)
                info.external_attr = (0o100000 | mode) << 16
                output.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED)
    else:
        # A fixed gzip timestamp and fixed tar metadata make repeated packaging
        # deterministic for the same source tree, toolchain and embedded version.
        import gzip
        with path.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as output:
                for filename, data, mode in entries:
                    info = tarfile.TarInfo(name + "/" + filename)
                    info.size, info.mode, info.mtime = len(data), mode, epoch
                    output.addfile(info, io.BytesIO(data))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", default="dist")
    args = parser.parse_args()
    if not re.fullmatch(r"v\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?", args.version):
        parser.error("version must be a v-prefixed semantic version")
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    epoch = int(subprocess.check_output(["git", "show", "-s", "--format=%ct", "HEAD"], cwd=ROOT, text=True))
    date = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    artifacts = []
    with tempfile.TemporaryDirectory(prefix="svpn-cli-release-") as temporary:
        for system, arch in TARGETS:
            binary = Path(temporary) / ("svpn-cli.exe" if system == "windows" else "svpn-cli")
            environment = dict(os.environ, GOOS=system, GOARCH=arch, CGO_ENABLED="0")
            flags = f"-s -w -X main.version={args.version} -X main.commit={revision} -X main.buildDate={date}"
            subprocess.run(["go", "build", "-buildvcs=false", "-trimpath", "-ldflags", flags, "-o", str(binary), "./cmd/svpn-cli"],
                           cwd=ROOT, env=environment, check=True)
            name = f"svpn-cli_{args.version}_{system}_{arch}"
            artifact = output / (name + (".zip" if system == "windows" else ".tar.gz"))
            archive(artifact, name, binary, epoch, system == "windows")
            artifacts.append(artifact)
            print(artifact.name, flush=True)
    checksums = "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in artifacts)
    (output / "SHA256SUMS.txt").write_text(checksums)


if __name__ == "__main__":
    main()
