"""Build the v1.2 update ZIP accepted by the published 1.0 and 1.1 controllers."""

import argparse
import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = "zapret-rust/"
CATALOG = "package-manifest.json"


def update_name(path):
    # The older updaters recognize license documents only at the package root.
    if path.startswith("licenses/"):
        leaf = path.removeprefix("licenses/")
        if "/" in leaf or not (
            leaf in {"LICENSE", "THIRD-PARTY-NOTICES.md"}
            or (leaf.startswith("LICENSE-") and leaf.endswith(".txt"))
        ):
            raise ValueError(f"Unrecognized license document: {path}")
        return leaf
    return path


def build(source, output):
    with ZipFile(source) as package:
        catalog = json.loads(package.read(ROOT + CATALOG))
        files = catalog["files"]
        if catalog["version"] != "1.2" or "licenses/LICENSE" not in files:
            raise ValueError("Expected the grouped-license Windows 1.2 package")
        members = [ROOT + path for path in [*files, CATALOG, "runtime/.keep"]]
        actual = [entry.filename for entry in package.infolist() if not entry.is_dir()]
        if sorted(actual) != sorted(members):
            raise ValueError("Archive members differ from the package catalog")
        if package.read(ROOT + "runtime/.keep"):
            raise ValueError("Expected an empty runtime placeholder")
        renamed = {update_name(path): digest for path, digest in files.items()}
        if len(renamed) != len(files):
            raise ValueError("Conflicting license paths")
        catalog["files"] = dict(sorted(renamed.items()))
        # Refuse to overwrite the source or any prior release asset.
        with output.open("xb") as target:
            try:
                write_archive(target, package, catalog, files)
            except BaseException:
                target.close()
                output.unlink()
                raise


def write_archive(target, package, catalog, files):
    with ZipFile(target, "w", compression=ZIP_DEFLATED) as result:
        for path in files:
            result.writestr(ROOT + update_name(path), package.read(ROOT + path))
        result.writestr(ROOT + "runtime/.keep", b"")
        result.writestr(ROOT + CATALOG, json.dumps(catalog, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    build(args.source, args.output)
