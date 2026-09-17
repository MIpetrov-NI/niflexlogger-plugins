#!/usr/bin/env python3
"""Add Linux packages owning LabVIEW project dependencies to a CycloneDX SBOM."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import quote
from xml.etree import ElementTree as ET


XML_EXTENSIONS = {".lvproj", ".lvlib", ".lvclass"}
TOKEN_ROOTS = {
    "vilib": "vi.lib",
    "resource": "resource",
    "userlib": "user.lib",
    "instrlib": "instr.lib",
    "helpdir": "help",
}


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True)


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(path))


def _project_references(project: Path, labview_root: Path) -> dict[Path, Path]:
    candidates: dict[Path, Path] = {}
    pending = [project.resolve()]
    visited: set[Path] = set()

    while pending:
        source = pending.pop()
        if source in visited or source.suffix.lower() not in XML_EXTENSIONS:
            continue
        visited.add(source)
        try:
            root = ET.parse(source).getroot()
        except (OSError, ET.ParseError) as exc:
            print(f"WARNING: Could not inspect LabVIEW reference file {source}: {exc}")
            continue

        for element in root.iter():
            raw_url = element.get("URL")
            if not raw_url:
                continue
            url = raw_url.replace("\\", "/")
            token_match = re.match(r"^/?<([^>]+)>/(.+)$", url)
            if token_match:
                token = token_match.group(1).lower()
                relative = token_match.group(2)
                mapped_root = TOKEN_ROOTS.get(token)
                if mapped_root:
                    floor = _absolute(labview_root / mapped_root)
                    candidates[_absolute(floor / relative)] = floor
                continue

            if url.startswith("/"):
                absolute = _absolute(Path(url))
                if absolute.exists():
                    candidates[absolute] = absolute
                continue
            if re.match(r"^[A-Za-z]:/", url):
                continue
            referenced = (source.parent / url).resolve()
            if not referenced.exists() and url.startswith("../"):
                referenced = (source.parent / url[3:]).resolve()
            if referenced.suffix.lower() in XML_EXTENSIONS and referenced.exists():
                pending.append(referenced)

    return candidates


def _nearest_existing(path: Path, floor: Path) -> Path | None:
    current = path
    floor = _absolute(floor)
    while current != floor and floor in current.parents:
        if current.exists():
            return current
        current = current.parent
    return floor if floor.exists() else None


def _package_owners(paths: list[Path]) -> dict[str, set[str]]:
    result = _run(["dpkg-query", "-S", *[str(path) for path in paths]])
    owners: dict[str, set[str]] = {}
    for line in result.stdout.splitlines():
        if line.startswith(("diversion by ", "local diversion ")):
            continue
        if ": " not in line:
            continue
        owner_text, owned_path = line.rsplit(": ", 1)
        for owner in owner_text.split(","):
            package = owner.strip()
            if package and not re.search(r"\s", package):
                owners.setdefault(owned_path, set()).add(package)
    return owners


def _package_metadata(package: str) -> dict:
    fmt = (
        "${binary:Package}\\t${Version}\\t${Architecture}\\t${Maintainer}"
        "\\t${Homepage}\\t${binary:Synopsis}"
    )
    result = _run(["dpkg-query", "-W", f"-f={fmt}", package])
    if result.returncode != 0:
        raise RuntimeError(f"dpkg-query could not read metadata for {package}: {result.stderr.strip()}")
    records = [line for line in result.stdout.splitlines() if line.strip()]
    if len(records) != 1:
        raise RuntimeError(f"dpkg-query returned {len(records)} metadata records for {package}")
    fields = records[0].split("\t")
    if len(fields) != 6:
        raise RuntimeError(f"dpkg-query returned unexpected metadata for {package}")
    name, version, architecture, maintainer, homepage, description = fields
    return {
        "name": re.sub(r":[A-Za-z0-9_-]+$", "", name),
        "version": version,
        "architecture": architecture,
        "maintainer": maintainer,
        "homepage": homepage,
        "description": description,
    }


def _os_release() -> tuple[str, str]:
    values: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value.strip().strip('"')
    except OSError:
        pass
    return values.get("ID", "linux"), values.get("VERSION_ID", "")


def _component(meta: dict, matched_paths: list[str], distro: tuple[str, str]) -> dict:
    distro_name, distro_version = distro
    namespace = quote(distro_name, safe="")
    name = quote(meta["name"], safe="")
    version = quote(meta["version"], safe="")
    qualifiers = [f"arch={quote(meta['architecture'], safe='')}"]
    if distro_version:
        qualifiers.append(f"distro={quote(distro_name + '-' + distro_version, safe='')}")
    purl = f"pkg:deb/{namespace}/{name}@{version}?{'&'.join(qualifiers)}"
    supplier_name = re.sub(r"\s*<[^>]+>\s*$", "", meta["maintainer"]).strip()
    component = {
        "type": "library",
        "name": meta["name"],
        "version": meta["version"],
        "bom-ref": purl,
        "purl": purl,
        "properties": [
            {"name": "lvci:discovery-source", "value": "dpkg-query"},
            {"name": "lvci:package-manager", "value": "dpkg"},
            *[
                {"name": "lvci:matched-project-path", "value": path}
                for path in sorted(set(matched_paths))
            ],
        ],
    }
    if supplier_name:
        component["supplier"] = {"name": supplier_name}
    if meta["description"]:
        component["description"] = meta["description"]
    if meta["homepage"]:
        component["externalReferences"] = [{"type": "website", "url": meta["homepage"]}]
    return component


def enrich(sbom_path: Path, project: Path, labview_bin: Path) -> int:
    if not shutil_which("dpkg-query"):
        raise RuntimeError("dpkg-query is required for Linux system-package SBOM discovery")
    labview_bin = _absolute(labview_bin)
    labview_root = labview_bin.parent
    referenced = _project_references(project, labview_root)
    referenced[labview_bin] = labview_bin
    resolved_labview_bin = labview_bin.resolve()
    referenced[resolved_labview_bin] = resolved_labview_bin

    ownership_paths: dict[Path, list[Path]] = {}
    floors: dict[Path, Path] = {}
    for path, floor in referenced.items():
        owned_path = _nearest_existing(path, floor)
        if owned_path is not None:
            ownership_paths.setdefault(owned_path, []).append(path)
            floors[owned_path] = floor

    owners = _package_owners(sorted(ownership_paths))

    matched: dict[str, list[str]] = {}
    for owned_path, source_paths in ownership_paths.items():
        packages = owners.get(str(owned_path), set())
        print(
            f"  dpkg ownership: {owned_path} -> "
            f"{', '.join(sorted(packages)) if packages else '(unowned)'}"
        )
        if owned_path == floors[owned_path] and len(packages) > 1:
            print(
                f"WARNING: Skipping ambiguous package ownership for token root {owned_path}: "
                f"{', '.join(sorted(packages))}"
            )
            continue
        for package in packages:
            matched.setdefault(package, []).extend(str(path) for path in source_paths)

    document = json.loads(sbom_path.read_text(encoding="utf-8"))
    if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") != "1.5":
        raise RuntimeError("Linux dpkg enrichment requires a CycloneDX 1.5 document")
    components = document.setdefault("components", [])
    existing = {
        (str(item.get("name", "")).lower(), str(item.get("version", "")))
        for item in components
        if isinstance(item, dict)
    }
    added_refs: list[str] = []
    distro = _os_release()
    for package in sorted(matched):
        meta = _package_metadata(package)
        if (meta["name"].lower(), meta["version"]) in existing:
            continue
        item = _component(meta, matched[package], distro)
        components.append(item)
        added_refs.append(item["bom-ref"])

    root_ref = str((document.get("metadata", {}).get("component") or {}).get("bom-ref") or "")
    if root_ref and added_refs:
        dependencies = document.setdefault("dependencies", [])
        root_dependency = next(
            (item for item in dependencies if isinstance(item, dict) and item.get("ref") == root_ref),
            None,
        )
        if root_dependency is None:
            root_dependency = {"ref": root_ref}
            dependencies.append(root_dependency)
        root_dependency["dependsOn"] = sorted(set(root_dependency.get("dependsOn", []) + added_refs))

    metadata = document.setdefault("metadata", {})
    dpkg_version_line = next(iter(_run(["dpkg-query", "--version"]).stdout.splitlines()), "")
    dpkg_version = next(iter(re.findall(r"\d+(?:\.\d+)+", dpkg_version_line)), "")
    tool_component = {
        "type": "application",
        "name": "dpkg-query",
        "publisher": "Debian",
        "version": dpkg_version,
    }
    tools = metadata.get("tools")
    if isinstance(tools, list):
        if not any(isinstance(tool, dict) and tool.get("name") == "dpkg-query" for tool in tools):
            tools.append({"vendor": "Debian", "name": "dpkg-query", "version": dpkg_version})
    else:
        if not isinstance(tools, dict):
            tools = {}
            metadata["tools"] = tools
        tool_components = tools.setdefault("components", [])
        if not any(
            isinstance(tool, dict) and tool.get("name") == "dpkg-query"
            for tool in tool_components
        ):
            tool_components.append(tool_component)

    properties = document.setdefault("properties", [])
    properties[:] = [
        item
        for item in properties
        if not (
            isinstance(item, dict)
            and item.get("name") == "lvci:linux-system-package-discovery"
        )
    ]
    properties.append(
        {
            "name": "lvci:linux-system-package-discovery",
            "value": f"dpkg-query ({len(added_refs)} components)",
        }
    )

    output_mode = sbom_path.stat().st_mode & 0o777
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=sbom_path.parent, delete=False
    ) as output:
        json.dump(document, output, indent=2, ensure_ascii=False)
        output.write("\n")
        temp_name = output.name
    os.chmod(temp_name, output_mode)
    os.replace(temp_name, sbom_path)
    print(f"Linux dpkg enrichment added {len(added_refs)} project package component(s).")
    return len(added_refs)


def shutil_which(command: str) -> str | None:
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(directory) / command
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sbom", required=True, type=Path)
    parser.add_argument("--project", required=True, type=Path)
    parser.add_argument("--labview-bin", required=True, type=Path)
    args = parser.parse_args()
    enrich(args.sbom, args.project, args.labview_bin)


if __name__ == "__main__":
    main()
