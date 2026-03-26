#!/usr/bin/env python3
"""Detect local compromise artifacts from the March 2026 Apifox supply-chain attack.

The public write-ups describe a malicious JavaScript payload served to the Apifox
desktop client between 2026-03-04 and 2026-03-22. This script scans common
Apifox Electron data directories for on-disk remnants such as:

- C2 / exfiltration markers: apifox.it.com, /public/apifox-event.js, /event/0/log
- localStorage / header markers: _rl_headers, _rl_mc, af_uuid, af_os, ...
- payload markers: foxapi, collectPreInformations, collectAddInformations

A clean result only means "no local artifact was found now". It does not prove the
host was never exposed, especially if caches/logs were cleared.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Sequence, Set


ATTACK_WINDOW_START = datetime(2026, 3, 4, 0, 0, 0)
ATTACK_WINDOW_END = datetime(2026, 3, 23, 0, 0, 0)  # exclusive

DEFAULT_MAX_FILE_SIZE = 32 * 1024 * 1024
CHUNK_SIZE = 1024 * 1024

INTERESTING_PATH_PARTS = {
    "network",
    "local storage",
    "session storage",
    "indexeddb",
    "cache",
    "code cache",
    "dawncache",
    "logs",
    "log",
    "partitions",
}

INTERESTING_FILE_NAMES = {
    "network persistent state",
    "preferences",
    "local state",
    "cookies",
    "transportsecurity",
    "desktop.json",
    "extensions.js",
}

TOP_LEVEL_SUFFIXES = {
    ".json",
    ".log",
    ".ldb",
    ".sst",
    ".sqlite",
    ".db",
    ".js",
    ".txt",
}

ACTIVITY_FILE_NAMES = {
    "network persistent state",
    "preferences",
    "local state",
    "cookies",
}

REMEDIATION_STEPS = [
    "立即停用 Apifox 桌面端并在排查结束前不要再次启动。",
    "按中招处理，轮换 SSH 私钥、Git/GitLab/GitHub PAT、K8s kubeconfig/OIDC token、npm token。",
    "检查 shell 历史里出现过的密码、API Key、数据库连接串、Vault token，并逐项更换。",
    "审计服务器和跳板机登录日志，重点查看 2026-03-04 到 2026-03-22 之后是否出现异常 SSH 登录。",
    "如果命中 IOC，建议对主机做进一步内存、网络和持久化排查，而不是只删 Apifox 缓存。",
]

SOURCE_URLS = [
    "https://rce.moe/2026/03/25/apifox-supply-chain-attack-analysis/",
    "https://docs.apifox.com/doc-5220271",
]


@dataclass(frozen=True)
class Indicator:
    literal: str
    category: str
    weight: int
    description: str


INDICATORS: Sequence[Indicator] = [
    Indicator("apifox.it.com", "core", 100, "攻击者使用的 C2 域名"),
    Indicator("/public/apifox-event.js", "network", 60, "Stage-1 载荷路径"),
    Indicator("/event/0/log", "network", 50, "第一轮外泄端点"),
    Indicator("/event/2/log", "network", 50, "第二轮外泄端点"),
    Indicator("_rl_headers", "storage", 35, "恶意脚本读取的 localStorage 键"),
    Indicator("_rl_mc", "storage", 35, "恶意脚本读取的 localStorage 键"),
    Indicator("af_uuid", "header", 20, "异常 HTTP 头"),
    Indicator("af_os", "header", 15, "异常 HTTP 头"),
    Indicator("af_user", "header", 15, "异常 HTTP 头"),
    Indicator("af_name", "header", 15, "异常 HTTP 头"),
    Indicator("af_apifox_user", "header", 20, "异常 HTTP 头"),
    Indicator("af_apifox_name", "header", 20, "异常 HTTP 头"),
    Indicator("foxapi", "payload", 25, "恶意载荷中使用的 AES 盐值"),
    Indicator("scryptsync", "payload", 15, "恶意载荷中的密钥派生调用"),
    Indicator("collectpreinformations", "payload", 20, "Stage-2 函数名"),
    Indicator("collectaddinformations", "payload", 20, "Stage-2 函数名"),
    Indicator(".git-credentials", "target", 10, "被窃取的凭证文件"),
    Indicator(".zsh_history", "target", 10, "被窃取的命令历史文件"),
    Indicator(".bash_history", "target", 10, "被窃取的命令历史文件"),
    Indicator(".kube", "target", 8, "被窃取的 K8s 配置目录"),
    Indicator(".npmrc", "target", 8, "被窃取的 npm token 文件"),
    Indicator(".subversion", "target", 8, "被窃取的 SVN 凭证目录"),
    Indicator("tasklist", "target", 6, "Windows 侦察命令"),
    Indicator("ps aux", "target", 6, "Linux/macOS 侦察命令"),
]


@dataclass
class FileHit:
    path: str
    size: int
    modified: str
    indicators: List[str] = field(default_factory=list)


@dataclass
class ScanResult:
    scanned_roots: List[str]
    existing_roots: List[str]
    scanned_files: int
    skipped_large_files: int
    unreadable_files: int
    window_activity: List[str]
    unique_indicators: List[str]
    score: int
    verdict: str
    exit_code: int
    hits: List[FileHit]
    sources: List[str]


INDICATOR_BY_LITERAL: Dict[str, Indicator] = {
    indicator.literal.lower(): indicator for indicator in INDICATORS
}
MAX_PATTERN_LEN = max(len(item.literal) for item in INDICATORS)


def default_roots() -> List[Path]:
    home = Path.home()
    roots: List[Path] = []
    if os.name == "nt":
        appdata = os.environ.get("APPDATA")
        localappdata = os.environ.get("LOCALAPPDATA")
        program_files = os.environ.get("ProgramFiles")
        for value in (appdata,):
            if value:
                roots.extend(
                    [
                        Path(value) / "apifox",
                        Path(value) / "Apifox",
                    ]
                )
        for value in (localappdata,):
            if value:
                roots.extend(
                    [
                        Path(value) / "Programs" / "Apifox",
                        Path(value) / "apifox-updater",
                        Path(value) / "Apifox-updater",
                    ]
                )
        if program_files:
            roots.append(Path(program_files) / "Apifox")
    elif sys.platform == "darwin":
        roots.extend(
            [
                home / "Library" / "Application Support" / "apifox",
                home / "Library" / "Application Support" / "Apifox",
                home / "Library" / "Caches" / "apifox",
                home / "Library" / "Caches" / "Apifox",
            ]
        )
    else:
        roots.extend(
            [
                home / ".config" / "apifox",
                home / ".config" / "Apifox",
                home / ".cache" / "apifox",
                home / ".cache" / "Apifox",
            ]
        )
    return unique_paths(roots)


def unique_paths(paths: Iterable[Path]) -> List[Path]:
    seen_text: Set[str] = set()
    seen_inodes: Set[tuple[int, int]] = set()
    result: List[Path] = []
    for path in paths:
        candidate = path.expanduser()
        try:
            stat = candidate.stat()
            inode_key = (stat.st_dev, stat.st_ino)
            if inode_key in seen_inodes:
                continue
            seen_inodes.add(inode_key)
            result.append(candidate)
            continue
        except OSError:
            pass

        normalized = str(candidate.resolve(strict=False))
        if normalized not in seen_text:
            seen_text.add(normalized)
            result.append(candidate)
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="检测 2026-03 Apifox 供应链攻击本地残留痕迹。"
    )
    parser.add_argument(
        "--root",
        action="append",
        default=[],
        help="额外指定需要扫描的 Apifox 数据目录，可重复传入。",
    )
    parser.add_argument(
        "--max-file-size-mb",
        type=int,
        default=DEFAULT_MAX_FILE_SIZE // (1024 * 1024),
        help="单文件最大扫描大小，默认 32MB。",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="输出 JSON，便于接入自动化流程。",
    )
    parser.add_argument(
        "--list-default-roots",
        action="store_true",
        help="只打印当前平台默认会扫描的目录，不执行扫描。",
    )
    parser.add_argument(
        "--no-default-roots",
        action="store_true",
        help="不扫描当前平台默认目录，只扫描 --root 指定目录。",
    )
    return parser.parse_args()


def build_roots(extra_roots: Sequence[str], include_defaults: bool) -> List[Path]:
    roots: List[Path] = []
    if include_defaults:
        roots.extend(default_roots())
    roots.extend(Path(item).expanduser() for item in extra_roots)
    return unique_paths(roots)


def is_interesting_file(root: Path, path: Path) -> bool:
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = path
    rel_parts = [part.lower() for part in rel.parts]
    if path.name.lower() in INTERESTING_FILE_NAMES:
        return True
    if any(part in INTERESTING_PATH_PARTS for part in rel_parts):
        return True
    if len(rel.parts) <= 2 and path.suffix.lower() in TOP_LEVEL_SUFFIXES:
        return True
    return False


def iter_candidate_files(roots: Sequence[Path]) -> Iterator[Path]:
    for root in roots:
        if root.is_file():
            yield root
            continue
        if not root.exists() or not root.is_dir():
            continue
        for dirpath, _, filenames in os.walk(root):
            base = Path(dirpath)
            for filename in filenames:
                path = base / filename
                if is_interesting_file(root, path):
                    yield path


def search_indicators_in_file(path: Path) -> List[str]:
    found: Set[str] = set()
    overlap = MAX_PATTERN_LEN - 1
    previous = b""
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(CHUNK_SIZE)
            if not chunk:
                break
            haystack = (previous + chunk).lower()
            for literal in INDICATOR_BY_LITERAL:
                if literal.encode("utf-8") in haystack:
                    found.add(literal)
            previous = haystack[-overlap:] if overlap > 0 else b""
            if len(found) == len(INDICATOR_BY_LITERAL):
                break
    return sorted(found)


def in_attack_window(ts: float) -> bool:
    local_dt = datetime.fromtimestamp(ts)
    return ATTACK_WINDOW_START <= local_dt < ATTACK_WINDOW_END


def classify(unique_indicators: Set[str], window_activity: List[str]) -> tuple[str, int, int]:
    score = sum(INDICATOR_BY_LITERAL[item].weight for item in unique_indicators)
    if window_activity:
        score += 10

    if "apifox.it.com" in unique_indicators:
        return "高危：已命中核心 IOC，建议按中招处理", score, 2

    network_markers = {
        "/public/apifox-event.js",
        "/event/0/log",
        "/event/2/log",
    }
    storage_markers = {
        "_rl_headers",
        "_rl_mc",
    }
    payload_markers = {
        "foxapi",
        "collectpreinformations",
        "collectaddinformations",
        "scryptsync",
    }

    if (unique_indicators & network_markers) and (
        unique_indicators & storage_markers or unique_indicators & payload_markers
    ):
        return "高危：命中多项恶意载荷特征，建议按中招处理", score, 2

    if score >= 60:
        return "高危：本地残留特征较多，建议按中招处理", score, 2
    if score >= 30:
        return "中危：发现多项可疑残留，建议继续深挖并轮换高价值凭证", score, 1
    if window_activity:
        return (
            "可疑：存在 Apifox 在受影响时间窗内的本地活动，但未找到强 IOC",
            score,
            1,
        )
    if unique_indicators:
        return "低危：有少量可疑痕迹，但不足以确认中招", score, 1
    return "未发现本地 IOC", score, 0


def scan(roots: Sequence[Path], max_file_size: int) -> ScanResult:
    scanned_roots = [str(path) for path in roots]
    existing_roots = [str(path) for path in roots if path.exists()]
    scanned_files = 0
    skipped_large_files = 0
    unreadable_files = 0
    window_activity: List[str] = []
    hits: List[FileHit] = []
    unique_indicators: Set[str] = set()

    for path in iter_candidate_files(roots):
        try:
            stat = path.stat()
        except OSError:
            unreadable_files += 1
            continue

        if stat.st_size > max_file_size:
            skipped_large_files += 1
            continue

        scanned_files += 1
        indicators = []
        try:
            indicators = search_indicators_in_file(path)
        except OSError:
            unreadable_files += 1
            continue

        modified = datetime.fromtimestamp(stat.st_mtime).isoformat(sep=" ", timespec="seconds")
        path_name = path.name.lower()
        if path_name in ACTIVITY_FILE_NAMES or "logs" in {part.lower() for part in path.parts}:
            if in_attack_window(stat.st_mtime):
                window_activity.append(f"{path} (mtime {modified})")

        if indicators:
            unique_indicators.update(indicators)
            hits.append(
                FileHit(
                    path=str(path),
                    size=stat.st_size,
                    modified=modified,
                    indicators=indicators,
                )
            )

    verdict, score, exit_code = classify(unique_indicators, window_activity)
    hits.sort(key=lambda item: (-len(item.indicators), item.path))
    window_activity = sorted(set(window_activity))

    return ScanResult(
        scanned_roots=scanned_roots,
        existing_roots=existing_roots,
        scanned_files=scanned_files,
        skipped_large_files=skipped_large_files,
        unreadable_files=unreadable_files,
        window_activity=window_activity,
        unique_indicators=sorted(unique_indicators),
        score=score,
        verdict=verdict,
        exit_code=exit_code,
        hits=hits,
        sources=SOURCE_URLS,
    )


def print_text_report(result: ScanResult) -> None:
    print("Apifox 供应链事件本地检测报告")
    print("=" * 60)
    print(f"受影响时间窗: {ATTACK_WINDOW_START.date()} 到 {ATTACK_WINDOW_END.date()}（结束日期不含当天）")
    print(f"风险结论: {result.verdict}")
    print(f"风险分数: {result.score}")
    print()

    if result.existing_roots:
        print("发现的 Apifox 相关目录:")
        for item in result.existing_roots:
            print(f"  - {item}")
    else:
        print("未发现默认或指定的 Apifox 相关目录。")
    print()

    print("扫描统计:")
    print(f"  - 扫描文件数: {result.scanned_files}")
    print(f"  - 跳过超大文件: {result.skipped_large_files}")
    print(f"  - 读取失败文件: {result.unreadable_files}")
    print(f"  - 命中 IOC 数量: {len(result.unique_indicators)}")
    print()

    if result.unique_indicators:
        print("命中的 IOC:")
        for item in result.unique_indicators:
            indicator = INDICATOR_BY_LITERAL[item]
            print(f"  - {item} [{indicator.category}] {indicator.description}")
        print()

    if result.hits:
        print("命中文件:")
        for hit in result.hits[:20]:
            print(f"  - {hit.path}")
            print(f"    mtime: {hit.modified} | size: {hit.size} bytes")
            print(f"    indicators: {', '.join(hit.indicators)}")
        if len(result.hits) > 20:
            print(f"  - 其余 {len(result.hits) - 20} 个命中文件已省略")
        print()

    if result.window_activity:
        print("受影响时间窗内的本地活动痕迹:")
        for item in result.window_activity[:20]:
            print(f"  - {item}")
        if len(result.window_activity) > 20:
            print(f"  - 其余 {len(result.window_activity) - 20} 项已省略")
        print()

    if result.exit_code > 0:
        print("建议动作:")
        for step in REMEDIATION_STEPS:
            print(f"  - {step}")
        print()

    print("情报来源:")
    for source in result.sources:
        print(f"  - {source}")


def main() -> int:
    args = parse_args()
    roots = build_roots(args.root, include_defaults=not args.no_default_roots)

    if args.list_default_roots:
        for root in roots:
            print(root)
        return 0

    result = scan(roots, max_file_size=args.max_file_size_mb * 1024 * 1024)

    if args.json:
        print(
            json.dumps(
                asdict(result),
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        print_text_report(result)
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
