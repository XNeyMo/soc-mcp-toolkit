"""
Merge new mcpServers entries into the user's .claude.json without touching the
rest of the file (projects, caches, oauth, etc.) or any mcpServers entries that
already exist. Makes a timestamped backup before writing.

Usage: python merge_claude_config.py <claude_json_path> <json_file_with_new_servers>
"""

import json
import shutil
import sys
import time


def main() -> int:
    if len(sys.argv) != 3:
        print("Usage: python merge_claude_config.py <claude.json> <new_servers.json>", file=sys.stderr)
        return 1

    config_path, new_servers_path = sys.argv[1], sys.argv[2]

    # utf-8-sig tolerates a BOM if the file has one (e.g. Set-Content -Encoding
    # utf8 in PowerShell adds it) and works the same if it does not.
    with open(new_servers_path, "r", encoding="utf-8-sig") as f:
        new_servers = json.load(f)

    with open(config_path, "r", encoding="utf-8-sig") as f:
        config = json.load(f)

    config.setdefault("mcpServers", {})

    backup_path = f"{config_path}.bak-{time.strftime('%Y%m%d-%H%M%S')}"
    shutil.copy2(config_path, backup_path)

    added, skipped = [], []
    for key, value in new_servers.items():
        if key in config["mcpServers"]:
            skipped.append(key)
            continue
        config["mcpServers"][key] = value
        added.append(key)

    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"BACKUP={backup_path}")
    print(f"ADDED={','.join(added)}")
    print(f"SKIPPED={','.join(skipped)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
