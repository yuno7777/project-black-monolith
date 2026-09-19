"""Read-only MCP tool exposing exactly one operator-selected note file."""

import json
import sys
from pathlib import Path

note = Path(sys.argv[1]).resolve(strict=True)
if not note.is_file() or note.stat().st_size > 65536:
    raise ValueError("Select a note file no larger than 64 KiB")
for line in sys.stdin:
    message = json.loads(line)
    if "id" not in message:
        continue
    method = message.get("method")
    result = None
    if method == "initialize":
        result = {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "read-only-note", "version": "1"},
        }
    elif method == "tools/list":
        result = {
            "tools": [
                {
                    "name": "read_note",
                    "description": "Read the operator-selected project note.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {},
                        "additionalProperties": False,
                    },
                }
            ]
        }
    elif method == "tools/call" and message.get("params") == {"name": "read_note", "arguments": {}}:
        with note.open(encoding="utf-8") as stream:
            content = stream.read(65537)
        if len(content.encode("utf-8")) > 65536:
            raise ValueError("Note grew beyond 64 KiB")
        result = {"content": [{"type": "text", "text": content}]}
    response = {"jsonrpc": "2.0", "id": message["id"]}
    if result is None:
        response["error"] = {"code": -32601, "message": "Unknown or invalid tool request"}
    else:
        response["result"] = result
    print(json.dumps(response), flush=True)
