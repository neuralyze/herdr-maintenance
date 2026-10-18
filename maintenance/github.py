"""Small authenticated GitHub transport; source processes must not use this environment."""
from __future__ import annotations

import json
import os
import re
import subprocess


class GitHubError(RuntimeError):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class GitHub:
    def command(self, args: list[str], input_text: str | None = None) -> str:
        result = subprocess.run(["gh", *args], input=input_text, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env={**os.environ, "GH_HOST": "github.com"})
        if result.returncode:
            match = re.search(r"HTTP (\d{3})", result.stderr)
            # Do not echo stderr: command output can contain credentials or signed URLs.
            raise GitHubError(f"GitHub command {args[0] if args else 'unknown'} failed"
                              + (f" (HTTP {match[1]})" if match else ""),
                              int(match[1]) if match else None)
        return result.stdout

    def api(self, method: str, endpoint: str, payload: dict | None = None):
        if not re.fullmatch(r"repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_./?=&%+:-]*)?", endpoint) or ".." in endpoint:
            raise ValueError("Only repository-scoped GitHub endpoints are allowed")
        args = ["api", "--hostname", "github.com", "--method", method, endpoint]
        if payload is not None:
            args += ["--input", "-"]
        text = self.command(args, json.dumps(payload) if payload is not None else None)
        return json.loads(text) if text.strip() else None
