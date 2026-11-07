"""MCP Worker Gateway — dispatch tasks to local CLI agents with audit & Telegram notifications.

Supported CLI agents on the protected Linux host:
  - codex        (/usr/local/bin/codex)
  - dsh          (DeepSeek Harness headless)
  - opencode     (/home/sungo/.opencode/bin/opencode)
  - commandcode  (Command Code headless -p)
  - vibe         (Mistral Vibe headless -p)
  - agy          (Antigravity headless -p)

Targets:
  - "linux"   : runs in a permitted local project directory on the Linux host
  - "windows" : runs on the Linux host with a harness prompt instructing the
                agent to operate on the Windows host via `ssh windows`
                (conta's full environment + GPU) or `/mnt/Win-*` mounts.

Every task is:
  1. Screened before execution for forbidden targets (credentials, monitoring
     services, destructive root wipes).
  2. Logged append-only to /mnt/hdd22/agent-zerotrust/evidence/workers/tasks.jsonl
     and per-task output files.
  3. Reported to the human owner on Telegram (start, block, and completion).
"""
from __future__ import annotations

import glob
import json
import os
import pwd
import re
import shutil
import subprocess
import threading
import time
import uuid
from pathlib import Path

from evidence.telegram import TelegramConfigError, load_config, send_message

EVIDENCE_DIR = Path(
    os.environ.get(
        "AZT_WORKERS_EVIDENCE_DIR",
        "/mnt/hdd22/agent-zerotrust/evidence/workers",
    )
)

ALLOWED_LINUX_ROOTS = (
    "/mnt/ssd2tb/projects",
    "/mnt/hdd22",
    "/mnt/hdd",
    "/home/sungo",
    "/tmp",
)

# Pre-execution guard patterns (Adrian / Guardian style policy boundary):
# blocks exfiltration of keys/tokens or tampering with agent-zerotrust itself.
FORBIDDEN_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"id_ed25519|id_rsa|muse-client-key|lease\.key|telegram\.json|admin-password\.txt", re.I),
     "秘密鍵または認証トークンへのアクセス要求"),
    (re.compile(r"(systemctl|service)\s+(stop|disable|mask)\s+.*(agent-zerotrust|tetragon|warpgate|ssh)", re.I),
     "監視・セキュリティサービスの停止試行"),
    (re.compile(r"docker\s+(stop|rm|kill)\s+.*(tetragon|warpgate)", re.I),
     "監視コンテナ（Tetragon/Warpgate）の停止試行"),
    (re.compile(r"rm\s+-[rf]{1,2}\s+(/|/home|/mnt)\s*$", re.I),
     "ルートまたはホーム全体の破壊的削除"),
]


def _home() -> str:
    return os.environ.get("HOME") or pwd.getpwuid(os.getuid()).pw_dir


def _find_binary(name: str, candidates: list[str]) -> str | None:
    for c in candidates:
        for expanded in glob.glob(c):
            if os.access(expanded, os.X_OK):
                return expanded
    return shutil.which(name)


def discover_agents() -> dict[str, str]:
    """Return mapping of agent_name -> executable path for available agents."""
    home = _home()
    specs = {
        "codex": ["/usr/local/bin/codex", f"{home}/.local/bin/codex"],
        "dsh": [f"{home}/.nvm/versions/node/*/bin/dsh", "/usr/local/bin/dsh"],
        "opencode": [f"{home}/.opencode/bin/opencode", f"{home}/.local/bin/opencode"],
        "commandcode": [f"{home}/.nvm/versions/node/*/bin/commandcode", f"{home}/.local/bin/commandcode"],
        "vibe": [f"{home}/.local/bin/vibe", "/usr/local/bin/vibe"],
        "agy": [f"{home}/.local/bin/agy", "/usr/bin/antigravity"],
    }
    found: dict[str, str] = {}
    for name, paths in specs.items():
        exe = _find_binary(name, paths)
        if exe:
            found[name] = exe
    return found


def check_instruction_safety(instruction: str) -> str | None:
    """Return a Japanese reason string if the instruction violates safety policy, else None."""
    for pat, reason in FORBIDDEN_PATTERNS:
        if pat.search(instruction):
            return reason
    return None


def validate_workdir(workdir: str) -> str:
    """Resolve and verify workdir is inside an allowed root."""
    resolved = os.path.realpath(os.path.expanduser(workdir))
    if not any(resolved.startswith(root) for root in ALLOWED_LINUX_ROOTS):
        raise ValueError(f"workdir not in allowed roots: {resolved}")
    if not os.path.isdir(resolved):
        raise ValueError(f"workdir does not exist: {resolved}")
    return resolved


def build_agent_command(
    agent: str,
    binary: str,
    prompt: str,
    workdir: str,
    sandbox_mode: str = "workspace-write",
) -> list[str]:
    """Build the headless CLI invocation for each supported coding agent."""
    if agent == "codex":
        sb = sandbox_mode if sandbox_mode in ("read-only", "workspace-write") else "workspace-write"
        return [
            binary, "exec",
            "--sandbox", sb,
            "--skip-git-repo-check",
            "-C", workdir,
            prompt,
        ]
    if agent == "dsh":
        return [binary, "headless", prompt]
    if agent == "opencode":
        return [binary, "run", "--auto", prompt]
    if agent == "commandcode":
        return [binary, "-t", "-p", prompt]
    if agent == "vibe":
        return [binary, "--workdir", workdir, "-p", prompt, "--output", "text"]
    if agent == "agy":
        return [binary, "-p", prompt]
    raise ValueError(f"unsupported agent: {agent}")


def wrap_prompt(instruction: str, target: str, workdir: str) -> str:
    """Inject safety & target context (especially for Windows tasks via ssh windows)."""
    guard_header = (
        "[agent-zerotrust Worker Harness]\n"
        "You are executing a delegated task under kernel & gateway auditing.\n"
        "Do NOT read or exfiltrate SSH private keys, .env secrets, or gateway tokens.\n"
        "Do NOT stop or modify warpgate, tetragon, or agent-zerotrust services.\n"
    )
    if target == "windows":
        win_header = (
            "TARGET ENVIRONMENT: Windows host with GPU access.\n"
            "- ALWAYS execute commands on Windows via: `ssh windows \"<command>\"` (uses SSH for all file/OS interaction).\n"
            "- NEVER access Windows files directly via mounts.\n"
            "- Report clearly what commands you ran on Windows and their output.\n\n"
        )
        return guard_header + win_header + "Task:\n" + instruction
    return guard_header + f"Working directory: {workdir}\n\nTask:\n" + instruction


def _append_event(record: dict) -> None:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    log_file = EVIDENCE_DIR / "tasks.jsonl"
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def _notify_telegram(text: str) -> None:
    try:
        cfg = load_config()
        send_message(cfg, text)
    except (TelegramConfigError, Exception):
        pass


_TASKS_LOCK = threading.Lock()
_TASKS: dict[str, dict] = {}


def dispatch_task(
    agent: str,
    instruction: str,
    target: str = "linux",
    workdir: str = "/mnt/ssd2tb/projects",
    sandbox_mode: str = "workspace-write",
    wait_seconds: int = 25,
    timeout_seconds: int = 600,
) -> dict:
    """Validate, log, notify Telegram, and run a CLI coding agent task."""
    agents = discover_agents()
    if agent not in agents:
        raise ValueError(
            f"unknown or unavailable agent '{agent}'. Available: {sorted(agents.keys())}"
        )
    if target not in ("linux", "windows"):
        raise ValueError("target must be 'linux' or 'windows'")

    resolved_dir = validate_workdir(workdir)
    task_id = f"TSK-{int(time.time())}-{uuid.uuid4().hex[:6]}"
    now = time.time()

    # Pre-execution safety screen
    violation = check_instruction_safety(instruction)
    if violation:
        rec = {
            "task_id": task_id,
            "status": "blocked",
            "reason": violation,
            "agent": agent,
            "target": target,
            "workdir": resolved_dir,
            "instruction": instruction,
            "created_at": now,
        }
        _append_event({"type": "task_blocked", **rec})
        _notify_telegram(
            "🚨 agent-zerotrust — ワーカー依頼をブロック\n"
            f"タスクID: {task_id}\n"
            f"エージェント: {agent} ({target})\n"
            f"理由: {violation}\n"
            f"依頼内容:\n{instruction}"
        )
        return rec

    binary = agents[agent]
    full_prompt = wrap_prompt(instruction, target, resolved_dir)
    cmd = build_agent_command(agent, binary, full_prompt, resolved_dir, sandbox_mode)

    task_state = {
        "task_id": task_id,
        "status": "running",
        "agent": agent,
        "target": target,
        "workdir": resolved_dir,
        "instruction": instruction,
        "created_at": now,
        "ended_at": None,
        "returncode": None,
        "output_preview": "",
        "output_file": str(EVIDENCE_DIR / f"{task_id}.log"),
    }
    with _TASKS_LOCK:
        _TASKS[task_id] = task_state
    _append_event({"type": "task_started", **task_state})

    _notify_telegram(
        "🚀 agent-zerotrust — ワーカータスク開始\n"
        f"タスクID: {task_id}\n"
        f"エージェント: {agent} (対象: {target})\n"
        f"作業場所: {resolved_dir}\n"
        f"依頼:\n{instruction}"
    )

    done_event = threading.Event()

    def _runner():
        home = _home()
        env = dict(os.environ)
        env["HOME"] = home
        node_bins = glob.glob(f"{home}/.nvm/versions/node/*/bin")
        extra_paths = node_bins + [
            f"{home}/.local/bin",
            f"{home}/.opencode/bin",
            "/usr/local/bin",
            "/usr/bin",
            "/bin",
        ]
        env["PATH"] = ":".join(extra_paths) + ":" + env.get("PATH", "")

        try:
            proc = subprocess.run(
                cmd,
                cwd=resolved_dir,
                env=env,
                capture_output=True,
                text=True,
                timeout=max(10, min(timeout_seconds, 1800)),
            )
            rc = proc.returncode
            combined = (proc.stdout or "") + (
                f"\n[stderr]\n{proc.stderr}" if proc.stderr else ""
            )
            status = "completed" if rc == 0 else "failed"
        except subprocess.TimeoutExpired as exc:
            rc = 124
            combined = (exc.stdout or "") + "\n[timeout expired]"
            status = "timeout"
        except Exception as exc:
            rc = 125
            combined = f"[worker execution error: {type(exc).__name__}: {exc}]"
            status = "failed"

        EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
        Path(task_state["output_file"]).write_text(combined, encoding="utf-8")
        full_output = combined.strip() if combined else "(no output)"
        preview = full_output[-1500:]

        with _TASKS_LOCK:
            task_state["status"] = status
            task_state["ended_at"] = time.time()
            task_state["returncode"] = rc
            task_state["output_preview"] = preview

        _append_event({"type": "task_finished", **task_state})
        icon = "✅" if status == "completed" else "⚠️"
        duration = int((task_state["ended_at"] - task_state["created_at"]))
        _notify_telegram(
            f"{icon} agent-zerotrust — ワーカータスク完了 ({status})\n"
            f"タスクID: {task_id} ({duration}秒)\n"
            f"エージェント: {agent} (対象: {target})\n"
            f"結果:\n{full_output}"
        )
        done_event.set()

    threading.Thread(target=_runner, daemon=True).start()
    if wait_seconds > 0:
        done_event.wait(timeout=min(wait_seconds, 120))

    with _TASKS_LOCK:
        return dict(_TASKS[task_id])


def get_task(task_id: str) -> dict | None:
    """Return current task status/output from memory or disk evidence."""
    with _TASKS_LOCK:
        if task_id in _TASKS:
            return dict(_TASKS[task_id])
    log_file = EVIDENCE_DIR / "tasks.jsonl"
    if not log_file.exists():
        return None
    latest = None
    for line in log_file.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
            if rec.get("task_id") == task_id:
                latest = rec
        except json.JSONDecodeError:
            continue
    return latest
