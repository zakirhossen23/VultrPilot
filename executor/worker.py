import json
import os
import resource
import subprocess
import time
from pathlib import Path, PurePosixPath

BASE = Path("/var/lib/vultrpilot-executor")
BASE.mkdir(parents=True, exist_ok=True)


def safe_path(name: str) -> Path:
    normalized = name.replace("\\", "/")
    parts = PurePosixPath(normalized).parts
    if not normalized or normalized.startswith("/") or ".." in parts:
        raise ValueError(f"Unsafe path: {name}")
    return Path(*parts)


def limits():
    resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
    resource.setrlimit(resource.RLIMIT_AS, (192 * 1024 * 1024, 192 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (10 * 1024 * 1024, 10 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_NPROC, (32, 32))


def write_result(job_dir: Path, result: dict):
    temp = job_dir / "result.tmp"
    temp.write_text(json.dumps(result), encoding="utf-8")
    os.replace(temp, job_dir / "result.json")


def run_job(job_dir: Path):
    request = json.loads((job_dir / "request.json").read_text(encoding="utf-8"))
    workdir = job_dir / "workspace"
    workdir.mkdir(exist_ok=True)
    for name, content in request["files"].items():
        target = workdir / safe_path(name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    entrypoint = safe_path(request["entrypoint"])
    output_path = job_dir / "output.log"
    started = time.time()
    try:
        with output_path.open("w", encoding="utf-8") as output:
            process = subprocess.Popen(
                ["python", "-u", str(entrypoint)],
                cwd=workdir,
                stdout=output,
                stderr=subprocess.STDOUT,
                env={"PATH": "/usr/local/bin:/usr/bin:/bin", "PYTHONUNBUFFERED": "1"},
                preexec_fn=limits,
            )
            try:
                return_code = process.wait(timeout=30)
                timed_out = False
            except subprocess.TimeoutExpired:
                process.kill()
                return_code = -1
                timed_out = True
        write_result(job_dir, {"status": "timeout" if timed_out else ("completed" if return_code == 0 else "failed"), "return_code": return_code, "duration_seconds": round(time.time() - started, 2)})
    except Exception as exc:
        write_result(job_dir, {"status": "failed", "error": str(exc), "return_code": -1})


while True:
    for request_path in BASE.glob("*/request.json"):
        job_dir = request_path.parent
        lock = job_dir / "running.lock"
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(fd)
        except FileExistsError:
            continue
        try:
            run_job(job_dir)
        finally:
            lock.unlink(missing_ok=True)
    time.sleep(0.2)
