import os
import json
import hashlib
import zipfile
import asyncio
import re
from datetime import datetime, timezone
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any
from uuid import uuid4

import httpx
import websockets
from fastapi import FastAPI, File, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from openai import AsyncOpenAI
from pydantic import BaseModel, Field


app = FastAPI(title="VultrPilot API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("FRONTEND_ORIGIN", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/static", StaticFiles(directory="frontend"), name="static")
live_sessions: dict[str, WebSocket] = {}
approval_waiters: dict[str, asyncio.Future] = {}
browser_sessions: list[dict[str, Any]] = []
UPLOAD_DIR = Path("/tmp/vultrpilot-uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
ALLOWED_EXTENSIONS = {".txt", ".md", ".csv", ".json", ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".webp"}
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
UPLOAD_TTL_SECONDS = 3600
ARTIFACT_DIR = Path("/tmp/vultrpilot-artifacts")
ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
EXECUTOR_DIR = Path("/var/lib/vultrpilot-executor")
EXECUTOR_DIR.mkdir(parents=True, exist_ok=True)

client = AsyncOpenAI(
    api_key=os.environ.get("VULTR_SERVERLESS_INFERENCE_API_KEY", ""),
    base_url=os.getenv("QWEN_BASE_URL", "https://api.vultrinference.com/v1"),
)
VISION_MODEL = os.getenv("QWEN_VISION_MODEL", "qwen3.8-27b")
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "https://vultrpilot.baharsoftbd.com").rstrip("/")


async def analyze_annotated_images(annotations: list[dict[str, Any]], attachments: list[dict[str, Any]] | None = None, image_urls: list[str] | None = None, user_instruction: str = "") -> dict[str, Any]:
    """Verify the marked screenshot with a multimodal Vultr model before actions."""
    content: list[dict[str, Any]] = [{
        "type": "text",
        "text": (
            "Analyze the attached browser screenshot. Inspect the pixels directly; do not require metadata coordinates. "
            "If a visible arrow, rectangle, circle, highlight, or other mark exists, identify the element it points to "
            "and use the arrow tip or marked center as browser_x/browser_y normalized to the full image. "
            "If no explicit mark exists, determine the target only when it is clearly implied by the user's instruction; "
            "otherwise set has_annotation to false and say that clarification is needed. Do not click or claim an action. "
            "Extract page_url if visible in the browser address bar. Return JSON only with keys has_annotation, target, label, "
            "control_type, confidence, browser_x, browser_y, page_url, and observation. "
            f"User instruction: {user_instruction[:1000]} "
            "Keep observation under 500 words."
        ),
    }]
    image_inputs = list(annotations[-1:])
    if not image_inputs:
        image_inputs = [item for item in (attachments or []) if (
            str(item.get("content_type", "")).startswith("image/")
            or "/files/" in str(item.get("url", ""))
            or Path(str(item.get("name", ""))).suffix.lower() in {".png", ".jpg", ".jpeg", ".webp", ".gif"}
        )][-1:]
    image_inputs.extend({"image_url": url} for url in (image_urls or [])[-1:])
    for item in image_inputs:
        image_url = item.get("image_url") or item.get("file_url") or item.get("url")
        image_data = item.get("image_data")
        if isinstance(image_url, str) and image_url.startswith("/"):
            image_url = PUBLIC_BASE_URL + image_url
        if isinstance(image_url, str) and image_url.startswith(("https://", "http://")):
            content.append({"type": "image_url", "image_url": {"url": image_url, "detail": "low"}})
        elif isinstance(image_data, str) and image_data.startswith("data:image/"):
            content.append({"type": "image_url", "image_url": {"url": image_data, "detail": "low"}})
    if len(content) == 1:
        return {"status": "no_image", "observation": "No usable annotated image was supplied."}
    result = await client.chat.completions.create(
        model=VISION_MODEL,
        messages=[{"role": "user", "content": content}],
        temperature=0.1,
        max_tokens=400,
    )
    raw = (result.choices[0].message.content or "No visual target was identified.").strip()
    structured: dict[str, Any] = {}
    try:
        candidate = raw.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        parsed = json.loads(candidate)
        if isinstance(parsed, dict): structured = parsed
    except (json.JSONDecodeError, TypeError):
        pass
    return {
        "status": "verified" if structured.get("target") or structured.get("label") else "needs_clarification",
        "has_annotation": bool(structured.get("has_annotation", False)),
        "target": str(structured.get("target", ""))[:500],
        "label": str(structured.get("label", ""))[:500],
        "control_type": str(structured.get("control_type", ""))[:120],
        "confidence": structured.get("confidence"),
        "browser_x": structured.get("browser_x"),
        "browser_y": structured.get("browser_y"),
        "page_url": str(structured.get("page_url", "") or next((str(item.get("source_url", "")) for item in image_inputs if item.get("source_url")), ""))[:500],
        "observation": raw[:1800],
    }

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "run_python_project",
            "description": "Run a generated Python project in the disposable no-network executor and return live console output.",
            "parameters": {
                "type": "object",
                "properties": {
                    "project_name": {"type": "string"},
                    "entrypoint": {"type": "string", "description": "Python file to run, usually main.py"},
                    "files": {"type": "object", "additionalProperties": {"type": "string"}},
                },
                "required": ["project_name", "entrypoint", "files"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "create_project_zip",
            "description": "Create a downloadable ZIP project from generated text files. Never execute the generated files.",
            "parameters": {
                "type": "object",
                "properties": {
                    "project_name": {"type": "string", "description": "Short project folder name"},
                    "files": {"type": "object", "description": "Map of safe relative file paths to complete text contents", "additionalProperties": {"type": "string"}},
                },
                "required": ["project_name", "files"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_browser_sessions",
            "description": "List recent and currently running isolated browser sessions.",
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "browser_task",
            "description": "Inspect a public web page or click a visible element in the isolated browser. When the user explicitly asks to click, open, select, press, or submit a visible control, you MUST use action=click with a precise CSS selector and wait for the browser result before claiming success.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "HTTPS URL to inspect"},
                    "goal": {"type": "string", "description": "What to extract"},
                    "action": {
                        "type": "string",
                    "enum": ["inspect", "analyze_point", "click", "click_point"],
                        "description": "For an annotated screenshot, call analyze_point first to identify the element, then call click_point only after confirming the analysis. Use click for a CSS selector.",
                    },
                    "selector": {
                        "type": "string",
                        "description": "CSS selector for the visible element to click when action is click.",
                    },
                    "x": {"type": "number", "description": "Normalized horizontal coordinate from an attached annotation, between 0 and 1."},
                    "y": {"type": "number", "description": "Normalized vertical coordinate from an attached annotation, between 0 and 1."},
                },
                "required": ["url", "goal", "action"],
                "additionalProperties": False,
            },
        },
    }
]


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    current_url: str | None = Field(default=None, max_length=2000)
    history: list[dict[str, str]] = Field(default_factory=list, max_length=30)
    session_id: str | None = Field(default=None, max_length=100)
    attachments: list[dict[str, Any]] = Field(default_factory=list, max_length=10)
    annotations: list[dict[str, Any]] = Field(default_factory=list, max_length=5)
    approval_mode: str = Field(default="ask_before", pattern="^(approve_once|ask_before|full_access)$")


@app.get("/", include_in_schema=False)
async def home():
    return FileResponse("frontend/index.html")


def cleanup_uploads():
    cutoff = datetime.now(timezone.utc).timestamp() - UPLOAD_TTL_SECONDS
    for item in UPLOAD_DIR.iterdir():
        try:
            if item.is_file() and item.stat().st_mtime < cutoff:
                item.unlink()
        except OSError:
            pass


def cleanup_artifacts():
    cutoff = datetime.now(timezone.utc).timestamp() - UPLOAD_TTL_SECONDS
    for item in ARTIFACT_DIR.iterdir():
        try:
            if item.is_file() and item.stat().st_mtime < cutoff:
                item.unlink()
        except OSError:
            pass


def create_project_zip(project_name: str, files: dict[str, str]) -> dict[str, Any]:
    cleanup_artifacts()
    if not files or len(files) > 100:
        raise HTTPException(status_code=400, detail="A project must contain between 1 and 100 files")
    safe_project = "".join(char for char in project_name if char.isalnum() or char in "-_ ").strip()[:80] or "vultrpilot-project"
    artifact_id = uuid4().hex
    zip_path = ARTIFACT_DIR / f"{artifact_id}.zip"
    total_size = 0
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for filename, content in files.items():
            normalized = str(filename).replace("\\", "/")
            parts = PurePosixPath(normalized).parts
            if not normalized or normalized.startswith("/") or ".." in parts or len(normalized) > 240:
                raise HTTPException(status_code=400, detail=f"Unsafe project path: {filename}")
            if not isinstance(content, str) or len(content.encode("utf-8")) > 200_000:
                raise HTTPException(status_code=413, detail=f"File is too large: {filename}")
            total_size += len(content.encode("utf-8"))
            if total_size > 2_000_000:
                raise HTTPException(status_code=413, detail="Project source is limited to 2 MB")
            archive.writestr(f"{safe_project}/{normalized}", content)
    return {"id": artifact_id, "project_name": safe_project, "files": list(files), "url": f"/artifacts/{artifact_id}.zip", "expires_in_seconds": UPLOAD_TTL_SECONDS}


async def run_python_project(project_name: str, entrypoint: str, files: dict[str, str], session_id: str | None) -> dict[str, Any]:
    if not files or len(files) > 50:
        raise HTTPException(status_code=400, detail="A runnable project must contain between 1 and 50 files")
    if not entrypoint.endswith(".py") or entrypoint not in files:
        raise HTTPException(status_code=400, detail="The entrypoint must be a Python file included in the project")
    total_size = sum(len(str(content).encode("utf-8")) for content in files.values())
    if total_size > 1_000_000:
        raise HTTPException(status_code=413, detail="Runnable project source is limited to 1 MB")
    job_id = uuid4().hex
    job_dir = EXECUTOR_DIR / job_id
    job_dir.mkdir(parents=True, exist_ok=False)
    request_data = {"project_name": project_name[:80], "entrypoint": entrypoint, "files": files}
    temp_request = job_dir / "request.tmp"
    temp_request.write_text(json.dumps(request_data), encoding="utf-8")
    os.replace(temp_request, job_dir / "request.json")
    output_offset = 0
    deadline = asyncio.get_running_loop().time() + 45
    try:
        while asyncio.get_running_loop().time() < deadline:
            output_path = job_dir / "output.log"
            if output_path.is_file():
                raw = output_path.read_bytes()
                if len(raw) > output_offset:
                    chunk = raw[output_offset:].decode("utf-8", errors="replace")
                    output_offset = len(raw)
                    await publish(session_id, {"type": "execution_output", "data": {"job_id": job_id, "chunk": chunk}})
            result_path = job_dir / "result.json"
            if result_path.is_file():
                result = json.loads(result_path.read_text(encoding="utf-8"))
                result.update({"job_id": job_id, "project_name": project_name, "output": (output_path.read_text(encoding="utf-8", errors="replace") if output_path.is_file() else "")[:20000]})
                return result
            await asyncio.sleep(0.25)
        raise HTTPException(status_code=504, detail="Code execution timed out")
    finally:
        # Keep the temporary job directory long enough for diagnostics, then
        # let the next cleanup pass remove old jobs.
        pass


@app.get("/artifacts/{artifact_id}.zip")
async def get_artifact(artifact_id: str):
    cleanup_artifacts()
    if not artifact_id.isalnum():
        raise HTTPException(status_code=400, detail="Invalid artifact id")
    artifact_path = ARTIFACT_DIR / f"{artifact_id}.zip"
    if not artifact_path.is_file():
        raise HTTPException(status_code=404, detail="Artifact not found or expired")
    return FileResponse(artifact_path, media_type="application/zip", filename="vultrpilot-project.zip")


@app.post("/files")
async def upload_file(file: UploadFile = File(...)):
    cleanup_uploads()
    original_name = Path(file.filename or "attachment").name
    extension = Path(original_name).suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=415, detail="This file type is not supported")
    data = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Files must be 10 MB or smaller")
    file_id = uuid4().hex
    (UPLOAD_DIR / file_id).write_bytes(data)
    return {
        "id": file_id,
        "name": original_name,
        "content_type": file.content_type or "application/octet-stream",
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "url": f"/files/{file_id}",
        "expires_in_seconds": UPLOAD_TTL_SECONDS,
    }


@app.get("/files/{file_id}")
async def get_file(file_id: str):
    cleanup_uploads()
    if not file_id.isalnum():
        raise HTTPException(status_code=400, detail="Invalid file id")
    stored_path = UPLOAD_DIR / file_id
    if not stored_path.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(stored_path)


async def publish(session_id: str | None, message: dict[str, Any]):
    if not session_id or session_id not in live_sessions:
        return
    try:
        await live_sessions[session_id].send_json(message)
    except Exception:
        live_sessions.pop(session_id, None)


async def require_approval(session_id: str | None, mode: str, action: str, url: str) -> None:
    if mode in {"approve_once", "full_access"}:
        return
    if not session_id:
        raise HTTPException(status_code=409, detail="Ask before mode requires a live chat session")
    loop = asyncio.get_running_loop()
    waiter = loop.create_future()
    approval_waiters[session_id] = waiter
    await publish(session_id, {"type": "approval_required", "data": {"action": action, "url": url, "message": "Approve this browser action?"}})
    try:
        approved = await asyncio.wait_for(waiter, timeout=120)
    except asyncio.TimeoutError as exc:
        raise HTTPException(status_code=408, detail="Approval timed out; no browser action was taken") from exc
    finally:
        if approval_waiters.get(session_id) is waiter:
            approval_waiters.pop(session_id, None)
    if not approved:
        raise HTTPException(status_code=403, detail="Browser action denied; no click was performed")


@app.websocket("/ws/{session_id}")
async def live_socket(websocket: WebSocket, session_id: str):
    await websocket.accept()
    live_sessions[session_id] = websocket
    try:
        while True:
            raw = await websocket.receive_text()
            try:
                message = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if message.get("type") == "approval" and session_id in approval_waiters:
                waiter = approval_waiters[session_id]
                if not waiter.done():
                    waiter.set_result(bool(message.get("approved")))
    except WebSocketDisconnect:
        pass
    finally:
        if live_sessions.get(session_id) is websocket:
            live_sessions.pop(session_id, None)


async def run_browser(url: str, goal: str, action: str = "inspect", selector: str | None = None, x: float | None = None, y: float | None = None, session_id: str | None = None) -> dict[str, Any]:
    runner = os.getenv("RUNNER_URL", "http://localhost:8001")
    if session_id:
        runner_ws = runner.replace("https://", "wss://").replace("http://", "ws://") + "/stream"
        async with websockets.connect(runner_ws, open_timeout=10, close_timeout=5, max_size=20 * 1024 * 1024) as socket:
            await socket.send(json.dumps({"url": url, "goal": goal, "action": action, "selector": selector, "x": x, "y": y}))
            async for raw in socket:
                message = json.loads(raw)
                await publish(session_id, {"type": f"browser_{message.get('type', 'event')}", "data": message.get("data", {})})
                if message.get("type") == "complete":
                    return message["data"]
                if message.get("type") == "error":
                    raise HTTPException(status_code=502, detail=message.get("data", {}).get("message", "Browser runner failed"))
        raise HTTPException(status_code=502, detail="Browser runner closed before completing")
    async with httpx.AsyncClient(timeout=45) as http:
        response = await http.post(f"{runner}/inspect", json={"url": url, "goal": goal, "action": action, "selector": selector, "x": x, "y": y})
        response.raise_for_status()
        return response.json()


@app.get("/health")
async def health():
    return {"status": "ok", "model": os.getenv("QWEN_MODEL", "Qwen/Qwen3-8B")}


@app.get("/sessions")
async def sessions():
    return {"sessions": browser_sessions[:20]}


@app.post("/chat")
async def chat(request: ChatRequest):
    await publish(request.session_id, {"type": "status", "data": {"message": "Qwen is planning the browser task", "phase": "planning"}})
    messages: list[dict[str, Any]] = [
        {
            "role": "system",
            "content": (
                "You are a safe browser agent. Explain a short plan before acting. "
                "Only inspect public pages in the isolated browser. Never request passwords, "
                "payment data, or irreversible actions. Use browser_task when browsing is needed. "
                "When browser results include structured video_results or links, use only those "
                "exact titles and URLs; never invent or fill in missing search results. "
                "For a click request, call browser_task with action click and a precise CSS selector. "
                "If attached_annotations are present and the user refers to a highlighted or marked area, first use action analyze_point with the supplied normalized x and y coordinates. Explain the identified element, then use action click_point with the same coordinates only when the requested action is safe and the analysis matches the target. "
                "For cropped annotations, use the annotation's browser_x and browser_y coordinates for browser actions; x and y describe the cropped image for vision only. "
                "If a pasted screenshot supplies pasted_image_target with a page URL and normalized x/y, use click_point with those coordinates after vision verification and approval. "
                "If vision reports has_annotation=false or lacks a reliable target, do not guess; ask the user to mark the target or name the control. "
                "Correct obvious spelling mistakes and typos while preserving the user's intent, for example interpret 'reposotores' or 'reposotories' as 'repositories'. "
                "If a selector click fails because the page changed or the selector no longer matches, retry with action click_point using the verified annotation coordinates instead of claiming failure. "
                "Never claim that a click happened unless the returned browser result has action=click. "
                "If the user asks for browser sessions, call list_browser_sessions. "
                "If the user asks you to build a project or provide a ZIP, generate complete source files "
                "and call create_project_zip with at least one complete file. If the tool returns an error, "
                "fix the files and retry. If the user explicitly asks to run or test generated Python code, "
                "call run_python_project. Never execute generated code outside that disposable executor."
            ),
        },
    ]
    for item in request.history[-12:]:
        if item.get("role") in {"user", "assistant"} and item.get("content"):
            messages.append({"role": item["role"], "content": item["content"][:6000]})
    user_content = request.message
    if request.current_url:
        user_content += f"\n\nCurrent live isolated browser page: {request.current_url}"
    if request.attachments:
        names = ", ".join(str(item.get("name", "attachment")) for item in request.attachments[:10])
        user_content += f"\n\nAttached files available for this session (metadata only; contents are not sent to Qwen): {names}"
    image_attachments = [item for item in request.attachments if (
        str(item.get("content_type", "")).startswith("image/")
        or "/files/" in str(item.get("url", ""))
        or Path(str(item.get("name", ""))).suffix.lower() in {".png", ".jpg", ".jpeg", ".webp", ".gif"}
    )]
    pasted_image_urls = [url.rstrip(".,") for url in re.findall(r"https?://[^\s)\]>\"]+", request.message) if "/files/" in url][-2:]
    if request.annotations or image_attachments or pasted_image_urls:
        await publish(request.session_id, {"type": "status", "data": {"message": "Vision model is analyzing the annotated screenshot", "phase": "vision_analysis"}})
        vision_analysis = await analyze_annotated_images(request.annotations, image_attachments, pasted_image_urls, request.message)
        vision_message = json.dumps(vision_analysis, ensure_ascii=False)
        await publish(request.session_id, {"type": "analysis", "data": {"model": VISION_MODEL, "message": vision_message}})
        user_content += "\n\nCompact vision verification from " + VISION_MODEL + " (JSON only; the image is not passed to the planner):\n" + vision_message
        if request.annotations:
            user_content += "\n\nattached_annotations (normalized coordinates; use analyze_point first, then click_point only after this visual verification): " + json.dumps([{k:v for k,v in item.items() if k != "image_data"} for item in request.annotations[-1:]])
        elif vision_analysis.get("browser_x") is not None and vision_analysis.get("browser_y") is not None:
            user_content += "\n\npasted_image_target (use click_point only after approval): " + json.dumps({"url": vision_analysis.get("page_url"), "x": vision_analysis.get("browser_x"), "y": vision_analysis.get("browser_y")})
    messages.append({"role": "user", "content": user_content})

    try:
        first = await client.chat.completions.create(
            model=os.getenv("QWEN_MODEL", "Qwen/Qwen3-8B"),
            messages=messages,
            tools=TOOLS,
            temperature=0.2,
        )
        assistant = first.choices[0].message
        events = []
        for _ in range(3):
            messages.append(assistant.model_dump(exclude_none=True))
            if not assistant.tool_calls:
                return {"reply": assistant.content or "I could not produce a response.", "events": events}

            for call in assistant.tool_calls:
                args = json.loads(call.function.arguments)
                if call.function.name == "run_python_project":
                    await publish(request.session_id, {"type": "status", "data": {"message": "Starting disposable Python execution", "phase": "executing"}})
                    result = await run_python_project(args["project_name"], args["entrypoint"], args["files"], request.session_id)
                    events.append({"type": "execution_result", "data": result})
                    messages.append({"role": "tool", "tool_call_id": call.id, "content": json.dumps(result)})
                    continue
                if call.function.name == "create_project_zip":
                    try:
                        result = create_project_zip(args.get("project_name", "vultrpilot-project"), args.get("files", {}))
                        events.append({"type": "artifact", "data": result})
                    except HTTPException as exc:
                        result = {"error": exc.detail}
                    messages.append({"role": "tool", "tool_call_id": call.id, "content": json.dumps(result)})
                    continue
                if call.function.name == "list_browser_sessions":
                    result = {"sessions": browser_sessions[:20]}
                    events.append({"type": "browser_sessions", "data": result})
                    messages.append({"role": "tool", "tool_call_id": call.id, "content": json.dumps(result)})
                    continue
                if call.function.name != "browser_task":
                    raise HTTPException(status_code=400, detail="Unsupported tool")
                await publish(request.session_id, {"type": "status", "data": {"message": "Starting the isolated browser", "phase": "browser_start"}})
                record = {
                    "id": uuid4().hex[:12],
                    "status": "running",
                    "url": args["url"],
                    "goal": args["goal"],
                    "action": args.get("action", "inspect"),
                    "selector": args.get("selector"),
                    "approval_mode": request.approval_mode,
                    "started_at": datetime.now(timezone.utc).isoformat(),
                }
                browser_sessions.insert(0, record)
                del browser_sessions[20:]
                try:
                    if args.get("action", "inspect") in {"click", "click_point"}:
                        await require_approval(request.session_id, request.approval_mode, args.get("action", "click"), args["url"])
                    action = args.get("action", "inspect")
                    action_x, action_y = args.get("x"), args.get("y")
                    if request.annotations and action in {"analyze_point", "click_point"}:
                        annotation_meta = request.annotations[-1].get("annotation", {})
                        action_x = annotation_meta.get("browser_x", action_x)
                        action_y = annotation_meta.get("browser_y", action_y)
                    try:
                        result = await run_browser(args["url"], args["goal"], action, args.get("selector"), action_x, action_y, request.session_id)
                    except Exception as first_error:
                        # A selector can become stale between vision verification and
                        # execution. The annotated coordinates are the verified target,
                        # so use them as a safe fallback for a failed selector click.
                        fallback = request.annotations[-1].get("annotation", {}) if request.annotations else {}
                        fallback_x, fallback_y = fallback.get("browser_x", fallback.get("x")), fallback.get("browser_y", fallback.get("y"))
                        selector_failed = "No element matched selector" in str(first_error) or "404" in str(first_error)
                        if action != "click" or not selector_failed or fallback_x is None or fallback_y is None:
                            raise
                        await publish(request.session_id, {"type": "status", "data": {"message": "Selector changed; using the verified vision target", "phase": "clicking"}})
                        result = await run_browser(args["url"], args["goal"], "click_point", None, fallback_x, fallback_y, request.session_id)
                    record.update({"status": "completed", "final_url": result.get("url"), "title": result.get("title"), "finished_at": datetime.now(timezone.utc).isoformat()})
                except Exception as exc:
                    record.update({"status": "failed", "error": str(exc), "finished_at": datetime.now(timezone.utc).isoformat()})
                    raise
                events.append({"type": "browser_result", "data": result})
                messages.append({"role": "tool", "tool_call_id": call.id, "content": json.dumps(result)})

            follow_up = await client.chat.completions.create(
                model=os.getenv("QWEN_MODEL", "Qwen/Qwen3-8B"),
                messages=messages,
                tools=TOOLS,
                temperature=0.2,
            )
            assistant = follow_up.choices[0].message

        final = await client.chat.completions.create(model=os.getenv("QWEN_MODEL", "Qwen/Qwen3-8B"), messages=messages, temperature=0.2)
        return {"reply": final.choices[0].message.content or "The browser task completed.", "events": events}
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Browser runner error: {exc}") from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Model request failed: {exc}") from exc

