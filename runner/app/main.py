import base64
from collections.abc import Awaitable, Callable
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, WebSocket
from pydantic import BaseModel, Field
from playwright.async_api import async_playwright

app = FastAPI(title="Isolated Browser Runner")


class InspectRequest(BaseModel):
    url: str
    goal: str = Field(min_length=1, max_length=1000)
    action: str = Field(default="inspect", pattern="^(inspect|analyze_point|click|click_point)$")
    selector: str | None = Field(default=None, max_length=500)
    x: float | None = Field(default=None, ge=0, le=1)
    y: float | None = Field(default=None, ge=0, le=1)


async def run_browser(request: InspectRequest, emit: Callable[[str, dict], Awaitable[None]] | None = None):
    async def notify(kind: str, data: dict):
        if emit:
            await emit(kind, data)

    parsed = urlparse(request.url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise HTTPException(status_code=400, detail="Only valid HTTPS URLs are allowed")

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
        )
        page = await browser.new_page()
        try:
            await notify("status", {"message": "Launching isolated Chromium", "phase": "launching"})
            await page.goto(request.url, wait_until="domcontentloaded", timeout=20000)
            await notify("screenshot", {
                "url": page.url,
                "title": await page.title(),
                "phase": "page_loaded",
                "screenshot_base64": base64.b64encode(await page.screenshot(type="png", full_page=True)).decode("ascii"),
            })
            # Many modern sites, including YouTube, fill the result list after
            # the initial HTML response. Give the page a short render window.
            await notify("status", {"message": "Waiting for dynamic page content", "phase": "rendering"})
            await page.wait_for_timeout(4000)
            point_info = None
            if request.action in {"analyze_point", "click", "click_point"}:
                if request.action in {"analyze_point", "click_point"}:
                    if request.x is None or request.y is None:
                        raise HTTPException(status_code=400, detail="Normalized x and y coordinates are required for annotated actions")
                    dimensions = await page.evaluate("""() => ({
                        width: Math.max(document.documentElement.scrollWidth, document.body.scrollWidth),
                        height: Math.max(document.documentElement.scrollHeight, document.body.scrollHeight),
                        viewport_width: window.innerWidth,
                        viewport_height: window.innerHeight
                    })""")
                    document_x = request.x * dimensions["width"]
                    document_y = request.y * dimensions["height"]
                    scroll_x = min(max(document_x - dimensions["viewport_width"] / 2, 0), max(dimensions["width"] - dimensions["viewport_width"], 0))
                    scroll_y = min(max(document_y - dimensions["viewport_height"] / 2, 0), max(dimensions["height"] - dimensions["viewport_height"], 0))
                    await page.evaluate("pos => window.scrollTo(pos.x, pos.y)", {"x": scroll_x, "y": scroll_y})
                    await page.wait_for_timeout(150)
                    point_x, point_y = document_x - scroll_x, document_y - scroll_y
                    point_info = await page.evaluate(
                        """({x, y}) => {
                          const el = document.elementFromPoint(x, y);
                          if (!el) return {found:false, x, y};
                          const r = el.getBoundingClientRect();
                          return {found:true, tag:el.tagName.toLowerCase(), text:(el.innerText || el.getAttribute('aria-label') || '').trim().slice(0,300), href:el.href || null, role:el.getAttribute('role'), rect:{left:r.left,top:r.top,width:r.width,height:r.height}, x, y};
                        }""",
                        {"x": point_x, "y": point_y},
                    )
                    point_info.update({"document_x": document_x, "document_y": document_y, "scroll_x": scroll_x, "scroll_y": scroll_y, "screenshot_width": dimensions["width"], "screenshot_height": dimensions["height"]})
                    if request.action == "analyze_point":
                        await notify("analysis", {"message": "Analyzed the annotated location", "phase": "analyzed", "point": point_info})
                    else:
                        await notify("status", {"message": "Clicking the analyzed annotated target", "phase": "clicking"})
                        await page.mouse.click(point_x, point_y)
                else:
                    if not request.selector:
                        raise HTTPException(status_code=400, detail="A CSS selector is required for click")
                    await notify("status", {"message": "Clicking the requested page element", "phase": "clicking"})
                    target = page.locator(request.selector).first
                    if await target.count() == 0:
                        raise HTTPException(status_code=404, detail=f"No element matched selector: {request.selector}")
                    await target.click(timeout=10000)
                await page.wait_for_timeout(3000)
                await notify("screenshot", {
                    "url": page.url,
                    "title": await page.title(),
                    "phase": "after_selection",
                    "screenshot_base64": base64.b64encode(await page.screenshot(type="png", full_page=True)).decode("ascii"),
                })
            title = await page.title()
            text = (await page.locator("body").inner_text())[:12000]
            links = await page.locator("a[href]").evaluate_all(
                """anchors => anchors.map(a => ({
                    text: (a.innerText || a.getAttribute('aria-label') || '').trim(),
                    href: a.href
                })).filter(x => x.text && x.href).slice(0, 80)"""
            )
            # YouTube's result cards are more reliable than body text when its
            # custom elements have not exposed all text to inner_text yet.
            video_results = await page.locator("a#video-title").evaluate_all(
                """anchors => anchors.map(a => ({
                    title: (a.getAttribute('title') || a.innerText || '').trim(),
                    url: a.href
                })).filter(x => x.title && x.url).slice(0, 20)"""
            )
            screenshot = await page.screenshot(type="png", full_page=True)
            result = {
                "url": page.url,
                "title": title,
                "text": text,
                "links": links,
                "video_results": video_results,
                "screenshot_base64": base64.b64encode(screenshot).decode("ascii"),
                "goal": request.goal,
                "action": request.action,
                "selector": request.selector,
                "point": point_info,
            }
            await notify("complete", result)
            return result
        finally:
            await browser.close()


@app.post("/inspect")
async def inspect(request: InspectRequest):
    return await run_browser(request)


@app.websocket("/stream")
async def stream(websocket: WebSocket):
    await websocket.accept()
    try:
        request = InspectRequest(**await websocket.receive_json())

        async def emit(kind: str, data: dict):
            await websocket.send_json({"type": kind, "data": data})

        await run_browser(request, emit)
    except Exception as exc:
        await websocket.send_json({"type": "error", "data": {"message": str(exc)}})
    finally:
        await websocket.close()

