from aiohttp import web
from .base import BaseHoneypotHandler

class HttpHandler(BaseHoneypotHandler):
    PROTOCOL = "HTTP"

    async def start(self):
        app = web.Application()
        app.router.add_route("*", "/{path:.*}", self._handle)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, self.config.get("bind_host", "0.0.0.0"), self.config.get("port", 18080))
        await site.start()
        return runner

    async def _handle(self, request: web.Request):
        ip = request.headers.get("X-Forwarded-For", request.remote or "0.0.0.0").split(",")[0].strip()
        await self.emit(ip, None, "http_request", "medium", {"path": request.path, "method": request.method, "ua": request.headers.get("User-Agent", "")})
        if request.path == "/":
            return web.Response(text="<html><body><h1>Apache2 Ubuntu Default Page</h1><p>It works!</p></body></html>", content_type="text/html")
        return web.Response(status=404, text="Not Found")
