from aiohttp import web
from .base import BaseHoneypotHandler


class K8sApiHandler(BaseHoneypotHandler):
    PROTOCOL = "K8S_API"

    async def start(self):
        app = web.Application()
        app.router.add_get("/version", self._version)
        app.router.add_get("/api/v1/namespaces", self._namespaces)
        app.router.add_get("/api/v1/pods", self._pods)
        app.router.add_get(r"/api/v1/namespaces/{ns}/pods", self._pods)
        app.router.add_get("/api/v1/secrets", self._secrets)
        app.router.add_get(r"/api/v1/namespaces/{ns}/secrets", self._secrets)
        app.router.add_post(r"/api/v1/namespaces/{ns}/pods", self._create_pod)
        app.router.add_route("*", "/{path:.*}", self._catch)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, self.config.get("bind_host", "0.0.0.0"), self.config.get("port", 16443))
        await site.start()
        return runner

    async def _log(self, req, event_type, severity, extra=None):
        ip = req.remote or "0.0.0.0"
        raw = {
            "method": req.method,
            "path": str(req.url.path),
            "user_agent": req.headers.get("User-Agent", ""),
            "token_preview": req.headers.get("Authorization", "").replace("Bearer ", "")[:50],
        }
        if extra:
            raw.update(extra)
        await self.emit(ip, None, event_type, severity, raw)

    async def _version(self, req):
        await self._log(req, "version_check", "low")
        return web.json_response({"major": "1", "minor": "28", "gitVersion": "v1.28.4"})

    async def _namespaces(self, req):
        await self._log(req, "namespace_list", "medium")
        return web.json_response({"kind": "NamespaceList", "items": [{"metadata": {"name": "default"}}, {"metadata": {"name": "production"}}]})

    async def _pods(self, req):
        ns = req.match_info.get("ns", "default")
        await self._log(req, "pod_list", "medium")
        return web.json_response({"kind": "PodList", "items": [{"metadata": {"name": "api-server-7d6f8b9", "namespace": ns}}]})

    async def _secrets(self, req):
        ns = req.match_info.get("ns", "default")
        await self._log(req, "secrets_access", "critical", {"namespace": ns})
        return web.json_response({"kind": "Status", "code": 403, "message": "Forbidden"}, status=403)

    async def _create_pod(self, req):
        ns = req.match_info.get("ns", "default")
        body = await req.json()
        await self._log(req, "pod_create", "critical", {"namespace": ns, "pod_spec": body})
        return web.json_response({"kind": "Pod", "metadata": {"name": "phantom-pod", "namespace": ns}})

    async def _catch(self, req):
        await self._log(req, f"unknown_endpoint_{req.method.lower()}", "medium", {"path": str(req.url.path)})
        return web.json_response({"kind": "Status", "code": 404, "message": "Not found"}, status=404)
