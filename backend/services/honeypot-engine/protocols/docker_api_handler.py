from aiohttp import web
from .base import BaseHoneypotHandler


class DockerApiHandler(BaseHoneypotHandler):
    PROTOCOL = "DOCKER_API"

    async def start(self):
        app = web.Application()
        app.router.add_route("GET", "/v{ver}/containers/json", self._container_list)
        app.router.add_route("GET", "/v{ver}/images/json", self._image_list)
        app.router.add_route("POST", "/v{ver}/containers/{id}/exec", self._exec_create)
        app.router.add_route("POST", "/v{ver}/exec/{id}/start", self._exec_start)
        app.router.add_route("GET", "/v{ver}/info", self._info)
        app.router.add_route("GET", "/v{ver}/_ping", self._ping)
        app.router.add_route("POST", "/v{ver}/containers/create", self._container_create)
        app.router.add_route("*", "/{path:.*}", self._catch_all)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, self.config.get("bind_host", "0.0.0.0"), self.config.get("port", 12375))
        await site.start()
        return runner

    async def _container_list(self, request):
        ip = request.remote
        await self.emit(ip, None, "container_list", "high", {"endpoint": "/containers/json"})
        return web.json_response([
            {"Id": "abc123def456", "Names": ["/web-server"], "Image": "nginx:latest", "State": "running", "Status": "Up 3 days"},
            {"Id": "789xyz012abc", "Names": ["/db-master"], "Image": "postgres:16", "State": "running", "Status": "Up 14 days"},
        ])

    async def _exec_create(self, request):
        ip = request.remote
        body = await request.json()
        await self.emit(ip, None, "exec_create", "critical", {"container_id": request.match_info["id"], "command": body.get("Cmd", [])}, ["container_escape", "rce_attempt"])
        return web.json_response({"Id": "execid12345"})

    async def _exec_start(self, request):
        ip = request.remote
        await self.emit(ip, None, "exec_start", "critical", {"exec_id": request.match_info["id"]}, ["container_escape"])
        return web.Response(status=200)

    async def _container_create(self, request):
        ip = request.remote
        body = await request.json()
        await self.emit(ip, None, "container_create", "critical", {
            "image": body.get("Image"),
            "binds": body.get("HostConfig", {}).get("Binds", []),
            "privileged": body.get("HostConfig", {}).get("Privileged", False),
        }, ["container_escape"])
        return web.json_response({"Id": "newcontainer123"}, status=201)

    async def _info(self, request):
        return web.json_response({"ServerVersion": "24.0.7", "Containers": 8, "ContainersRunning": 5, "NCPU": 4})

    async def _ping(self, request):
        return web.Response(text="OK", headers={"API-Version": "1.44"})

    async def _image_list(self, request):
        return web.json_response([
            {"Id": "sha256:abc", "RepoTags": ["nginx:latest"], "Size": 187456789},
            {"Id": "sha256:def", "RepoTags": ["postgres:16"], "Size": 378654321},
        ])

    async def _catch_all(self, request):
        ip = request.remote
        await self.emit(ip, None, "unknown_endpoint", "medium", {"method": request.method, "path": str(request.url.path)})
        return web.Response(status=404)
