from aiohttp import web
from .base import BaseHoneypotHandler


class AwsMetadataHandler(BaseHoneypotHandler):
    PROTOCOL = "AWS_METADATA"

    FAKE_ROLE = "EC2InstanceRole-WebServer"

    async def start(self):
        app = web.Application()
        app.router.add_route("GET", "/latest/meta-data/", self._index)
        app.router.add_route("GET", "/latest/meta-data/{path:.*}", self._metadata)
        app.router.add_route("GET", "/latest/user-data", self._userdata)
        app.router.add_route("PUT", "/latest/api/token", self._imdsv2)
        app.router.add_route("*", "/{path:.*}", self._catch)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, self.config.get("bind_host", "0.0.0.0"), self.config.get("port", 18169))
        await site.start()
        return runner

    async def _ip(self, req):
        return req.headers.get("X-Forwarded-For", req.remote or "0.0.0.0")

    async def _index(self, req):
        ip = await self._ip(req)
        await self.emit(ip, None, "metadata_index", "medium", {})
        return web.Response(text="ami-id\nhostname\ninstance-id\niam/\n")

    async def _metadata(self, req):
        ip = await self._ip(req)
        path = req.match_info["path"]
        if "iam/security-credentials" in path:
            await self.emit(ip, None, "iam_access", "critical", {"path": path}, ["ssrf_metadata"])
            if path.endswith("security-credentials") or path.endswith("security-credentials/"):
                return web.Response(text=self.FAKE_ROLE)
            return web.json_response({
                "Code": "Success",
                "Type": "AWS-HMAC",
                "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "Token": "fake-session-token",
                "Expiration": "2099-12-31T23:59:59Z",
            })
        await self.emit(ip, None, "metadata_access", "high", {"path": path})
        mapping = {
            "instance-id": "i-0abcdef1234567890",
            "instance-type": "t3.medium",
            "hostname": "ip-10-0-1-15.ec2.internal",
            "local-ipv4": "10.0.1.15",
            "public-ipv4": "54.204.105.32",
            "ami-id": "ami-0abcdef1234567890",
        }
        return web.Response(text=mapping.get(path, ""))

    async def _userdata(self, req):
        ip = await self._ip(req)
        await self.emit(ip, None, "userdata", "high", {"path": "/latest/user-data"}, ["ssrf_metadata"])
        return web.Response(text="#!/bin/bash\napt-get update\n")

    async def _imdsv2(self, req):
        return web.Response(text="fake-imdsv2-token-phantom")

    async def _catch(self, req):
        ip = await self._ip(req)
        await self.emit(ip, None, "unknown_path", "medium", {"path": str(req.url.path)})
        return web.Response(status=404, text="404 Not Found")
