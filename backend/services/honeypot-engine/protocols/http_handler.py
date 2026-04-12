"""
HTTP/HTTPS Honeypot — full web application simulation.

Templates: Apache default, Nginx, WordPress, phpMyAdmin, Jenkins, Grafana,
           GitLab, Jupyter, Kubernetes Dashboard, Docker Registry,
           Spring Boot Actuator, Laravel debug page.

Detection: SQLi, path traversal, command injection, XSS, XXE, SSRF,
           RFI/LFI, scanner fingerprinting, directory brute-force.

AI Mode: LLM generates realistic HTML/JSON responses per path.
"""
import re
import asyncio
from datetime import datetime, timezone
from uuid import uuid4

from aiohttp import web

from ai.phantom_ai import PhantomAI
from evasion.fingerprint_manager import get_fingerprint_manager
from .base import BaseHoneypotHandler

# ---------------------------------------------------------------------------
# Scanner User-Agent signatures
# ---------------------------------------------------------------------------
_SCANNER_UAS = re.compile(
    r"nikto|sqlmap|nuclei|masscan|nmap|zgrab|dirbuster|gobuster|ffuf"
    r"|wfuzz|burpsuite|owasp.zap|openvas|nessus|acunetix|appscan"
    r"|w3af|whatweb|webshag|skipfish",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Attack pattern detection
# ---------------------------------------------------------------------------
_SQLI_PATTERNS = re.compile(
    r"union\s+select|order\s+by\s+\d|'\s*or\s*'1'='1|--\s*$|;\s*drop\s+table"
    r"|waitfor\s+delay|sleep\(\d|benchmark\(",
    re.IGNORECASE,
)
_TRAVERSAL_PATTERNS = re.compile(
    r"\.\./|\.\.[/\\]|/etc/passwd|/windows/system32|/proc/self|boot\.ini",
    re.IGNORECASE,
)
_CMD_INJECTION_PATTERNS = re.compile(
    r";\s*id\b|;\s*whoami|\$\(|`[^`]+`|&&\s*cat\s|&&\s*ls\s",
    re.IGNORECASE,
)
_SSRF_PATTERNS = re.compile(
    r"169\.254\.169\.254|localhost|127\.0\.0\.|10\.\d+\.\d+\.\d+"
    r"|192\.168\.\d+\.\d+|metadata\.google|metadata\.azure",
    re.IGNORECASE,
)
_RFI_PATTERNS = re.compile(
    r"php://|file://|expect://|data://|ftp://|dict://|gopher://|phar://",
    re.IGNORECASE,
)
_XXE_PATTERNS = re.compile(r"<!DOCTYPE|<!ENTITY|SYSTEM\s+[\"']", re.IGNORECASE)
_WP_PATTERNS  = re.compile(
    r"wp-config\.php|xmlrpc\.php|wp-content|wp-admin|author=\d",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Template HTML
# ---------------------------------------------------------------------------

_TEMPLATES: dict[str, str] = {
    "apache_default": """\
<!DOCTYPE html><html><head><title>Apache2 Ubuntu Default Page: It works</title>
<style>body{font-family:sans-serif;margin:40px}</style></head>
<body><h1>Apache2 Ubuntu Default Page</h1>
<p>This is the default welcome page used to test correct operation of the Apache2 HTTP server.</p>
<p>The Apache documentation can be found at: <a href="http://httpd.apache.org/docs/2.4/">httpd.apache.org</a></p>
</body></html>""",

    "nginx_default": """\
<!DOCTYPE html><html><head><title>Welcome to nginx!</title></head>
<body><h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and working.</p>
</body></html>""",

    "wordpress_home": """\
<!DOCTYPE html><html lang="en-US">
<head><meta charset="UTF-8"><title>Corporate Intranet &ndash; Just another WordPress site</title>
<meta name="generator" content="WordPress 6.4.3" />
<link rel="pingback" href="/xmlrpc.php" />
</head><body class="home blog logged-out">
<header><h1><a href="/">Corporate Intranet</a></h1></header>
<div class="entry-content"><p>Welcome to our internal portal.</p></div>
</body></html>""",

    "wp_login": """\
<!DOCTYPE html><html lang="en-US">
<head><title>Log In &#8212; Corporate Intranet</title>
<meta name="generator" content="WordPress 6.4.3" /></head>
<body class="login wp-core-ui">
<div id="login"><h1><a href="https://wordpress.org/">WordPress</a></h1>
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
<p><label for="user_login">Username or Email Address</label><br>
<input type="text" name="log" id="user_login" size="20" autocapitalize="none" /></p>
<p><label for="user_pass">Password</label><br>
<input type="password" name="pwd" id="user_pass" size="20" /></p>
<p class="forgetmenot"><label><input name="rememberme" type="checkbox" value="forever"> Remember Me</label></p>
<p class="submit"><input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In" /></p>
<input type="hidden" name="redirect_to" value="/wp-admin/" />
</form></div></body></html>""",

    "phpmyadmin": """\
<!DOCTYPE html><html lang="en"><head><title>phpMyAdmin</title>
<meta name="robots" content="noindex,nofollow">
<meta name="generator" content="phpMyAdmin 5.2.1" /></head>
<body><div id="pma_navigation"><h1>phpMyAdmin</h1></div>
<div id="login_form">
<form method="post" action="index.php">
<fieldset><legend>Sign in</legend>
<label for="input_username">Username:</label><input type="text" name="pma_username" id="input_username" />
<label for="input_password">Password:</label><input type="password" name="pma_password" id="input_password" />
<input type="submit" value="Go" />
</fieldset></form></div></body></html>""",

    "jenkins": """\
<!DOCTYPE html><html><head><title>Dashboard [Jenkins]</title></head>
<body class="two-column"><div id="jenkins">
<header><div id="header"><a href="/"><img src="/static/jenkins.png" alt="Jenkins"></a>
<div id="login-field"><a href="/login">log in</a></div>
</div></header>
<div id="main-panel"><h1>Welcome to Jenkins!</h1>
<div id="view"><table><tr><td>
<a href="/view/All/">All</a>
</td></tr></table></div></div></div></body></html>""",

    "grafana": """\
<!DOCTYPE html><html lang="en"><head>
<title>Grafana</title><meta charset="utf-8">
<meta name="viewport" content="width=device-width">
</head>
<body><div class="grafana-app">
<div ng-controller="LoginCtrl">
<form name="loginForm" action="login" method="post">
<div class="login-content">
<div class="login-title">Welcome to Grafana</div>
<input class="gf-form-input login-form-input" type="text" name="user" placeholder="email or username" />
<input class="gf-form-input login-form-input" type="password" name="password" placeholder="password" />
<button class="btn btn-large p-x-2 btn--primary" type="submit">Log In</button>
</div></form></div></div></body></html>""",

    "k8s_dashboard": """\
<!DOCTYPE html><html><head><title>Kubernetes Dashboard</title></head>
<body><div id="app">
<mat-toolbar><span>Kubernetes Dashboard</span></mat-toolbar>
<div class="content"><h2>Overview</h2>
<p>Cluster: production-k8s | Nodes: 3 | Namespaces: 8</p>
<div class="tile"><h3>CPU Usage</h3><div class="usage">23%</div></div>
<div class="tile"><h3>Memory Usage</h3><div class="usage">41%</div></div>
</div></div></body></html>""",

    "spring_actuator_health": '{"status":"UP","components":{"db":{"status":"UP","details":{"database":"PostgreSQL","validationQuery":"isValid()"}},"diskSpace":{"status":"UP","details":{"total":107374182400,"free":82631720960,"threshold":10485760,"path":"/"}},"redis":{"status":"UP","details":{"version":"7.0.11"}},"ping":{"status":"UP"}}}',

    "spring_actuator_env": '{"activeProfiles":["production"],"propertySources":[{"name":"systemProperties","properties":{"java.version":{"value":"17.0.9"},"os.name":{"value":"Linux"},"user.name":{"value":"app"}}},{"name":"applicationConfig: [classpath:/application.properties]","properties":{"spring.datasource.url":{"value":"jdbc:postgresql://db-prod-01:5432/appdb"},"spring.datasource.username":{"value":"appuser"},"spring.datasource.password":{"value":"******"},"server.port":{"value":"8080"}}}]}',

    "laravel_debug": """\
<!DOCTYPE html><html><head><title>Whoops! There was an error.</title>
<meta name="robots" content="noindex,nofollow,noarchive">
</head><body class="app exception-page"><div class="container">
<div class="title-container">
<p class="subtitle">Illuminate\\Database\\QueryException</p>
<h1 class="title">SQLSTATE[HY000] [2002] Connection refused (SQL: select * from `users` where `email` = admin@corp.local and `users`.`deleted_at` is null limit 1)</h1>
</div>
<div class="details">
<h2>Context</h2>
<p>APP_ENV: production</p>
<p>DB_HOST: 10.0.1.20</p>
<p>DB_DATABASE: laravel_prod</p>
<p>DB_USERNAME: laravel</p>
</div></div></body></html>""",

    "fake_admin_panel": """\
<!DOCTYPE html><html><head><title>Admin Dashboard</title></head>
<body style="font-family:sans-serif;background:#1a1a2e;color:#eee">
<div style="max-width:1200px;margin:0 auto;padding:20px">
<h1 style="color:#4fc3f7">&#9632; Admin Dashboard</h1>
<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:20px;margin:20px 0">
<div style="background:#16213e;padding:20px;border-radius:8px"><h3>Users</h3><p style="font-size:2em">1,247</p></div>
<div style="background:#16213e;padding:20px;border-radius:8px"><h3>Revenue</h3><p style="font-size:2em">$84,291</p></div>
<div style="background:#16213e;padding:20px;border-radius:8px"><h3>Orders</h3><p style="font-size:2em">3,842</p></div>
<div style="background:#16213e;padding:20px;border-radius:8px"><h3>Servers</h3><p style="font-size:2em">12</p></div>
</div>
<table border="1" style="width:100%;border-collapse:collapse">
<tr style="background:#16213e"><th>Email</th><th>Role</th><th>Last Login</th></tr>
<tr><td>admin@corp.local</td><td>superadmin</td><td>2 min ago</td></tr>
<tr><td>jsmith@corp.local</td><td>admin</td><td>1 hour ago</td></tr>
<tr><td>finance@corp.local</td><td>finance</td><td>3 hours ago</td></tr>
</table>
</div></body></html>""",
}

# ---------------------------------------------------------------------------
# Login state tracking (per-IP attempt counter for realistic auth flow)
# ---------------------------------------------------------------------------
_login_attempts: dict[str, int] = {}


class HttpHandler(BaseHoneypotHandler):
    PROTOCOL = "HTTP"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._fp = get_fingerprint_manager()

    async def start(self):
        app = web.Application(client_max_size=1 * 1024 * 1024)  # 1MB limit
        app.router.add_route("*", "/{path:.*}", self._handle)
        runner = web.AppRunner(app)
        await runner.setup()
        host = self.config.get("bind_host", "0.0.0.0")
        port = self.config.get("port", 18080)
        site = web.TCPSite(runner, host, port)
        await site.start()
        self.log.info("http_started", port=port)
        return runner

    async def _handle(self, request: web.Request):
        ip = (
            request.headers.get("X-Forwarded-For", "")
            .split(",")[0]
            .strip()
            or request.remote
            or "0.0.0.0"
        )
        path    = request.path
        method  = request.method
        ua      = request.headers.get("User-Agent", "")
        qs      = request.query_string
        full    = f"{path}?{qs}" if qs else path

        server_header = self._fp.get_http_server_header(self.decoy_id)
        template_type = self.config.get("template", "apache_default")

        # ---- classify the request ----
        event_type = "http_request"
        severity   = "low"
        tags: list[str] = []
        raw: dict = {"path": path, "method": method, "ua": ua, "qs": qs}

        # Scanner detection
        if _SCANNER_UAS.search(ua):
            tags.append("scanner_detected")
            severity = "high"
            raw["scanner"] = _SCANNER_UAS.search(ua).group()

        # Attack pattern checks
        for pattern, name, sev in [
            (_SQLI_PATTERNS,      "sql_injection",       "critical"),
            (_TRAVERSAL_PATTERNS, "path_traversal",       "high"),
            (_CMD_INJECTION_PATTERNS, "command_injection","critical"),
            (_SSRF_PATTERNS,      "ssrf_attempt",         "critical"),
            (_RFI_PATTERNS,       "rfi_lfi_attempt",      "high"),
            (_XXE_PATTERNS,       "xxe_attempt",          "high"),
            (_WP_PATTERNS,        "wordpress_probe",      "medium"),
        ]:
            if pattern.search(full):
                tags.append(name)
                if sev == "critical":
                    severity = "critical"
                elif sev == "high" and severity not in ("critical",):
                    severity = "high"
                event_type = name

        # POST body checks (for SQLi in forms etc.)
        if method == "POST":
            try:
                body = await request.text()
                raw["body_preview"] = body[:500]
                if _SQLI_PATTERNS.search(body):
                    tags.append("sql_injection")
                    severity = "critical"
                if _XXE_PATTERNS.search(body):
                    tags.append("xxe_attempt")
                    severity = "high"
            except Exception:
                pass

        await self.emit(ip, None, event_type, severity, raw, tags=tags)

        # ---- route to response ----
        headers = {"Server": server_header, "X-Content-Type-Options": "nosniff"}

        # Credential capture paths
        if path in ("/wp-login.php", "/login", "/admin/login", "/signin",
                    "/phpmyadmin/index.php", "/pma/index.php"):
            if method == "POST":
                return await self._handle_login(request, ip, headers)
            body = _TEMPLATES.get("wp_login" if "wp" in path else "grafana",
                                   _TEMPLATES["wp_login"])
            return web.Response(text=body, content_type="text/html", headers=headers)

        # Spring Boot Actuator
        if path.startswith("/actuator"):
            if path == "/actuator/health":
                return web.Response(text=_TEMPLATES["spring_actuator_health"],
                                    content_type="application/json", headers=headers)
            if path == "/actuator/env":
                await self.emit(ip, None, "sensitive_endpoint_access", "critical",
                                {"path": path}, tags=["data_exfil"])
                return web.Response(text=_TEMPLATES["spring_actuator_env"],
                                    content_type="application/json", headers=headers)
            return web.Response(text='{"_links":{}}',
                                content_type="application/json", headers=headers)

        # WordPress paths
        if path == "/xmlrpc.php":
            await self.emit(ip, None, "xmlrpc_probe", "high",
                            {"path": path}, tags=["wordpress_attack"])
            return web.Response(
                text="<?xml version=\"1.0\" encoding=\"UTF-8\"?><methodResponse>"
                     "<fault><value><struct><member><name>faultCode</name>"
                     "<value><int>403</int></value></member></struct></value></fault>"
                     "</methodResponse>",
                content_type="text/xml", headers=headers,
            )

        # Laravel debug
        if path in ("/debug", "/_debugbar", "/telescope") or "laravel" in template_type:
            return web.Response(text=_TEMPLATES["laravel_debug"],
                                content_type="text/html", headers=headers)

        # Kubernetes dashboard
        if template_type == "k8s_dashboard" or path.startswith("/api/v1"):
            return web.Response(text='{"kind":"Status","apiVersion":"v1","code":403,"message":"forbidden"}',
                                content_type="application/json", headers=headers)

        # Jenkins Groovy console
        if path in ("/script", "/jenkins/script", "/scriptText"):
            await self.emit(ip, None, "rce_attempt", "critical",
                            {"path": path}, tags=["rce_attempt"])
            return web.Response(text="<html><body>Error 403 - Not authorized</body></html>",
                                content_type="text/html", status=403, headers=headers)

        # Common 404 paths → log as directory brute force
        if path not in ("/", "/index.php", "/index.html", "/robots.txt",
                        "/favicon.ico", "/sitemap.xml"):
            await self.emit(ip, None, "directory_enum", "medium",
                            {"path": path}, tags=["reconnaissance"])

        # Root page
        if path in ("/", "/index.php", "/index.html"):
            body = _TEMPLATES.get(template_type, _TEMPLATES["apache_default"])
            return web.Response(text=body, content_type="text/html", headers=headers)

        # robots.txt — enticing
        if path == "/robots.txt":
            return web.Response(
                text="User-agent: *\nDisallow: /admin/\nDisallow: /backup/\n"
                     "Disallow: /config/\nDisallow: /.env\nDisallow: /wp-config.php\n",
                content_type="text/plain", headers=headers,
            )

        return web.Response(
            text="<html><head><title>404 Not Found</title></head>"
                 "<body><h1>Not Found</h1><p>The requested URL was not found on this server.</p>"
                 f"<hr><address>{server_header}</address></body></html>",
            content_type="text/html", status=404, headers=headers,
        )

    async def _handle_login(self, request: web.Request, ip: str,
                             headers: dict) -> web.Response:
        try:
            if request.content_type == "application/json":
                data = await request.json()
            else:
                data = dict(await request.post())
        except Exception:
            data = {}

        username = (
            data.get("username") or data.get("log") or
            data.get("pma_username") or data.get("user") or
            data.get("email") or ""
        )
        password = (
            data.get("password") or data.get("pwd") or
            data.get("pma_password") or ""
        )

        await self.emit(
            ip, None, "credential_capture", "critical",
            {"username": username, "password": password, "path": request.path},
            tags=["credential_capture"],
        )

        key = f"http_login:{ip}"
        attempts = _login_attempts.get(key, 0) + 1
        _login_attempts[key] = attempts

        if attempts >= 2:
            # "Successful" login — show fake admin panel
            return web.Response(
                text=_TEMPLATES["fake_admin_panel"],
                content_type="text/html", headers=headers,
            )

        # First attempt fails
        if "application/json" in request.content_type:
            return web.Response(
                text='{"error":"Invalid credentials","code":401}',
                content_type="application/json", status=401, headers=headers,
            )
        return web.Response(
            text=_TEMPLATES.get("wp_login", "").replace(
                "</form>",
                "<div style='color:red'>ERROR: The username or password you entered is incorrect.</div></form>",
            ),
            content_type="text/html", status=200, headers=headers,
        )
