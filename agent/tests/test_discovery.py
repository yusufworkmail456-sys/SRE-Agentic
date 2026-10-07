"""Agent discovery unit tests — pure inputs, no live system probing."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sre_agent.discovery import detect_runtime, parse_nginx  # noqa: E402

NGINX_SAMPLE = """
server {
    listen 80;
    server_name example.com www.example.com;
    location / { proxy_pass http://127.0.0.1:8080; }
}
server {
    listen 443 ssl;
    server_name api.example.com;
    ssl_certificate /etc/letsencrypt/live/api.example.com/fullchain.pem;
    location / { proxy_pass http://127.0.0.1:8646; }
}
server {
    listen 80;
    server_name _;
    return 301 https://$host$request_uri;
}
"""


def test_parse_nginx_pairs_names_with_own_upstream():
    vhosts = parse_nginx(NGINX_SAMPLE)
    by_name = {v.server_name: v for v in vhosts}
    assert set(by_name) == {"example.com", "www.example.com", "api.example.com"}
    assert by_name["example.com"].upstream == "127.0.0.1:8080"
    assert by_name["api.example.com"].upstream == "127.0.0.1:8646"
    assert by_name["api.example.com"].ssl_cert.endswith("fullchain.pem")
    assert by_name["example.com"].ssl_cert is None


def test_parse_nginx_skips_wildcard_name():
    assert all(v.server_name != "_" for v in parse_nginx(NGINX_SAMPLE))


def test_parse_nginx_ignores_commented_blocks():
    text = "# server { server_name dead.com; }\n" + NGINX_SAMPLE
    assert "dead.com" not in {v.server_name for v in parse_nginx(text)}


def test_detect_runtime_from_command():
    assert detect_runtime("/usr/bin/java -jar app.jar") == "java"
    assert detect_runtime("node /srv/app/index.js") == "node"
    assert detect_runtime("/opt/venv/bin/uvicorn app:main") == "python"
    assert detect_runtime("/usr/sbin/nginx -g daemon off;") == "nginx"


def test_detect_runtime_from_cwd_markers(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    assert detect_runtime(None, str(tmp_path)) == "node"
    (tmp_path / "package.json").unlink()
    (tmp_path / "requirements.txt").write_text("fastapi")
    assert detect_runtime(None, str(tmp_path)) == "python"
    assert detect_runtime(None, str(tmp_path / "missing")) is None
