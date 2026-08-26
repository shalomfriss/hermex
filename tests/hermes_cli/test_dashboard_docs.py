"""Dashboard API documentation asset and prefix contracts."""

from fastapi.testclient import TestClient

from hermes_cli import web_server
from hermes_cli.dashboard_auth.client_ip import parse_trusted_proxy_networks


def _client(
    *,
    peer: str = "testclient",
    trusted_proxies: tuple[str, ...] = (),
) -> TestClient:
    web_server.app.state.dashboard_trusted_proxy_networks = (
        parse_trusted_proxy_networks(trusted_proxies)
    )
    client = TestClient(web_server.app, client=(peer, 50000))
    client.headers[web_server._SESSION_HEADER_NAME] = web_server._SESSION_TOKEN
    return client


def test_docs_html_self_hosts_runtime_assets_and_declares_language():
    response = _client().get("/docs")

    assert response.status_code == 200
    assert '<html lang="en">' in response.text
    assert 'href="/docs-assets/swagger-ui.css"' in response.text
    assert 'href="/docs-assets/swagger-ui-a11y.css"' in response.text
    assert 'src="/docs-assets/swagger-ui-bundle.js"' in response.text
    assert 'src="/docs-assets/swagger-ui-a11y.js"' in response.text
    assert 'href="/favicon.ico"' in response.text
    assert '"validatorUrl": null' in response.text
    assert "cdn.jsdelivr.net" not in response.text
    assert "fastapi.tiangolo.com" not in response.text


def test_docs_html_honours_forwarded_prefix_for_every_runtime_url():
    response = _client(
        peer="127.0.0.1", trusted_proxies=("127.0.0.1",)
    ).get("/docs", headers={"X-Forwarded-Prefix": "/hermes/"})

    assert response.status_code == 200
    assert 'href="/hermes/docs-assets/swagger-ui.css"' in response.text
    assert 'href="/hermes/docs-assets/swagger-ui-a11y.css"' in response.text
    assert 'src="/hermes/docs-assets/swagger-ui-bundle.js"' in response.text
    assert 'src="/hermes/docs-assets/swagger-ui-a11y.js"' in response.text
    assert 'href="/hermes/favicon.ico"' in response.text
    assert "url: '/hermes/openapi.json'" in response.text
    assert "oauth2RedirectUrl: window.location.origin + '/hermes/docs/oauth2-redirect'" in response.text


def test_docs_html_ignores_forwarded_prefix_from_untrusted_peer():
    response = _client(peer="203.0.113.9").get(
        "/docs", headers={"X-Forwarded-Prefix": "/hermes/"}
    )

    assert response.status_code == 200
    assert 'href="/docs-assets/swagger-ui.css"' in response.text
    assert 'href="/docs-assets/swagger-ui-a11y.css"' in response.text
    assert 'src="/docs-assets/swagger-ui-bundle.js"' in response.text
    assert 'src="/docs-assets/swagger-ui-a11y.js"' in response.text
    assert 'href="/favicon.ico"' in response.text
    assert "url: '/openapi.json'" in response.text
    assert "/hermes/" not in response.text


def test_docs_assets_are_served_from_the_production_bundle(tmp_path, monkeypatch):
    docs_assets = tmp_path / "docs-assets"
    docs_assets.mkdir()
    (docs_assets / "swagger-ui.css").write_text(".swagger-ui{}", encoding="utf-8")
    (docs_assets / "swagger-ui-bundle.js").write_text(
        "window.SwaggerUIBundle = {};", encoding="utf-8"
    )
    (docs_assets / "swagger-ui-a11y.css").write_text(
        ".swagger-ui .opblock-summary-method{}", encoding="utf-8"
    )
    (docs_assets / "swagger-ui-a11y.js").write_text(
        "window.swaggerUiA11yLoaded = true;", encoding="utf-8"
    )
    monkeypatch.setattr(web_server, "WEB_DIST", tmp_path)
    client = _client()

    css = client.get("/docs-assets/swagger-ui.css")
    js = client.get("/docs-assets/swagger-ui-bundle.js")
    a11y_css = client.get("/docs-assets/swagger-ui-a11y.css")
    a11y_js = client.get("/docs-assets/swagger-ui-a11y.js")
    missing = client.get("/docs-assets/not-allowlisted.js")

    assert css.status_code == 200
    assert css.headers["content-type"].startswith("text/css")
    assert css.text == ".swagger-ui{}"
    assert js.status_code == 200
    assert js.headers["content-type"].startswith("text/javascript")
    assert "SwaggerUIBundle" in js.text
    assert a11y_css.status_code == 200
    assert a11y_css.headers["content-type"].startswith("text/css")
    assert ".opblock-summary-method" in a11y_css.text
    assert a11y_js.status_code == 200
    assert a11y_js.headers["content-type"].startswith("text/javascript")
    assert "swaggerUiA11yLoaded" in a11y_js.text
    assert missing.status_code == 404


def test_docs_oauth_redirect_declares_language():
    response = _client().get("/docs/oauth2-redirect")

    assert response.status_code == 200
    assert '<html lang="en-US">' in response.text
