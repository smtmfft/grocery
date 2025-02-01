# proxy.py
from flask import Flask, Response, request
import requests
from collections import defaultdict
from eth_trace_block import trace_block as web3_trace_block
import os
import logging


def create_proxy_app(target_url: str):
    if not target_url:
        # TODO: config default target_url
        # target_url = "http://other-service.com"
        raise ValueError("target_url is required")

    app = Flask(__name__)

    @app.route("/trace/<int:block_number>")
    def trace_block(block_number):
        return web3_trace_block(block_number, rpc_url=target_url)

    @app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE"])
    def proxy(path):
        resp = requests.request(
            method=request.method,
            url=f"{target_url}/{path}",
            headers={key: value for key, value in request.headers if key != "Host"},
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
        )

        excluded_headers = [
            "content-encoding",
            "content-length",
            "transfer-encoding",
            "connection",
        ]
        headers = [
            (name, value)
            for (name, value) in resp.raw.headers.items()
            if name.lower() not in excluded_headers
        ]

        response = Response(resp.content, resp.status_code, headers)
        return response

    @app.route("/")
    def root():
        return proxy("")

    @app.errorhandler(requests.exceptions.RequestException)
    def handle_request_error(error):
        return f"Proxy error: {str(error)}", 500

    @app.before_request
    def before_request():
        if not request.path.startswith("/trace/"):
            return proxy(request.path.lstrip("/"))

    return app


if __name__ == "__main__":
    target_url = os.getenv("TARGET_URL")
    app = create_proxy_app(target_url)
    app.logger.setLevel(logging.DEBUG)
    app.run(host="0.0.0.0", port=8090, debug=True)
