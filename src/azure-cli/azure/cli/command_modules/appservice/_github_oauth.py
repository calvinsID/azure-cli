# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

from knack.util import CLIError
from knack.log import get_logger

from ._constants import (GITHUB_OAUTH_CLIENT_ID, GITHUB_OAUTH_REDIRECT_URI)

logger = get_logger(__name__)


def get_github_access_token():
    import os
    random_state = os.urandom(5).hex()

    authorize_url = 'https://github.com/login/oauth/authorize?' \
                    'client_id={}&state={}&scope=repo+workflow&redirect_uri={}'.format(
                        GITHUB_OAUTH_CLIENT_ID, random_state, GITHUB_OAUTH_REDIRECT_URI)
    logger.warning('Opening OAuth URL')

    import webbrowser
    webbrowser.open(authorize_url)

    # Get code to exchange for access token
    access_code = _start_http_server(random_state)

    if access_code:
        import requests
        access_token_url = 'https://localhost:44300/api/staticsites/appservice/github/generateAccessToken'
        payload = {
            'code': access_code,
            'state': random_state
        }
        # Exchange for access token
        response = requests.post(access_token_url, json=payload, verify=False)
        if 'access_token' in response.json():
            return response.json()['access_token']
    return None


def _start_http_server(random_state):
    ip = '127.0.0.1'
    port = 3000
    
    import http.server
    import socketserver
    import urllib.parse as urlparse

    class CallBackHandler(http.server.BaseHTTPRequestHandler):
        access_token = None
        
        def do_GET(self):
            parsed_params = urlparse.parse_qs(urlparse.urlparse(self.path).query)
            received_state = parsed_params.get('state', [None])[0]
            received_code = parsed_params.get('code', [None])[0]

            if (self.path.startswith('/TokenAuthorize') and received_state and received_code and (random_state == received_state)):
                CallBackHandler.received_code = received_code
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write('GitHub account authenticated. You may close this tab'.encode('utf-8'))
            else:
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write('Unable to authenticate GitHub account. Please close this tab'.encode('utf-8'))

    try:
        with socketserver.TCPServer((ip, port), CallBackHandler) as httpd:
            logger.warning('Listening at port: {}'.format(port))
            httpd.handle_request()
    except Exception as e:
        raise CLIError('Socket error: {}. Please try again, or provide personal access token'.format(e))

    return CallBackHandler.received_code if hasattr(CallBackHandler, 'received_code') else None

