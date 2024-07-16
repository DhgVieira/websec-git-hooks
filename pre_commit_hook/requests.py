import json

import requests
from requests.adapters import HTTPAdapter, Retry


UTF_8 = 'utf-8'

from pre_commit_hook.errors import ServerError, ClientError, UnexpectedError

req_session = requests.Session()
retries = Retry(total=2, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504])
base_url = 'https://githooks.mercadolibre.com'
req_session.mount(base_url, HTTPAdapter(max_retries=retries))


def make_request(method, url, payload):
    """
    Makes an api call and returns the response or raise and exception
    :param method The request method
    :param url The url to be called
    :param payload The body of the request
    """
    try:
        if method == "POST":
            return post(url, payload)
        elif method == "PUT":
            return put(url, payload)
        else:
            raise UnexpectedError(f"invalid method {method} with url {url}")

    except requests.HTTPError as err:
        return handleErrorResponse(err.response.status_code, err.response.text, err.response.url)
    except Exception as err:
        raise UnexpectedError(f"unexpected error making request {err}")


def post(url, payload):
    """
    Makes a POST api call and returns the response
    :param url The url to be called
    :param payload The body of the request
    """
    res = req_session.post(base_url + url,
                           headers={"Content-Type": "application/json",
                                    "Content-Encoding": "deflate",
                                    "X-Base64-Encode-Fields": "files"
                                    },
                           data=json.dumps(payload, ensure_ascii=False))
    res.raise_for_status()
    return res.json()


def put(url, payload):
    """
    Makes a PUT api call and returns the response
    :param url The url to be called
    :param payload The body of the request
    """
    res = req_session.put(base_url + url,
                          headers={"Content-Type": "application/json"},
                          data=json.dumps(payload))
    res.raise_for_status()
    return res.json()


def handleErrorResponse(status_code, text, url):
    """
    Handles HTTP exceptions
    :param status_code The status_code returned by the request
    :param text The text returned by the request
    :param url The url where the request was made
    """
    if status_code >= 500:
        raise ServerError(status_code, url, text)
    raise ClientError(status_code, url, text)
