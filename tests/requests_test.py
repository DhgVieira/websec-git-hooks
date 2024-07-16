from unittest.mock import patch

import pytest
import responses
from pre_commit_hook.requests import make_request
from pre_commit_hook.errors import ServerError, ClientError, UnexpectedError


def test_make_request_invalid_method():
    with pytest.raises(UnexpectedError):
        make_request("GET", "/ping", None)


@responses.activate
def test_make_request_POST():
    responses.add(
        responses.POST, 'https://githooks.mercadolibre.com/ping',
        match=[responses.matchers.header_matcher({"Content-Type": "application/json"}),
               responses.matchers.json_params_matcher({"some_key": "some_value"})],
        json={"key": "value"}, status=200
    )

    res = make_request("POST", "/ping", {"some_key": "some_value"})
    assert res["key"] == "value"


@responses.activate
def test_make_request_PUT():
    responses.add(
        responses.PUT, 'https://githooks.mercadolibre.com/ping',
        match=[responses.matchers.header_matcher({"Content-Type": "application/json"}),
               responses.matchers.json_params_matcher({"some_key": "some_value"})],
        json={"key": "value"}, status=200
    )

    res = make_request("PUT", "/ping", {"some_key": "some_value"})
    assert res["key"] == "value"


@responses.activate
def test_make_request_403_ClientError():
    responses.add(
        responses.PUT, 'https://githooks.mercadolibre.com/ping',
        match=[responses.matchers.header_matcher({
            "Content-Type": "application/json"
        }),
               responses.matchers.json_params_matcher({"some_key": "some_value"})],
        json={"key": "value"}, status=403
    )
    with pytest.raises(ClientError):
        make_request("PUT", "/ping", {"some_key": "some_value"})


@responses.activate
def test_make_request_ServerError():
    responses.add(
        responses.PUT, 'https://githooks.mercadolibre.com/ping',

        match=[responses.matchers.header_matcher({
            "Content-Type": "application/json"
        }),
            responses.matchers.json_params_matcher({"some_key": "some_value"})],
        json={"key": "value"}, status=501
    )
    with pytest.raises(ServerError):
        make_request("PUT", "/ping", {"some_key": "some_value"})


@responses.activate
def test_make_request_ClientError():
    responses.add(
        responses.PUT, 'https://githooks.mercadolibre.com/ping',
        match=[responses.matchers.header_matcher({"Content-Type": "application/json"}),
               responses.matchers.json_params_matcher({"some_key": "some_value"})],
        json={"key": "value"}, status=404
    )
    with pytest.raises(ClientError):
        make_request("PUT", "/ping", {"some_key": "some_value"})
