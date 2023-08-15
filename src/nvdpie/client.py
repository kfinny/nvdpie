import urllib3
import requests

from typing import Any


class Client:

    def __init__(self, apikey: str | None = None):
        self.session = requests.Session()
        self.session.verify = True
        self.apikey = apikey
        self.delay = 0.6 if self.apikey else 6
        self.version = '2.0'
        self.host = 'services.nvd.nist.gov'
        self.headers = {
            'Content-Type': 'application/json'
        }

    def __prepare_request__(self, url: str, **params) -> requests.PreparedRequest:
        if self.apikey:
            self.headers.update({'apiKey': self.apikey})
        return requests.Request(method='GET', url=url, headers=self.headers, params=params).prepare()

    def cves(self, **params) -> dict[Any, Any]:
        url = f'https://{self.host}/rest/json/cves/{self.version}'
        prepared = self.__prepare_request__(url, **params)
        response = self.session.send(prepared)
        if response.ok:
            return response.json()
        response.raise_for_status()

    def cvehistory(self, **params) -> dict[Any, Any]:
        url = f'https://{self.host}/rest/json/cvehistory/{self.version}'
        prepared = self.__prepare_request__(url, **params)
        response = self.session.send(prepared)
        if response.ok:
            return response.json()
        response.raise_for_status()

    def cpes(self, **params) -> dict[Any, Any]:
        url = f'https://{self.host}/rest/json/cpes/{self.version}'
        prepared = self.__prepare_request__(url, **params)
        response = self.session.send(prepared)
        if response.ok:
            return response.json()
        response.raise_for_status()

    def cpematch(self, **params) -> dict[Any, Any]:
        url = f'https://{self.host}/rest/json/cpematch/{self.version}'
        prepared = self.__prepare_request__(url, **params)
        response = self.session.send(prepared)
        if response.ok:
            # return Response(**response.json())
            return response.json()
        response.raise_for_status()
