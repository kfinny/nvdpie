import urllib3
import requests
from .models import Response


class Client:

    def __init__(self, apikey: str | None = None):
        self.session = requests.Session()
        self.session.verify = False
        if not self.session.verify:
            urllib3.disable_warnings()
        self.apikey = apikey
        self.delay = 0.6 if self.apikey else 6
        self.version = '1.0'
        self.host = 'services.nvd.nist.gov'
        self.headers = {
            'Content-Type': 'application/json'
        }

    def __prepare_request__(self, url: str, **params) -> requests.PreparedRequest:
        if self.apikey:
            params.update({'apikey': self.apikey})
        return requests.Request(method='GET', url=url, headers=self.headers, params=params).prepare()

    def cve(self, cve_id, add_ons: bool = False) -> Response:
        url = f'https://{self.host}/rest/json/cve/{self.version}/{cve_id}'
        params = {}
        if add_ons:
            params.update({'addOns': 'dictionaryCpes'})

        response = self.session.send(self.__prepare_request__(url, **params))
        if response.ok:
            return Response(**response.json())
        response.raise_for_status()

    def cves(self, add_ons: bool = False) -> Response:
        url = f'https://{self.host}/rest/json/cves/{self.version}'
        params = {}
        if add_ons:
            params.update({'addOns': 'dictionaryCpes'})

        response = requests.get(url, params=params, headers=self.headers)
        if response.ok:
            return Response(**response.json())
        response.raise_for_status()

    def cpes(self, add_ons: bool = False) -> Response:
        url = f'https://{self.host}/rest/json/cpes/{self.version}'
        params = {}
        if add_ons:
            params.update({'addOns': 'cves'})

        response = requests.get(url, params=params, headers=self.headers)
        if response.ok:
            return Response(**response.json())
        response.raise_for_status()
