import requests
from .models import Response

class Client:

    def __init__(self, apikey):
        self.apikey = apikey
        self.version = '1.0'
        self.host = 'services.nvd.nist.gov'
        self.headers = {
            'Content-Type': 'application/json'
        }

    def cve(self, cve_id, add_ons: bool = False) -> Response:
        url = f'https://{self.host}/rest/json/cve/{self.version}/{cve_id}'
        params = {}
        if add_ons:
            params.update({'addOns': 'dictionaryCpes'})

        response = requests.get(url, params=params, headers=self.headers)
        if response.ok:
            return Response(**response.json())

    def cves(self, add_ons: bool = False) -> Response:
        url = f'https://{self.host}/rest/json/cves/{self.version}/'
        params = {}
        if add_ons:
            params.update({'addOns': 'dictionaryCpes'})

        response = requests.get(url, params=params, headers=self.headers)
        if response.ok:
            return Response(**response.json())

    def cpes(self, add_ons: bool = False) -> Response:
        url = f'https://{self.host}/rest/json/cpes/{self.version}/'
        params = {}
        if add_ons:
            params.update({'addOns': 'cves'})

        response = requests.get(url, params=params, headers=self.headers)
        if response.ok:
            return Response(**response.json())
