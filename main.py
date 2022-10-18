from pathlib import Path

import requests
import os
from dotenv import load_dotenv


class VirusTotalClient:
    def __init__(self, base_url: str, api_version: str, api_token: str):
        self.base_url = self.sanitize_string(base_url)
        self.api_token = api_token
        self.headers = {"x-apikey": self.api_token}
        self.api_version = self.sanitize_string(api_version)

    @staticmethod
    def sanitize_string(string_to_sanitize):
        if isinstance(string_to_sanitize, str):
            return string_to_sanitize if string_to_sanitize.endswith('/') else string_to_sanitize + '/'

    def get_file_report(self, id_: str):
        url = self.base_url + self.api_version + f'files/{id_}'
        self.headers.update({"accept": "application/json"})
        response = requests.get(url=url, headers=self.headers)
        return response.text


def main():
    dotenv_path = Path('venv/.env')
    load_dotenv(dotenv_path=dotenv_path)
    api_key = os.getenv('API_KEY_VIRUS_TOTAL')

    vt_client = VirusTotalClient("https://www.virustotal.com/api/", 'v3', api_token=api_key)
    vt_client.get_file_report('12602de6659a356141e744bf569e7e56')


if __name__ == '__main__':
    main()
