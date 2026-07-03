import requests
import time

API_KEY = "22ebeda5c0e4e411a5036f9fb6c64326f06b171e2fc2e1bb18a7125f082f3683"

BASE_URL = "https://www.virustotal.com/api/v3"
HEADERS = {
    "x-apikey": API_KEY
}

class ScanUrl:
    def submit_url(self, url):
        try:
            response = requests.post(
                f"{BASE_URL}/urls",
                headers=HEADERS,
                data={"url": url},
                timeout=30
            )

            response.raise_for_status()
            data = response.json()
            return data["data"]["id"]

        except requests.exceptions.HTTPError as e:
            return f"HTTP Error: {e}"
        except requests.exceptions.ConnectionError:
            return "Connection Error: Unable to reach VirusTotal."
        except requests.exceptions.Timeout:
            return "Request timed out."
        except requests.exceptions.RequestException as e:
            return f"Request Error: {e}"
        except KeyError:
            return "Unexpected response format."
        except Exception as e:
            return f"Unexpected error: {e}"


    def get_analysis(self, analysis_id):
        try:
            for i in range(30):
                response = requests.get(
                    f"{BASE_URL}/analyses/{analysis_id}",
                    headers=HEADERS,
                    timeout=30
                )

                response.raise_for_status()
                data = response.json()
                status = data["data"]["attributes"]["status"]

                if status == "completed":
                    return data
                elif status in ("queued", "running", "in-progress"):
                    time.sleep(2)
                else:
                    return None

        except requests.exceptions.HTTPError as e:
            return f"HTTP Error: {e}"
        except requests.exceptions.ConnectionError:
            return "Connection Error."
        except requests.exceptions.Timeout:
            return "Request timed out."
        except requests.exceptions.RequestException as e:
            return f"Request Error: {e}"
        except KeyError:
            return "Unexpected response format."
        except Exception as e:
            return f"Unexpected error: {e}"
