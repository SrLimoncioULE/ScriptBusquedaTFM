import requests

url = "https://gnews.io/api/v4/search"
params = {
    "q": "can bus",
    "lang": "en",
    "token": "eb1e2f08eeedeb0a667f142d4b495ea3",
    "max": 10,
    "start": 0
}
resp = requests.get(url, params=params)
print(resp)
print(resp.json())