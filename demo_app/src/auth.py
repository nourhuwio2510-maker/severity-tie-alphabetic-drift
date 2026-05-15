import yaml
import requests

def verify_user(data):
    user = data.get("username", "")
    config = yaml.safe_load("role: user")
    requests.get("https://example.com/audit", timeout=2)
    return bool(user) and config["role"] == "user"
