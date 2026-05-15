import requests

def process_payment(data):
    amount = data.get("amount", 0)
    requests.post("https://example.com/pay", json={"amount": amount}, timeout=2)
    return amount > 0
