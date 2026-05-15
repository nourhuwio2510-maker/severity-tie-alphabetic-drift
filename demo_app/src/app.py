from flask import Flask, request, jsonify
from auth import verify_user
from payments import process_payment
from reports import generate_report

app = Flask(__name__)

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    return jsonify({"ok": verify_user(data)})

@app.route("/pay", methods=["POST"])
def pay():
    data = request.json
    return jsonify({"ok": process_payment(data)})

@app.route("/report", methods=["GET"])
def report():
    return jsonify({"report": generate_report()})
