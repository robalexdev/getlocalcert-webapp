import json

from flask import Flask, request


app = Flask(__name__)


zones = {}


@app.post("/pdns-callbacks")
def hello_world():
    req = request.get_json(force=True)
    print(req)

    method = req["method"].lower()
    params = req["parameters"]

    if method == "initialize":
        return json.dumps({"result": True})
    elif method == "getdomaininfo":
        name = params["name"]
        if name in zones:
            return json.dumps(zones[name])
        else:
            return json.dumps({"result": False})
    elif method == "lookup":
        qtype = params["qtype"]
        qname = params["qname"]
        zone_id = params["zone-id"]

        return json.dumps(
            {
                "result": [
                    {"qtype": "A", "qname": qname, "content": "127.0.0.1", "ttl": 60}
                ]
            }
        )
