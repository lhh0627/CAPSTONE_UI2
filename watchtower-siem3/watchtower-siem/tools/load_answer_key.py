#!/usr/bin/env python3
"""DRY-RUN ONLY: load fake_alerts_answers.csv as ground-truth labels so you can test the Evaluation tab.
For your real project, labels must come from humans following your labelling guide, never from a script.
Usage: python load_answer_key.py [--url http://localhost:8000] [--key KEY] [--labeler answer-key]"""
import argparse, csv, json, urllib.request
ap = argparse.ArgumentParser(); ap.add_argument("--url", default="http://localhost:8000"); ap.add_argument("--key", default=""); ap.add_argument("--labeler", default="answer-key"); a = ap.parse_args()
def call(m, p, b=None):
    return json.loads(urllib.request.urlopen(urllib.request.Request(a.url + "/api" + p, json.dumps(b).encode() if b is not None else None, {"Content-Type": "application/json", "X-API-Key": a.key}, method=m), timeout=30).read())
ids = {x["meta"]["alert_id"]: x["id"][1:] for x in call("GET", "/triage?limit=1000")}; n = 0
for r in csv.DictReader(open("fake_alerts_answers.csv")):
    if r["alert_id"] in ids: call("POST", f"/alerts/{ids[r['alert_id']]}/label", {"label": r["truth"], "labeler": a.labeler}); n += 1
print("labelled", n, "alerts")
