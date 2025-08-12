#!/usr/bin/env python3
from flask import Flask, jsonify, render_template_string, request, Response, redirect
import sqlite3, os, io, csv

DB_PATH = os.environ.get("SCANNER_DB", "scanner.db")

app = Flask(__name__)

def connect():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

PAGE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Domain Scan Dashboard</title>
    <style>
      body{font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; padding:24px}
      table{border-collapse: collapse; width: 100%}
      th, td{padding:8px; border-bottom:1px solid #ddd; text-align: left}
      .muted{color:#666}
      .chip{display:inline-block; padding:2px 6px; border-radius:10px; background:#eee}
      .grid{display:grid; grid-template-columns: repeat(4, 1fr); gap: 12px}
      .card{border:1px solid #ddd; padding:12px; border-radius:10px}
      input[type="search"], input[type="number"]{width:100%; padding:8px}
      select{width:100%; padding:8px}
      .row{display:grid; grid-template-columns: repeat(8, 1fr); gap: 8px; margin: 10px 0}
      .btn{padding:8px 12px; border:1px solid #222; background:#fff; border-radius:8px; text-decoration:none}
      .btn:hover{background:#f5f5f5}
      .chart{height:120px; display:flex; gap:2px; align-items:flex-end; margin:8px 0}
      .bar{width:8px; background:#9aa0a6}
    </style>
  </head>
  <body>
    <h1>Domain Scan Dashboard</h1>
    <div class="grid">
      <div class="card">
        <div class="muted">Total Checked</div>
        <div><strong>{{ stats.total_checked or 0 }}</strong></div>
      </div>
      <div class="card">
        <div class="muted">Available</div>
        <div><strong>{{ stats.available or 0 }}</strong></div>
      </div>
      <div class="card">
        <div class="muted">Premium</div>
        <div><strong>{{ stats.premium or 0 }}</strong></div>
      </div>
      <div class="card">
        <div class="muted">Max Score</div>
        <div><strong>{{ stats.max_score or 0 }}</strong></div>
      </div>
    </div>

    <h2>Advanced Search</h2>
    <form method="get" class="row">
      <input type="search" name="q" placeholder="Search domain..." value="{{q or ''}}" />
      <input type="number" name="min_score" placeholder="Min score" step="0.1" value="{{min_score or ''}}" />
      <input type="number" name="min_len" placeholder="Min length" value="{{min_len or ''}}" />
      <input type="number" name="max_len" placeholder="Max length" value="{{max_len or ''}}" />
      <label><input type="checkbox" name="digits" value="1" {{ 'checked' if digits else '' }}> Has digits</label>
      <label><input type="checkbox" name="hyphen" value="1" {{ 'checked' if hyphen else '' }}> Has hyphen</label>
      <select name="tld">
        <option value="">All TLDs</option>
        {% for t in tlds %}
        <option value="{{t}}" {% if selected_tld==t %}selected{% endif %}>.{{t}}</option>
        {% endfor %}
      </select>
      <button class="btn" type="submit">Filter</button>
      <a class="btn" href="/export.csv">Export CSV</a>
      <a class="btn" href="/export.json">Export JSON</a>
    </form>

    <div class="card">
      <div class="muted">Length histogram (last 500)</div>
      <div class="chart">
        {% for h in hist %}
        <div class="bar" style="height: {{ h*4 }}px" title="{{ loop.index }}: {{ h }}"></div>
        {% endfor %}
      </div>
    </div>

    <h2>Available Results</h2>
    <table>
      <thead><tr><th>Domain</th><th>TLD</th><th>Score</th><th>Premium</th><th>Registration</th><th>Renewal</th><th>ICANN</th><th>Checked</th><th>Feedback</th></tr></thead>
      <tbody>
      {% for row in rows %}
        <tr>
          <td>{{ row['domain'] }}</td>
          <td>.{{ row['tld'] }}</td>
          <td>{{ "%.2f"|format(row['score'] or 0) }}</td>
          <td>{{ 'Yes' if row['is_premium'] else 'No' }}</td>
          <td>{{ row['premium_registration_price'] or '' }}</td>
          <td>{{ row['premium_renewal_price'] or '' }}</td>
          <td>{{ row['icann_fee'] or '' }}</td>
          <td class="muted">{{ row['checked_at'] }}</td>
          <td>
            <a class="btn" href="/feedback?domain={{ row['domain'] }}&label=liked">Like</a>
            <a class="btn" href="/feedback?domain={{ row['domain'] }}&label=purchased">Purchased</a>
            <a class="btn" href="/feedback?domain={{ row['domain'] }}&label=reject">Reject</a>
          </td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
  </body>
</html>
"""

@app.route("/")
def home():
    qstr = request.args.get("q", "").strip()
    min_score = request.args.get("min_score", type=float)
    min_len = request.args.get("min_len", type=int)
    max_len = request.args.get("max_len", type=int)
    digits = request.args.get("digits", type=int) == 1
    hyphen = request.args.get("hyphen", type=int) == 1
    selected_tld = request.args.get("tld", "").strip().lower()

    where = ["is_available=1"]
    args = []
    if qstr:
        where.append("domain LIKE ?")
        args.append(f"%{qstr}%")
    if min_score is not None:
        where.append("score >= ?")
        args.append(min_score)
    if min_len is not None:
        where.append("length >= ?")
        args.append(min_len)
    if max_len is not None:
        where.append("length <= ?")
        args.append(max_len)
    if digits:
        where.append("has_digit=1")
    if hyphen:
        where.append("has_hyphen=1")
    if selected_tld:
        where.append("tld=?")
        args.append(selected_tld)

    sql_where = "WHERE " + " AND ".join(where) if where else ""
    con = connect()
    cur = con.execute(f"SELECT domain,tld,score,is_premium,premium_registration_price,premium_renewal_price,icann_fee,checked_at FROM domains {sql_where} ORDER BY score DESC, checked_at DESC LIMIT 500", args)
    rows = cur.fetchall()

    # Stats
    st = con.execute("SELECT COUNT(*) as total_checked, SUM(is_available) as available, SUM(is_premium) as premium, MAX(score) as max_score FROM domains").fetchone()

    # TLD list
    tlds_rows = con.execute("SELECT DISTINCT tld FROM domains WHERE tld IS NOT NULL AND tld != '' ORDER BY tld ASC").fetchall()
    tlds = [r["tld"] for r in tlds_rows]

    # histogram of lengths (last 500)
    hist_rows = con.execute("SELECT length FROM domains WHERE is_available=1 ORDER BY checked_at DESC LIMIT 500").fetchall()
    counts = [0]*20
    for r in hist_rows:
        L = int(r[0])
        if 1 <= L <= 20:
            counts[L-1] += 1
    con.close()

    return render_template_string(PAGE, rows=rows, stats=st, q=qstr, min_score=min_score, min_len=min_len, max_len=max_len, digits=digits, hyphen=hyphen, hist=counts, tlds=tlds, selected_tld=selected_tld)

@app.route("/api/stats")
def api_stats():
    con = connect()
    row = con.execute("SELECT COUNT(*) as total_checked, SUM(is_available) as available, SUM(is_premium) as premium FROM domains").fetchone()
    con.close()
    return jsonify(dict(row))

@app.route("/export.csv")
def export_csv():
    con = connect()
    cur = con.execute("SELECT domain,tld,score,is_premium,premium_registration_price,premium_renewal_price,icann_fee,checked_at FROM domains WHERE is_available=1 ORDER BY score DESC")
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["domain","tld","score","is_premium","premium_registration_price","premium_renewal_price","icann_fee","checked_at"])
    for r in cur.fetchall():
        cw.writerow([r["domain"], r["tld"], r["score"], r["is_premium"], r["premium_registration_price"], r["premium_renewal_price"], r["icann_fee"], r["checked_at"]])
    con.close()
    output = si.getvalue().encode("utf-8")
    return Response(output, mimetype="text/csv", headers={"Content-Disposition":"attachment; filename=available_export.csv"})

@app.route("/export.json")
def export_json():
    con = connect()
    cur = con.execute("SELECT domain,tld,score,is_premium,premium_registration_price,premium_renewal_price,icann_fee,checked_at FROM domains WHERE is_available=1 ORDER BY score DESC")
    rows = [dict(r) for r in cur.fetchall()]
    con.close()
    return jsonify(rows)

@app.route("/feedback")
def feedback():
    domain = request.args.get("domain","")
    label = request.args.get("label","")
    if not domain or not label:
        return redirect("/")
    con = connect()
    con.execute("INSERT OR REPLACE INTO feedback(domain,label) VALUES (?,?)", (domain, label))
    # update bigrams
    try:
        sld = ".".join(domain.split(".")[:-1])
        bigrams = [sld[i:i+2] for i in range(len(sld)-1)]
        for bg in bigrams:
            con.execute("INSERT INTO model_bigrams(bigram, weight) VALUES (?, 1.0) ON CONFLICT(bigram) DO UPDATE SET weight = weight + 1.0", (bg,))
        con.commit()
    finally:
        con.close()
    return redirect("/")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8088")), debug=False)
