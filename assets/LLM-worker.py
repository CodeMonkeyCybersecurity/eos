#!/usr/bin/env python3
# /usr/local/bin/llm-worker.py
# 750 stanley:stanley 

"""
Wazuh Alert LLM Worker – Azure-native, REST-only, real-time with backlog drain + NOTIFY+POLL
"""

import os, select, json, psycopg2, time, traceback, requests, hashlib
from datetime import datetime
from dotenv import load_dotenv

# ───── Load Environment Variables ─────
load_dotenv("/opt/stackstorm/packs/delphi/.env")
PG_DSN = os.getenv("PG_DSN")

PG_DSN         = os.getenv("PG_DSN")
API_KEY        = os.getenv("AZURE_OPENAI_API_KEY")
ENDPOINT       = os.getenv("ENDPOINT_URL")
DEPLOYMENT     = os.getenv("DEPLOYMENT_NAME")
API_VERSION    = os.getenv("AZURE_API_VERSION")

# these two you can default to the values from .env
PROMPT_FILE    = os.getenv("PROMPT_FILE", "/opt/system-prompt.txt")
LOG_FILE       = os.getenv("LOG_FILE", "/var/log/stackstorm/llm-worker.log")
HEARTBEAT_FILE = os.getenv("HEARTBEAT_FILE", "/var/log/stackstorm/llm-worker.heartbeat")
MAX_LOG_SIZE   = int(os.getenv("MAX_LOG_SIZE", 10 * 1024 * 1024))

def debug_log(msg):
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    try:
        if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > MAX_LOG_SIZE:
            os.rename(LOG_FILE, LOG_FILE + ".old")
    except: pass
    with open(LOG_FILE, "a") as f:
        f.write(f"[{ts}] {msg}\n")

def update_heartbeat():
    try:
        with open(HEARTBEAT_FILE, "w") as f:
            f.write(str(int(time.time())))
    except: pass

def load_system_prompt():
    if not os.path.exists(PROMPT_FILE):
        debug_log("System prompt missing, exiting")
        exit(2)
    txt = open(PROMPT_FILE).read().strip()
    if not txt:
        debug_log("System prompt empty, exiting")
        exit(2)
    debug_log(f"Loaded system prompt ({len(txt)} chars)")
    return txt

def azure_chat(system_prompt, alert_id, alert_json, retries=3):
    url = f"{ENDPOINT}/openai/deployments/{DEPLOYMENT}/chat/completions?api-version={API_VERSION}"
    headers = {"Content-Type":"application/json", "api-key":API_KEY}
    user = json.dumps(alert_json)
    prompt = system_prompt + "\n\nPlease explain what happened, what to do, and how to check for a non-technical user in one paragraph:\n\n" + user
    prompt_hash = hashlib.sha1(prompt.encode()).hexdigest()
    debug_log(f"Alert {alert_id}: prompt hash={prompt_hash} len={len(prompt)}")
    body = {"messages":[{"role":"system","content":system_prompt},
                       {"role":"user","content":prompt}],
            "max_tokens":800,"temperature":1.0,"top_p":1.0}
    for attempt in range(1, retries+1):
        try:
            start = time.time()
            r = requests.post(url, headers=headers, json=body, timeout=45)
            r.raise_for_status()
            duration = time.time()-start
            resp = r.json()["choices"][0]["message"]["content"].strip()
            debug_log(f"Alert {alert_id}: Azure returned {len(resp)} chars in {duration:.2f}s")
            return prompt, datetime.utcnow(), resp, datetime.utcnow()
        except Exception as e:
            debug_log(f"Alert {alert_id}: Azure error #{attempt}: {e}")
            if attempt < retries:
                time.sleep(5*attempt)
            else:
                raise

def process_alerts(conn, system_prompt, batch_size=5):
    with conn.cursor() as curs:
        # get the next batch
        curs.execute("""
            SELECT id, raw
              FROM alerts
             WHERE state = 'new'
             ORDER BY ingest_timestamp
             LIMIT %s
             FOR UPDATE SKIP LOCKED
        """, (batch_size,))
        rows = curs.fetchall()
        if not rows:
            return 0

        for alert_id, raw in rows:
            try:
                alert_json = raw if isinstance(raw, dict) else json.loads(raw)
            except Exception as e:
                debug_log(f"Alert {alert_id}: JSON parse error: {e}")
                continue

            try:
                prompt_text, prompt_sent_at, resp_text, resp_received_at = \
                    azure_chat(system_prompt, alert_id, alert_json)
            except Exception as e:
                debug_log(f"Alert {alert_id}: LLM call failed: {e}")
                continue

            # now do a per-row transaction
            try:
                curs.execute("BEGIN")
                curs.execute("""
                    UPDATE alerts
                       SET prompt_sent_at       = %s,
                           prompt_text          = %s,
                           response_received_at = %s,
                           response_text        = %s,
                           state                = 'summarized'
                     WHERE id = %s
                """, (
                    prompt_sent_at,
                    prompt_text,
                    resp_received_at,
                    resp_text,
                    alert_id
                ))
                debug_log(f"Alert {alert_id}: UPDATE rowcount={curs.rowcount}")
                curs.execute("COMMIT")
            except Exception as e:
                debug_log(f"Alert {alert_id}: DB update failed: {e}")
                curs.execute("ROLLBACK")

        return len(rows)

def main():
    sp = load_system_prompt()
    try:
        conn = psycopg2.connect(PG_DSN); conn.set_session(autocommit=True)
        debug_log("Connected to Postgres")
    except Exception as e:
        debug_log(f"DB connect failed: {e}")
        return

    # 1) initial backlog drain
    drained = process_alerts(conn, sp, batch_size=1000)
    debug_log(f"Drained initial backlog of {drained} alerts")

    # 2) LISTEN + POLL loop
    curs = conn.cursor()
    curs.execute("LISTEN new_alert;")
    debug_log("LISTEN new_alert established")

    while True:
        update_heartbeat()
        r,_,_ = select.select([conn],[],[],30)
        if r:
            conn.poll()
            debug_log("Woke on NOTIFY")
        else:
            debug_log("Notify timeout, manual poll")

        # 3) process up to X new alerts
        n = process_alerts(conn, sp, batch_size=5)
        debug_log(f"Processed {n} alerts this cycle")

if __name__ == "__main__":
    main()