#!/usr/bin/env python3
# /usr/local/bin/llm-worker.py
# 750 stanley:stanley

"""
Wazuh Alert LLM Worker – Azure-native, REST-only, real-time with backlog drain + NOTIFY+POLL
Enhanced with verbose debug logging.
"""

import os, select, json, psycopg2, time, requests, hashlib, traceback
from datetime import datetime
from dotenv import load_dotenv

# ───── Load Environment Variables ─────
load_dotenv("/opt/stackstorm/packs/delphi/.env")
PG_DSN         = os.getenv("PG_DSN")
API_KEY        = os.getenv("AZURE_OPENAI_API_KEY")
ENDPOINT       = os.getenv("ENDPOINT_URL")
DEPLOYMENT     = os.getenv("DEPLOYMENT_NAME")
API_VERSION    = os.getenv("AZURE_API_VERSION")

PROMPT_FILE    = os.getenv("PROMPT_FILE", "/opt/system-prompt.txt")
LOG_FILE       = os.getenv("LOG_FILE", "/var/log/stackstorm/llm-worker.log")
HEARTBEAT_FILE = os.getenv("HEARTBEAT_FILE", "/var/log/stackstorm/llm-worker.heartbeat")
MAX_LOG_SIZE   = int(os.getenv("MAX_LOG_SIZE", 10 * 1024 * 1024))

def debug_log(msg):
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    try:
        if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > MAX_LOG_SIZE:
            os.rename(LOG_FILE, LOG_FILE + ".old")
    except Exception:
        pass
    with open(LOG_FILE, "a") as f:
        f.write(f"[{ts}] {msg}\n")

def update_heartbeat():
    try:
        with open(HEARTBEAT_FILE, "w") as f:
            f.write(str(int(time.time())))
    except Exception as e:
        debug_log(f"Heartbeat update failed: {e}")

def load_system_prompt():
    debug_log("Loading system prompt from %r" % PROMPT_FILE)
    if not os.path.exists(PROMPT_FILE):
        debug_log("ERROR: System prompt missing, exiting")
        exit(2)
    txt = open(PROMPT_FILE).read().strip()
    if not txt:
        debug_log("ERROR: System prompt empty, exiting")
        exit(2)
    debug_log(f"Loaded system prompt ({len(txt)} chars)")
    return txt

def azure_chat(system_prompt, alert_id, alert_json, retries=3):
    url = f"{ENDPOINT}/openai/deployments/{DEPLOYMENT}/chat/completions?api-version={API_VERSION}"
    headers = {"Content-Type":"application/json", "api-key":API_KEY}
    user_payload = json.dumps(alert_json)
    prompt = (
        system_prompt
        + "\n\nPlease explain what happened, what to do, and how to check for a non-technical user in one paragraph:\n\n"
        + user_payload
    )
    prompt_hash = hashlib.sha1(prompt.encode()).hexdigest()
    debug_log(f"Alert {alert_id}: preparing LLM prompt (hash={prompt_hash}, length={len(prompt)})")
    body = {
        "messages": [
            {"role":"system","content":system_prompt},
            {"role":"user","content":prompt}
        ],
        "max_tokens":800,"temperature":1.0,"top_p":1.0
    }
    for attempt in range(1, retries+1):
        try:
            debug_log(f"Alert {alert_id}: HTTP POST to {url} (attempt {attempt})")
            start = time.time()
            r = requests.post(url, headers=headers, json=body, timeout=45)
            debug_log(f"Alert {alert_id}: HTTP status={r.status_code} time={(time.time()-start):.2f}s")
            r.raise_for_status()
            resp = r.json()["choices"][0]["message"]["content"].strip()
            debug_log(f"Alert {alert_id}: received {len(resp)} chars from Azure")
            return prompt, datetime.utcnow(), resp, datetime.utcnow()
        except Exception as e:
            debug_log(f"Alert {alert_id}: Azure error #{attempt}: {e}")
            debug_log(traceback.format_exc())
            if attempt < retries:
                sleep_for = 5 * attempt
                debug_log(f"Alert {alert_id}: retrying after {sleep_for}s")
                time.sleep(sleep_for)
            else:
                debug_log(f"Alert {alert_id}: out of retries, propagating")
                raise

def process_alerts(conn, system_prompt, batch_size=5):
    with conn.cursor() as curs:
        debug_log(f"Fetching up to {batch_size} new alerts (state='new')")
        curs.execute("""
            SELECT id, raw
              FROM alerts
             WHERE state = 'new'
             ORDER BY ingest_timestamp
             LIMIT %s
             FOR UPDATE SKIP LOCKED
        """, (batch_size,))
        rows = curs.fetchall()
        ids = [r[0] for r in rows]
        debug_log(f"Fetched {len(rows)} rows, IDs={ids!r}")
        if not rows:
            return 0

        processed = 0
        for alert_id, raw in rows:
            debug_log(f"--- Processing alert {alert_id} raw_len={len(str(raw))} ---")
            try:
                alert_json = raw if isinstance(raw, dict) else json.loads(raw)
            except Exception as e:
                debug_log(f"Alert {alert_id}: JSON parse error: {e}")
                debug_log(traceback.format_exc())
                continue

            try:
                prompt_text, prompt_sent_at, resp_text, resp_received_at = \
                    azure_chat(system_prompt, alert_id, alert_json)
            except Exception as e:
                debug_log(f"Alert {alert_id}: LLM call failed: {e}")
                continue

            try:
                debug_log(f"Alert {alert_id}: BEGIN DB transaction")
                curs.execute("BEGIN")
                curs.execute("""
                    UPDATE alerts
                       SET prompt_sent_at       = %s,
                           prompt_text          = %s,
                           response_received_at = %s,
                           response_text        = %s,
                           state                = 'summarized'
                     WHERE id = %s
                """, (prompt_sent_at, prompt_text, resp_received_at, resp_text, alert_id))
                debug_log(f"Alert {alert_id}: UPDATE rowcount={curs.rowcount}")
                curs.execute("COMMIT")
                debug_log(f"Alert {alert_id}: COMMIT succeeded")
                processed += 1
            except Exception as e:
                debug_log(f"Alert {alert_id}: DB update failed: {e}")
                debug_log(traceback.format_exc())
                curs.execute("ROLLBACK")
                debug_log(f"Alert {alert_id}: ROLLBACK complete")

        return processed

def main():
    sp = load_system_prompt()
    try:
        conn = psycopg2.connect(PG_DSN); conn.set_session(autocommit=True)
        debug_log("Connected to Postgres")
    except Exception as e:
        debug_log(f"DB connect failed: {e}")
        debug_log(traceback.format_exc())
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
        debug_log("Waiting for NOTIFY or timeout…")
        r,_,_ = select.select([conn], [], [], 30)
        if r:
            conn.poll()
            notifies = [n.payload for n in conn.notifies]
            debug_log(f"Woke on NOTIFY, payloads={notifies}")
            conn.notifies.clear()
        else:
            debug_log("Notify timeout reached, falling back to manual poll")

        n = process_alerts(conn, sp, batch_size=5)
        debug_log(f"Processed {n} alerts this cycle")

if __name__ == "__main__":
    main()