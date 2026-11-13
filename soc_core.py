"""Synthetic SOC incident analytics demo with MCP-style discoverable tool functions.

This is a simulated MCP toolset (ordinary Python functions), NOT a deployed MCP server.
All facts and entities in this database are fictitious.
"""
import json
import os
import re
import sqlite3
from pathlib import Path

try:
    import sqlparse
    from sqlparse import tokens as T
except ImportError:
    sqlparse = None
    T = None

BASE_DIR = Path(__file__).resolve().parent
DB_FILE = BASE_DIR / 'soc_incidents.sqlite'
SCHEMA_FILE = BASE_DIR / 'soc_schema.txt'

SEED_SQL = '''
CREATE TABLE IF NOT EXISTS assets (
 asset_id TEXT PRIMARY KEY, hostname TEXT NOT NULL, business_unit TEXT NOT NULL,
 environment TEXT NOT NULL, criticality TEXT NOT NULL, owner_team TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS analysts (
 analyst_id TEXT PRIMARY KEY, display_name TEXT NOT NULL, shift TEXT NOT NULL,
 team TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
 alert_id TEXT PRIMARY KEY, asset_id TEXT NOT NULL, detected_at TEXT NOT NULL,
 severity TEXT NOT NULL, alert_type TEXT NOT NULL, source TEXT NOT NULL,
 status TEXT NOT NULL, mitre_technique TEXT, analyst_id TEXT,
 FOREIGN KEY(asset_id) REFERENCES assets(asset_id),
 FOREIGN KEY(analyst_id) REFERENCES analysts(analyst_id)
);
INSERT OR IGNORE INTO assets VALUES
 ('AST_101','web-gateway-01','Digital Services','Production','Critical','Infrastructure'),
 ('AST_102','fin-app-02','Finance','Production','High','Applications'),
 ('AST_103','hr-laptop-07','People Operations','Endpoint','Medium','IT Support'),
 ('AST_104','db-core-01','Platform','Production','Critical','Database Operations'),
 ('AST_105','dev-ci-03','Engineering','Development','Medium','DevOps');
INSERT OR IGNORE INTO analysts VALUES
 ('ANL_201','Analyst Alpha','Day','Tier 1'),
 ('ANL_202','Analyst Bravo','Night','Tier 1'),
 ('ANL_203','Analyst Charlie','Day','Tier 2');
INSERT OR IGNORE INTO alerts VALUES
 ('ALT_1001','AST_101','2026-10-21 08:12:00','Critical','Credential Stuffing','SIEM','Open','T1110','ANL_201'),
 ('ALT_1002','AST_102','2026-10-21 09:32:00','High','Suspicious PowerShell','EDR','Investigating','T1059.001','ANL_203'),
 ('ALT_1003','AST_103','2026-10-22 10:42:00','Medium','Phishing Email','Email Gateway','Closed','T1566','ANL_201'),
 ('ALT_1004','AST_104','2026-10-22 11:08:00','Critical','Unusual Database Access','SIEM','Open','T1213','ANL_202'),
 ('ALT_1005','AST_105','2026-10-23 14:01:00','Low','Port Scan','NDR','Closed','T1046','ANL_202'),
 ('ALT_1006','AST_101','2026-10-24 07:18:00','High','Web Exploit Attempt','WAF','Investigating','T1190','ANL_203'),
 ('ALT_1007','AST_102','2026-10-24 16:35:00','Medium','Impossible Travel','IAM','Open','T1078','ANL_201'),
 ('ALT_1008','AST_104','2026-10-25 20:13:00','High','Privilege Escalation','EDR','Open','T1068','ANL_203'),
 ('ALT_1009','AST_103','2026-10-26 10:20:00','Low','Blocked Malware','EDR','Closed','T1204','ANL_202'),
 ('ALT_1010','AST_101','2026-10-27 02:45:00','Critical','Brute Force Login','SIEM','Investigating','T1110','ANL_202');
'''

MIGRATION_SQL = '''
CREATE TABLE IF NOT EXISTS incidents (
 incident_id TEXT PRIMARY KEY, alert_id TEXT NOT NULL, priority TEXT NOT NULL,
 incident_category TEXT NOT NULL, opened_at TEXT NOT NULL,
 resolution_hours REAL, disposition TEXT NOT NULL,
 FOREIGN KEY(alert_id) REFERENCES alerts(alert_id)
);
INSERT OR IGNORE INTO incidents VALUES
 ('INC_501','ALT_1001','P1','Identity Attack','2026-10-21 08:30:00',NULL,'In Progress'),
 ('INC_502','ALT_1002','P2','Endpoint Compromise','2026-10-21 10:00:00',5.5,'Contained'),
 ('INC_503','ALT_1004','P1','Data Access','2026-10-22 11:25:00',NULL,'In Progress'),
 ('INC_504','ALT_1006','P2','Web Attack','2026-10-24 07:45:00',2.0,'False Positive'),
 ('INC_505','ALT_1010','P1','Identity Attack','2026-10-27 03:00:00',NULL,'In Progress');
'''

def export_schema():
    with sqlite3.connect(DB_FILE) as conn:
        rows = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()
    SCHEMA_FILE.write_text('\n\n'.join(r[0] for r in rows if r[0]), encoding='utf-8')
    return SCHEMA_FILE

def ensure_database():
    """Create deterministic sample SOC data if absent; do not overwrite user changes."""
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_FILE) as conn:
        conn.executescript(SEED_SQL)
    export_schema()
    return DB_FILE

def migrate_incidents():
    ensure_database()
    with sqlite3.connect(DB_FILE) as conn:
        conn.executescript(MIGRATION_SQL)
    export_schema()
    return 'incidents'

def reset_database():
    if DB_FILE.exists():
        DB_FILE.unlink()
    return ensure_database()

def connect_read_only():
    # SQLite query_only is a second protection beyond mode=ro.
    conn = sqlite3.connect(DB_FILE.resolve().as_uri() + '?mode=ro', uri=True)
    conn.execute('PRAGMA query_only=ON')
    conn.execute('PRAGMA busy_timeout=3000')
    conn.set_progress_handler(lambda: 1, 200000)  # stop expensive queries
    return conn

def validate_select(query: str):
    """Reject stacked statements, comments, PRAGMA, and SQL outside SELECT.

    sqlparse provides token checks, not a comprehensive SQL security AST.
    SQLite's read-only connection is the binding write prohibition.
    """
    if not isinstance(query, str) or len(query) > 4000:
        return False
    if not re.match(r'^\s*SELECT\b', query, re.IGNORECASE):
        return False
    if '--' in query or '/*' in query or '*/' in query or query.rstrip('; \n\t').find(';') >= 0:
        return False
    if sqlparse is not None:
        parsed = sqlparse.parse(query)
        if len(parsed) != 1 or parsed[0].get_type() != 'SELECT':
            return False
        for tok in parsed[0].flatten():
            if tok.ttype in T.Comment:
                return False
            if tok.value.upper() in {'PRAGMA','ATTACH','DETACH','VACUUM','INSERT','UPDATE','DELETE','DROP','CREATE','ALTER','REPLACE','TRUNCATE'}:
                return False
    return True

def mcp_list_tables() -> str:
    """Discover tables currently available in the synthetic SOC database."""
    try:
        with connect_read_only() as conn:
            rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()
        return json.dumps({'status':'success', 'tables':[x[0] for x in rows]})
    except Exception as exc:
        return json.dumps({'status':'error','message':str(exc)})

def mcp_describe_table(table_name: str) -> str:
    """Inspect a discovered SOC table's column definitions.

    Args:
      table_name: Table name from mcp_list_tables (e.g. alerts, assets, analysts).
    """
    try:
        name = table_name.strip()
        with connect_read_only() as conn:
            allowed = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            if name not in allowed:
                return json.dumps({'status':'error','message':'Unknown table'})
            columns = conn.execute(f'PRAGMA table_info("{name}")').fetchall()
        return json.dumps({'status':'success', 'table':name, 'columns':[
            {'name':r[1], 'type':r[2], 'notnull':bool(r[3]), 'primary_key':bool(r[5])} for r in columns]})
    except Exception as exc:
        return json.dumps({'status':'error','message':str(exc)})

def mcp_read_query(sql_query: str) -> str:
    """Execute a single read-only SELECT query against synthetic SOC records.

    Args:
      sql_query: A SQLite SELECT statement. At most 50 rows are returned.
    """
    if not validate_select(sql_query):
        return json.dumps({'status':'blocked', 'message':'Only a single read-only SELECT is permitted.'})
    try:
        with connect_read_only() as conn:
            cur = conn.execute(f'SELECT * FROM ({sql_query.rstrip().rstrip(";")}) LIMIT 51')
            rows = cur.fetchmany(51)
            columns = [col[0] for col in cur.description]
        return json.dumps({'status':'success','columns':columns,'rows':[list(x) for x in rows[:50]],'truncated':len(rows)>50})
    except Exception as exc:
        return json.dumps({'status':'error','message':str(exc)})

def anonymize_soc_entities(text: str) -> str:
    """Mask synthetic IDs and hostnames in the *displayed* agent response."""
    text = re.sub(r'\b(AST_|ALT_|ANL_|INC_)[A-Za-z0-9]+\b', r'\1***', text, flags=re.IGNORECASE)
    text = re.sub(r'\b(?:web-gateway-01|fin-app-02|hr-laptop-07|db-core-01|dev-ci-03)\b', '[REDACTED_HOST]', text, flags=re.IGNORECASE)
    return text

def before_model_guardrail(callback_context, llm_request):
    """Block clear attempts to mutate data; SQL/tool restrictions remain authoritative."""
    from google.genai import types
    from google.adk.models import LlmResponse
    last_text = ''
    for content in reversed(llm_request.contents or []):
        if getattr(content, 'role', None) == 'user':
            last_text = ' '.join(part.text or '' for part in (content.parts or []) if getattr(part,'text',None)).lower()
            break
    if re.search(r'\b(drop\s+table|truncate\s+table|delete\s+from|update\s+\w+\s+set|insert\s+into|wipe\s+(?:the\s+)?database)\b', last_text):
        return LlmResponse(content=types.Content(role='model', parts=[types.Part(text='🛡️ Request blocked: this SOC analyst is strictly read-only.')]))
    return None

def make_agent(model='gemini-2.5-flash'):
    from google.adk.agents import Agent
    return Agent(
        name='soc_mcp_analyst', model=model,
        description='Read-only cybersecurity SOC incident intelligence analyst with discoverable database tools.',
        instruction=(
            'You are a defensive Cybersecurity SOC Incident Analyst. The dataset is synthetic. '
            'Use mcp_list_tables to discover tables and mcp_describe_table to inspect relevant schemas '
            'before using mcp_read_query with read-only SELECT statements. Never invent findings. '
            'Explain severity, trends, affected business units, MITRE techniques, incident priorities, '
            'and analyst workload with concise supporting counts. Do not suggest intrusion or offensive actions. '
            'If a table is absent, say it is not present and discover available tables. '
            'Never request or perform data modifications. Do not reveal raw IDs or hostnames in final answers. '
            'General introductions need no database query.'
        ),
        tools=[mcp_list_tables,mcp_describe_table,mcp_read_query],
        before_model_callback=before_model_guardrail
    )

async def ask_agent(prompt, runner, user_id, session_id):
    """Collect only final ADK response content, avoiding tool-call fragments."""
    from google.genai import types
    msg = types.Content(role='user',parts=[types.Part.from_text(text=prompt)])
    output=[]
    async for event in runner.run_async(user_id=user_id, session_id=session_id, new_message=msg):
        if event.is_final_response() and event.content:
            output.extend(p.text for p in (event.content.parts or []) if getattr(p,'text',None))
    return anonymize_soc_entities('\n'.join(output) or 'No final response was returned.')

if __name__=='__main__':
    ensure_database()
    print(mcp_list_tables())
