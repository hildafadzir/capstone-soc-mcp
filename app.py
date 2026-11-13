"""Streamlit interface for the synthetic read-only SOC ADK analyst."""
import asyncio
import os
import uuid
import streamlit as st
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from soc_core import (ensure_database, migrate_incidents, reset_database, export_schema,
                      mcp_list_tables, make_agent, ask_agent)

st.set_page_config(page_title='SOC Incident Analyst | MCP-style', page_icon='🛡️', layout='wide')
try:
    secret_key = st.secrets.get('GOOGLE_API_KEY', '')
except (FileNotFoundError, KeyError):
    secret_key = ''
if secret_key:
    os.environ['GOOGLE_API_KEY'] = secret_key
os.environ.setdefault('GOOGLE_GENAI_USE_VERTEXAI', 'FALSE')
ensure_database()

APP_NAME='soc_mcp_demo'
USER_ID='soc_analyst_demo'

async def new_session():
    service = InMemorySessionService()
    session_id = uuid.uuid4().hex
    await service.create_session(app_name=APP_NAME,user_id=USER_ID,session_id=session_id)
    return service, session_id

if 'service' not in st.session_state:
    st.session_state.service, st.session_state.session_id = asyncio.run(new_session())
    st.session_state.messages=[]

with st.sidebar:
    st.header('🛡️ SOC Analyst')
    st.caption('Synthetic data · discoverable MCP-style tools · read-only access')
    st.subheader('Live schema evolution')
    if st.button('➕ Add incidents table', use_container_width=True):
        migrate_incidents()
        st.success('New incidents table available to agent.')
    if st.button('↩ Reset sample database', use_container_width=True):
        reset_database()
        st.session_state.messages=[]
        st.success('Restored the original three tables.')
    st.subheader('Suggested questions')
    questions=[
        'Which tables exist in the SOC database?',
        'How many alerts are in each severity category?',
        'Which asset criticality has the most open alerts?',
        'Which MITRE ATT&CK techniques appear most often?',
        'Show the alert workload by analyst shift.',
        'How many P1 incidents are still in progress?',
        'Who are you?',
        'DROP TABLE alerts;'
    ]
    for idx,q in enumerate(questions):
        if st.button(q,key=f'q_{idx}',use_container_width=True):
            st.session_state.pending=q
    with st.expander('Live database schema'):
        st.code(export_schema().read_text(encoding='utf-8'),language='sql')
    st.caption('MCP-style demo: Python tool functions, not an external MCP transport server.')

st.title('🛡️ Cybersecurity SOC Incident Analyst')
st.caption('Google ADK + Gemini + SQLite | Dynamic schema discovery | Least-privilege query safeguards')
for msg in st.session_state.messages:
    with st.chat_message(msg['role']):
        st.markdown(msg['content'])

prompt=st.session_state.pop('pending',None) or st.chat_input('Ask about SOC alerts, assets, analysts, or incidents...')
if prompt:
    st.session_state.messages.append({'role':'user','content':prompt})
    with st.chat_message('user'):
        st.markdown(prompt)
    with st.chat_message('assistant'):
        if not os.environ.get('GOOGLE_API_KEY'):
            answer='Set GOOGLE_API_KEY in Streamlit Secrets or your environment to enable the Gemini agent.'
        else:
            try:
                with st.spinner('Analysing synthetic SOC data...'):
                    runner=Runner(agent=make_agent(),app_name=APP_NAME,session_service=st.session_state.service)
                    answer=asyncio.run(ask_agent(prompt,runner,USER_ID,st.session_state.session_id))
            except Exception as exc:
                answer=f'Unable to complete agent request: {type(exc).__name__}: {exc}'
        st.markdown(answer)
    st.session_state.messages.append({'role':'assistant','content':answer})
