import streamlit as st
from os import listdir
from hashlib import md5
from subprocess import run as proc_run

st.set_page_config(page_title="Offline Sandbox", page_icon=":biohazard_sign:", layout="wide")

def set_header():
    #st.set_page_config(page_title="Offline Sandbox", page_icon=":biohazard_sign:", layout="wide")
    # Hide streamlit branding
    hide_streamlit_style = """
        <style>
        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
        .stDeployButton {
            visibility: hidden;
        }
        </style>
        """
    st.markdown(hide_streamlit_style, unsafe_allow_html=True) 
    st.markdown("# Overview")
    st.markdown("""<hr style="height:5px;border:none;color:#808080;background-color:#808080;" /> """, unsafe_allow_html=True)

def already_reported():
    current_report = st.session_state['file_uid'] + '_capa.txt'
    known_files = listdir('reports')

    for report in known_files:
        if report == current_report:
            return True
    
def continue_to_execute():
    init_keys = 0
    req_keys = ['current_file', 'file_uid', 'file_bytes']
    current_keys = st.session_state.keys()

    for key in current_keys:
        if key in req_keys:
            if len(st.session_state[key]) > 1:
                init_keys += 1

    if init_keys == len(req_keys):
        return True

def load():
    
    # Establish Header across pages
    set_header()

    # Start analysis
    capa_report = ''
    if not continue_to_execute():
        return
    
    file_uid = st.session_state['file_uid']
    target_file = file_uid + '_' + st.session_state['current_file']
    
    
    # We already did the analysis
    if not already_reported():    
        while True:
            with st.spinner('Generating Report...'):
                capa_res = proc_run(['tools/capa', f'uploads/{target_file}'], capture_output=True)
                if capa_res.stdout:
                    break
                
        with open(f'reports/{file_uid}_capa.txt', 'w') as f:
            f.write(capa_res.stdout.decode())
            # Store results
            capa_report = capa_res.stdout.decode()
    else:
        # Read report
        with open(f'reports/{file_uid}_capa.txt', 'r') as f:
            capa_report = f.read()

    st.code(capa_report)

# Execute
load()