import re
import hashlib
import streamlit as st
from os import listdir
from pprint import pformat
from subprocess import run as proc_run

st.set_page_config(page_title="Offline Sandbox", page_icon="images/hazard.png", layout="wide")

def set_header():
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
    st.markdown("# IOC Report")
    st.markdown("""<hr style="height:5px;border:none;color:#808080;background-color:#808080;" /> """, unsafe_allow_html=True)

def gen_hashes():
    
    target_data = st.session_state['file_bytes']
    
    # Setup hashes
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    
    md5.update(target_data)
    sha1.update(target_data)
    sha256.update(target_data)

    hashes = f"MD5: {md5.hexdigest()}\nSHA1: {sha1.hexdigest()}\nSHA256: {sha256.hexdigest()}"
    return hashes

def continue_to_execute():
    init_keys = 0
    req_keys = ['current_file', 'file_uid', 'file_bytes', 'emu_report']
    current_keys = st.session_state.keys()

    for key in current_keys:
        if key in req_keys:
            if len(st.session_state[key]) > 1:
                init_keys += 1

    if init_keys == len(req_keys):
        return True

def already_reported():
    current_report = st.session_state['file_uid'] + '_' + st.session_state['current_file'] +'_capa_verbose.txt'
    known_files = listdir('reports')

    for report in known_files:
        if report == current_report:
            return True

def clean_capa_results(target_file):
    with open(f'reports/{target_file}_capa_verbose.txt', 'r') as f:
            raw_report = f.readlines()

    formatted = ""
    for line in raw_report:
        if line == '\n':
            line = "\n" + "-" * 175 + "\n"
        formatted += line

    # Skip start
    start_index = formatted.find('-'*175)
    end_index = formatted.find('-'*175+'\n'+'-'*175+'\n' + '-'*175)

    # Cleaned header/footer
    cleaned = formatted[start_index:-606]

    # Add coloring
    starting_blocks = re.finditer('-' * 175, cleaned)

    final_output = cleaned
    for block in starting_blocks:
        chunk = cleaned[block.start():block.end()+5]
        added_comment = cleaned[block.start():block.end()+1] + '# ' + cleaned[block.end()+1:block.end()+5]
        final_output = final_output.replace(chunk, added_comment)
    
    return final_output

def gen_ioc_report():
    # Configure header
    set_header()

    if not continue_to_execute():
        return
    
    st.markdown('**Hashes:**')
    
    st.code(gen_hashes())

    emu_report = st.session_state['emu_report']
    
    if 'file_access' in emu_report.keys():
        st.markdown('**File Access:**')
        st.code(pformat(emu_report['file_access'], indent=4))

    if 'network_events' in emu_report.keys():
        st.markdown('**DNS Requests:**')
        st.code(pformat(emu_report['network_events']['dns'], indent=4))

        st.markdown('**HTTP/HTTPs requests**')
        st.code(pformat(emu_report['network_events']['traffic'], indent=4))
    
    if 'process_events' in emu_report.keys():
        st.markdown('**Process Creation:**')
        st.code(pformat(emu_report['process_events'], indent=4))

    # Dump all Capa info
    st.markdown("**Capa based rules:**")
    target_file = st.session_state['file_uid'] + '_' + st.session_state['current_file']
    
    if not already_reported():
        while True:
            with st.spinner('Generating Report...'):
                
                if st.session_state['shellcode']:
                    capa_res = proc_run(['tools/capa', '-vv', '-fsc64', f'uploads/{target_file}'], capture_output=True)
                else:
                    capa_res = proc_run(['tools/capa', '-vv', f'uploads/{target_file}'], capture_output=True)
                
                if capa_res.stdout:
                    break
                        
        with open(f'reports/{target_file}_capa_verbose.txt', 'w') as f:
            f.write(capa_res.stdout.decode())
            # Store results
            raw_report = capa_res.stdout.decode()
    else:
        with open(f'reports/{target_file}_capa_verbose.txt', 'r') as f:
                raw_report = f.read()
    
    cleaned_report = clean_capa_results(target_file)
    st.code(cleaned_report)

    
    

# Execute

gen_ioc_report()