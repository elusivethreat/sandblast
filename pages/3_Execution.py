import json
import streamlit as st
from os import listdir
from subprocess import run as proc_run
from pprint import pformat

st.set_page_config(page_title="Offline Sandbox", page_icon="images/hazard.png", layout="wide")

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
    st.markdown("# Execution")
    st.markdown("""<hr style="height:5px;border:none;color:#808080;background-color:#808080;" /> """, unsafe_allow_html=True)


def build_api_list(executed_instructions):
    # Build chain of APIs that were called
    executed_apis = []

    for inst in executed_instructions:
        
        # Get API args 
        args = ""
        for arg in inst['args']:
            args += arg + ', '
        current_api = inst['api_name'] + '(' + args[:-2] + ')\n'
        if current_api not in executed_apis:
            executed_apis.append(current_api)
    
    return executed_apis


def cherry_pick_apis(entries):
    api_of_interest = ['KERNEL32.CreateNamedPipe', 'KERNEL32.ReadFile', 'KERNEL32.CreateFile', 'msvcrt.sprintf']
    executed_apis = []
    found = ""
    
    for entry in entries:
        
        # Our main entry (EXE and shellcode)
        if entry['ep_type']== 'module_entry' or entry['ep_type'] == 'shellcode':
            
            # Parse report and verify no errors
            st.session_state['emu_report'] = entry
            if len(entry['apis']) >= 1:
                all_instructions = entry['apis']
                # Build chain of APIs that were called
                executed_apis = build_api_list(all_instructions)
                for api in executed_apis:
                    found += api + '\n'
            
            # Build error report
            elif entry['error']:
                error_emulating = "# Runtime error occurred during emulation: \n\n" + pformat(entry['error'], indent=4)
                return error_emulating
            
        
        elif st.session_state['is_dll'] :
            # Assign the "main" emu_report as the one that had network/process events
            if 'network_events' in entry.keys() or 'process_events' in entry.keys() or 'file_access' in entry.keys():
                st.session_state['emu_report'] = entry
            
    return found

def already_reported():
    current_report = st.session_state['file_uid'] + '_' + st.session_state['current_file'] +'_emulated.json'
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

def start_emulation():

    # Start analysis
    if not continue_to_execute():
        return
    
    name = st.session_state['current_file']
    target_file = st.session_state['file_uid'] + '_' + name 

    if not already_reported():
        while True:
            with st.spinner('Executing binary w/ SpeakEasy ...'):
                if st.session_state['shellcode']:
                    res = proc_run(['python3', '-m', 'speakeasy', '-q', '30', '-r', '-a', 'amd64', '-t', f'uploads/{target_file}', '-o', f'reports/{target_file}_emulated.json'], capture_output=True)
                else:    
                    res = proc_run(['python3', '-m', 'speakeasy', '-q', '30', '-t', f'uploads/{target_file}', '-o', f'reports/{target_file}_emulated.json'], capture_output=True)
                if res.stdout or res.stderr:
                    break
        
        # Save DLL output
        if st.session_state['is_dll']:
            with open(f'reports/{target_file}_emulated_dll.txt', 'w') as f:
                if res.stdout.decode():
                    f.write(res.stdout.decode())
                elif res.stderr.decode():
                    f.write(res.stderr.decode())
        
        # Save regular JSON report
        with open(f'reports/{target_file}_emulated.json', 'r') as f:
            emulated = json.loads(f.read())
        
        data = emulated['entry_points']

        cleaned = cherry_pick_apis(data)
        if cleaned:
            st.code(cleaned)
        else:
            st.code(res.stderr.decode())
    else:
        
        with open(f"reports/{target_file}_emulated.json", 'r') as f:
            data = json.loads(f.read())
    
        cleaned = cherry_pick_apis(data['entry_points'])

        if cleaned:
            # Display parsed APIs
            st.code(cleaned)
        else:
            # For DLLs currently
            with open(f'reports/{target_file}_emulated_dll.txt', 'r') as f:
                data = f.read()
            st.code(data)

def load():
    # Establish Header across pages
    set_header()
    start_emulation()

# Execute
load()

