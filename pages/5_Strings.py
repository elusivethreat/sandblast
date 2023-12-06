import streamlit as st
from os import listdir
from subprocess import run as proc_run


st.set_page_config(page_title="Offline Sandbox", page_icon="images/hazard.png", layout="wide")

def set_header():
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
    st.markdown("# Extracted strings")
    st.markdown("""<hr style="height:5px;border:none;color:#808080;background-color:#808080;" /> """, unsafe_allow_html=True)


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

def already_reported():
    current_report = st.session_state['file_uid'] + '_' + st.session_state['current_file'] +'_strings.txt'
    known_files = listdir('reports')

    for report in known_files:
        if report == current_report:
            return True


def get_strings():
    
    # Setup title
    set_header()
    
    # Verify we have req keys
    if not continue_to_execute():
         return

    target_file = target_file = st.session_state['file_uid'] + '_' + st.session_state['current_file'] 

    if not already_reported():
        while True:
            with st.spinner('Extracting strings with Floss...'):
                    
                    if st.session_state['shellcode']:
                        floss_res = proc_run(['tools/floss', '-n', '6', '-fsc64', f'uploads/{target_file}'], capture_output=True)
                    else:    
                        floss_res = proc_run(['tools/floss', '-n', '6', f'uploads/{target_file}'], capture_output=True)
                    
                    if floss_res.stdout:
                        break
        # Save results
        with open(f'reports/{target_file}_strings.txt', 'w') as f:
            f.write(floss_res.stdout.decode())
        
        st.code(floss_res.stdout.decode())
    else:
        with open(f"reports/{target_file}_strings.txt", "r") as f:
            string_report = f.read()
        st.code(string_report)

# Execute
get_strings()