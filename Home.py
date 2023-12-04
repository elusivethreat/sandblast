import json
import time
import hashlib
import streamlit as st
from hashlib import sha1
from subprocess import run as proc_run
#from streamlit_agraph import agraph, Node, Edge, Config
from streamlit_extras.switch_page_button import switch_page
from pprint import pformat


class ETRSandbox:

    def __init__(self) -> None:
        self.target_file = ""
        self.target_data = b''
        self.emu_report = None
    
    def generate_overview(self):
        time.sleep(5)
        switch_page('Overview')
        
        while True:
            with st.spinner('Generating Report...'):
                capa_res = proc_run(['tools/capa', f'uploads/{self.target_file}'], capture_output=True)
                if capa_res.stdout:
                    break
        
        st.code(capa_res.stdout.decode())

                
    def gen_behavior_graph(self):
        nodes = []
        edges = []
        nodes.append(Node(id="Test",
                          label="Testing1",
                          size=25,
                          shape="circularImage",
                          image='/home/sandbox/Desktop/CustomSandbox/WebApp/uploads/cmd.png'))
        nodes.append( Node(id="Spiderman", 
                        label="Peter Parker", 
                        size=25, 
                        shape="circularImage",
                        image="http://marvel-force-chart.surge.sh/marvel_force_chart_img/top_spiderman.png") 
                    ) # includes **kwargs
        nodes.append( Node(id="Captain_Marvel", 
                        size=25,
                        shape="circularImage",
                        image="http://marvel-force-chart.surge.sh/marvel_force_chart_img/top_captainmarvel.png") 
                    )
        edges.append( Edge(source="Captain_Marvel", 
                        label="friend_of", 
                        target="Spiderman", 
                        # **kwargs
                        ) 
                    ) 

        config = Config(width=500,
                        height=950,
                        directed=False, 
                        physics=False, 
                        hierarchical=True,
                        # **kwargs
                        )

        return_value = agraph(nodes=nodes, 
                            edges=edges, 
                            config=config)
        with open('css/graph.css', 'r') as f:
            graph_css = f.read()
        st.markdown(graph_css, unsafe_allow_html=True)
    
    def gen_hashes(self):
    
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()

        md5.update(self.target_data)
        sha1.update(self.target_data)
        sha256.update(self.target_data)

        hashes = f"MD5: {md5.hexdigest()}\nSHA1: {sha1.hexdigest()}\nSHA256: {sha256.hexdigest()}"
        return hashes

    def gen_ioc_report(self):
        st.markdown('## IOCs')
        
        st.markdown('**Hashes:**')
        st.code(self.gen_hashes())
        
        if 'file_access' in self.emu_report.keys():
            st.markdown('**File Access:**')
            st.code(pformat(self.emu_report['file_access'], indent=4))
        
        if 'network_events' in self.emu_report.keys():
            st.markdown('**DNS Requests:**')
            st.code(pformat(self.emu_report['network_events']['dns'], indent=4))

            st.markdown('**HTTP/HTTPs requests**')
            st.code(self.emu_report['network_events']['traffic'])

    def extract_strings(self):
        st.markdown(" ## Strings:")
        while True:
            with st.spinner('Extracting strings with Floss...'):
                    floss_res = proc_run(['tools/floss', '-n', '6', f'uploads/{self.target_file}'], capture_output=True)
                    if floss_res.stdout:
                        break
        
        st.code(floss_res.stdout.decode())

    def run(self):
        st.set_page_config(page_title="Offline Sandbox", page_icon=":biohazard_sign:", layout="wide")
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

        # Top of page (logo)
        st.image('images/bluelogo.png', width=300)
        st.markdown("""
        <style>
            [data-testid="stImage"] {
                margin: auto;
                position: center;
                display: flex;
            }
        </style>
        """, unsafe_allow_html=True
        )
        
        # Setup session
        st.session_state['current_file'] = ''
        st.session_state['file_bytes'] = b''
        st.session_state['file_uid'] = ''
        st.session_state['emu_report'] = ''

        # File uploader section
        with st.container():
            # https://discuss.streamlit.io/t/how-to-change-text-language-in-a-widgets/35931
            new_file = st.file_uploader(label='Choose your target', label_visibility='hidden', )
            with open('css/file_uploader.css', 'r') as f:
                file_uploader_css = f.read()
            st.markdown(file_uploader_css,
                    unsafe_allow_html=True,
                    )
            st.markdown("""<hr style="height:5px;border:none;color:#808080;background-color:#808080;" /> """, unsafe_allow_html=True)

        # Store new file if uploaded ; start analysis
        if new_file:
                # Save our new target
                st.session_state['current_file'] = new_file.name
                st.session_state['file_bytes'] = new_file.getvalue()
                
                # Generate UID
                file_id = sha1()
                file_id.update(st.session_state['file_bytes'])
                st.session_state['file_uid'] = file_id.hexdigest()

                with open(f'uploads/{file_id.hexdigest()}_{new_file.name}', 'wb') as f:
                    f.write(new_file.getvalue())

                # Send status
                st.success("File uploaded succesfully!")
                
                # Overview
                self.generate_overview()
                
            
# Execute 
etr = ETRSandbox()
etr.run()