FROM ubuntu:22.04
WORKDIR /app

RUN mkdir -p /app/tools
RUN mkdir -p /app/uploads
RUN mkdir -p /app/reports
RUN mkdir -p /app/tools/speakeasy
RUN mkdir -p /app/images
RUN mkdir -p /app/css
RUN mkdir -p /app/pages
RUN mkdir -p /app/.streamlit

COPY css/* /app/css
COPY pages/* /app/pages
COPY images/* /app/images
COPY tools/capa /app/tools/
COPY tools/floss /app/tools
COPY Home.py /app
COPY config.toml /app/.streamlit

RUN apt-get update -y
RUN apt-get install python3 python3-pip git -y
RUN python3 -m pip install streamlit streamlit_agraph streamlit_extras
RUN cd tools && git clone https://github.com/mandiant/speakeasy.git
RUN cd tools/speakeasy && python3 -m pip install -r requirements.txt && python3 setup.py install

ENTRYPOINT ["/usr/local/bin/streamlit", "run", "Home.py", "--server.port=8501", "--server.address=0.0.0.0"]