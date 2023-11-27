FROM ubuntu:22.04
WORKDIR /app

RUN mkdir -p /app/tools
RUN mkdir -p /app/uploads
RUN mkdir -p /app/reports
RUN mkdir -p /app/tools/speakeasy
RUN mkdir -p /app/images
RUN mkdir -p /app/css
RUN mkdir -p /app/pages

COPY css/* /app/css
COPY pages/* /app/pages
COPY images/* /app/images
COPY tools/speakeasy /app/tools/speakeasy
COPY tools/capa /app/tools/
COPY tools/floss /app/tools
COPY Home.py /app

RUN apt-get update -y
RUN apt-get install python3 python3-pip git -y
RUN python3 -m pip install streamlit streamlit_agraph streamlit_extras
RUN python3 -m pip install -r tools/speakeasy/requirements.txt
RUN cd tools/speakeasy && python3 setup.py install

ENTRYPOINT ["/usr/local/bin/streamlit", "run", "Home.py", "--server.port=8501", "--server.address=0.0.0.0"]