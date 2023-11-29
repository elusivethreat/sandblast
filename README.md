<div align="center">
  <img width="300px" src="images/bluelogo.png" />

  <br/>

  <p><i>Sandblast is a modern malware triaging tool built as an easily deployable container</i></p>
  <br />
  
  <h3> Powered by </h2>
  
  ---
  
  <div>
    <img width="200px" src="https://github.com/mandiant/capa/blob/master/.github/logo.png" hspace="20" alt="" />
    <img width="200px" src="https://github.com/mandiant/flare-floss/blob/master/resources/floss-logo.png" alt="" hspace="20"/>
    <img width="125px" src="https://raw.githubusercontent.com/rizinorg/rizin/dev/doc/img/rizin.svg?sanitize=true" alt="" hspace="20"/>
    <img width="125px" src="https://github.com/unicorn-engine/unicorn/blob/master/docs/unicorn-logo.png" alt=""  hspace="20" />
  </div>
  
</div>

---

# Installation

```
docker pull elusivethreat/sandblast

docker run -it -p 8501:8501 sandbox:latest
```

# Usage

Navigate to `localhost:8501` in your web browser to access the Sandblast. Upload your file to start analysis and use the side-pane to navigate through the reports.

<img src="assets/home.png"/>