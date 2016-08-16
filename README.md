# TinyWSGI
Lightweight Python uWSGI Framework For Web, Used by Project POSX

# External Python Library Dependencies
* Mako - Template Engine
* Mysql Connector - Database Client

# Usage

### /ABC/web/wsgi_start.py
```python
import tinywsgi4 as wsgi
import config

application = wsgi.Application(True, config.APP_DIR, web_dir='/web', cfg=config, gzip=True).application
```

### /ABC/web/request/test.py
```python
import tinywsgi4 as tinywsgi

class RequestHandler(tinywsgi.RequestHandler):
  def fn_hello(self):
    #output query as json
    self.req.writejs(self.qsd)
```

### Apache httpd.conf
```
WSGIScriptAliasMatch ^/web/([0-9a-zA-Z_]+)$ /ABC/web/wsgi_start.py
```

Access http://localhost/web/test?fn=hello&param1=123 to dump the query as json


