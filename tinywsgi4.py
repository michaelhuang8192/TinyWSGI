import traceback
from httplib import responses
import urlparse
import re
import os
import sys
import time
import thread
import string
import cgi
import time
import Cookie
import gzip
import json
import cStringIO

from mako.lookup import TemplateLookup
import mysql.connector


#database connections cache, (default, alt)
g_l_dbrefs = ([], [])


class TinyFieldStorage(cgi.FieldStorage):
    def to_dict(self):
        d = {}
        for o in self.list:
            if o.file:
                d.setdefault(o.name, []).append(o.file)
            else:
                d.setdefault(o.name, []).append(o.value)

        return d

class Module:
    def __init__(self, app):
        self.App = app

class ModuleRef:
    def __init__(self, tid, fname, app):
        self.loaded = False
        self.tid = tid
        self.fname = fname
        self.module = Module(app)
        
    def load(self):
        m = self.module
        m.__file__ = self.fname
        try:
            execfile(self.fname, m.__dict__)
        except:
            m.__dict__.clear()
            raise
        finally:
            m.__file__ = self.fname
        
        self.loaded = True
        
    def cleanup(self):
        self.module.__dict__.clear()

class Application:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        self.create_new_instance()
        
        app = self.appref.app
        if not app.debug:
            self.rev_file = os.path.join(app.app_dir, '.git/refs/heads/master')
            thread.start_new_thread(self.monitor, ())
    
    def create_new_instance(self):
        self.appref = ApplicationRef(*self.args, **self.kwargs)

    def monitor(self):
        last_st_mtime = None
        
        while True:
            time.sleep(1)
            try:
                if os.path.exists(self.rev_file):
                    st_mtime = os.stat(self.rev_file).st_mtime
                    if last_st_mtime == None:
                        last_st_mtime = st_mtime
                    elif last_st_mtime < st_mtime:
                        last_st_mtime = st_mtime
                        self.create_new_instance()
                        
            except Exception, e:
                print traceback.format_exc()
        
    def application(self, environ, start_response):
        appref = self.appref
        try:
            output = appref.app.application(environ, start_response)
        finally:
            appref = None
            
        return output

class ApplicationRef:
    def __init__(self, *args, **kwargs):
        self.app = _Application(*args, **kwargs)

    def __del__(self):
        self.app.cleanup()
        self.app = None

class _Application:
    headers = {
        'content-type': 'text/html',
        'cache-control': 'no-cache, must-revalidate',
        'expires': 'Thu, 01 Jan 1970 00:00:00 GMT'
    }
    
    def __init__(self, debug=False, app_dir=None, tmpl_conf={}, encoding='utf-8', gzip=False, web_dir=None, cfg=object()):
        self.cfg = cfg
        self.aid = id(self)
        
        self.encoding = encoding
        self.debug = debug
        self.gzip = gzip
        self.app_dir = app_dir = os.path.abspath(app_dir)
        self.req_dir = os.path.join(self.app_dir, 'request')
        self.web_dir = web_dir or ''
        
        orig_dir = os.path.normpath(os.path.join(app_dir, tmpl_conf.get('orig_dir', 'tmpl/orig')))
        exec_dir = os.path.normpath(os.path.join(app_dir, tmpl_conf.get('exec_dir', 'tmpl/exec')))
        self.tmpl = TemplateLookup(orig_dir, exec_dir, debug, input_encoding=encoding, output_encoding=encoding)
    
        self.als = {}
    
        self.__modrefs = {}
        self.__threads = {}
    
    def cleanup(self):
        for m in self.__modrefs.values():
            m.cleanup()
        self.__modrefs.clear()
        self.__threads.clear()
        self.als.clear()
        
    def application(self, environ, start_response):
        ts = time.time()
        tid = thread.get_ident()
        tdata = self.__threads.get(tid)
        if tdata == None:
            #current_request, thread_local_storage, thread_module_refs
            tdata = self.__threads[tid] = [None, {}, {}]
        
        try:
            tdata[0] = req = Request(self, environ, tdata[1])
            
            #get module name
            pi = environ.get('PATH_INFO') or environ.get('SCRIPT_NAME')
            if pi != None and pi[:len(self.web_dir)] == self.web_dir:
                pi = pi[len(self.web_dir):]
                if pi[:1] != '/' or len(pi) == 1: pi = '/default'
            else:
                pi = '/default'
            
            #process request
            while pi:
                nz = os.path.normpath(self.req_dir + pi)
                if nz[:len(self.req_dir)] == self.req_dir and os.path.isfile(nz + '.py'):
                    handler = self.load(nz[len(self.app_dir):]).RequestHandler
                else:
                    handler = RequestHandler

                #process request
                hinst = handler(req)
                try:
                    hinst.handle()
                except RequestExitException, ree:
                    pass
                finally:
                    hinst.cleanup()
                    hinst = None

                pi, req._next_req_handler = req._next_req_handler, None
            
            #build response
            status = req.out_status
            output = ''.join(req.out_res)
            cookie = [ c.OutputString() for c in req.out_cookie.values() ]
            status = "%s %s" % (status, responses.get(status, 'UNKNOWN'))
            headers = self.headers.copy()
            headers.update(req.out_headers)
            
            #gzip
            if self.gzip and output and not headers.has_key('content-encoding') \
            and environ.get('HTTP_ACCEPT_ENCODING', '').lower().find('gzip') >= 0:
                headers['content-encoding'] = 'gzip'
                gfp = cStringIO.StringIO()
                gzf = gzip.GzipFile(fileobj=gfp, mode='wb')
                gzf.write(output)
                gzf.close()
                output = gfp.getvalue()
                is_gzip = 1
            
            headers['content-length'] = len(output)
            headers = [ (string.capwords(k, '-'), str(v)) for k,v in headers.items() ]
            headers.extend( [ ('Set-Cookie', c) for c in cookie ] )
            
        except Exception, e:
            status = 200
            output = traceback.format_exc()
            if isinstance(output, unicode): output = output.encode(self.encoding)
            status = "%s %s" % (status, responses.get(status, 'UNKNOWN'))
            headers = self.headers.copy()
            headers['content-length'] = len(output)
            headers = [ (string.capwords(k, '-'), str(v)) for k,v in headers.items() ]
        
        finally:
            if tdata[0]:
                tdata[0].cleanup()
                tdata[0] = None
            if self.debug:
                tdata[1].clear()
                tdata[2].clear()
                self.als.clear()
        
        headers.append( ('SYS', 'TS:%0.3f, TID:%08X, AID:%08X' % (time.time() - ts, tid, self.aid)) )
        start_response(status, headers)
        return [output]
        
    def tls(self):
        return self.__threads[ self.tid() ][1]
    
    def req(self):
        return self.__threads[ self.tid() ][0]
    
    def tid(self):
        return thread.get_ident()
    
    def render(self, fnz, v={}):
        return self.tmpl.get_template(fnz).render(**v)
    
    def load(self, fnz):
        ffnz = os.path.normpath(self.app_dir + fnz + '.py')
        fnz = ffnz[len(self.app_dir):]
        
        tid = self.tid()
        if self.debug:
            modrefs = self.__threads[tid][2]
        else:
            modrefs = self.__modrefs
        
        mref = modrefs.get(fnz)
        if mref != None and (mref.tid == tid or mref.loaded): return mref.module
        
        modrefs[fnz] = mref = ModuleRef(tid, ffnz, self)
        mref.load()
        
        return mref.module

class RequestExitException(Exception):
    pass

class Request:
    def __init__(self, app, environ, tls):
        self.app = app
        self.environ = environ
        self.tls = tls
        self.rls = {}
        
        self.out_status = 200
        
        self.out_res = []
        self.out_headers = {}
        
        self.cookie = Cookie.SimpleCookie()
        if environ.has_key('HTTP_COOKIE'): self.cookie.load(environ['HTTP_COOKIE'])
        self.out_cookie = Cookie.SimpleCookie()
        
        self._psd = None
        
        self.qsd = urlparse.parse_qs(self.environ['QUERY_STRING'], keep_blank_values=True)
        if not self.qsd: self.qsd = {}

        self._next_req_handler = None

        self._l_dbref = [None, None]

    def cleanup(self):
        self.rls.clear()
        self._put_dbref(0)
        self._put_dbref(1)

    def exit(self, status=None, msg=None):
        if status != None: self.out_status = status
        if msg != None: self.writex(msg)
        raise RequestExitException
    
    def exitjs(self, js=None):
        self.exit(None, json.dumps(js, separators=(',',':'), encoding=self.app.encoding))
    
    def redirect_i(self, mod, fn):
        self.qsd['fn'] = [fn]
        self._next_req_handler = '/' + mod
        self.writex('')
        self.exit()

    def redirect(self, url):
        e = self.environ
        full_url = "%s://%s%s" % (e['wsgi.url_scheme'], e['SERVER_NAME'], e['SCRIPT_NAME'])
        nurl = urlparse.urljoin(full_url, url)
        self.out_status = 301
        self.out_headers['location'] = nurl
        self.writex('')
        self.exit()
    
    def writejs(self, o):
        self.write( json.dumps(o, separators=(',',':'), encoding=self.app.encoding) )
    
    def writex(self, v):
        self.out_res = []
        self.write(v)
    
    def write(self, v):
        if isinstance(v, unicode):
            self.out_res.append(v.encode(self.app.encoding))
        else:
            self.out_res.append(str(v))
    
    def writefile(self, fnz, data={}):
        self.out_res.append( self.app.render(fnz, data) )

    def qsv_int(self, k, dv=0):
        v = self.qsd.get(k, [''])[0].strip()
        try:
            v = int(v)
        except:
            v = dv
        return v
        
    def qsv_str(self, k, dv=''):
        return self.qsd.get(k, [dv])[0].strip()
    
    def qsv_ustr(self, k, dv=''):
        return self.qsd.get(k, [dv])[0].decode(self.app.encoding).strip()

    def psv_int(self, k, dv=0):
        v = self.psd().get(k, [''])[0].strip()
        try:
            v = int(v)
        except:
            v = dv
        return v

    def psv_str(self, k, dv=''):
        return self.psd().get(k, [dv])[0].strip()

    def psv_ustr(self, k, dv=''):
        return self.psd().get(k, [dv])[0].decode(self.app.encoding).strip()

    def psv_js(self, k):
        return json.loads(self.psv_str(k), encoding=self.app.encoding)

    def psd(self):
        if not self._psd:
            self._psd = TinyFieldStorage(fp=self.environ.get('wsgi.input'), environ=self.environ, keep_blank_values=True).to_dict()
        return self._psd

    def escape_html(self, s):
        return cgi.escape(s, True)
    
    def str2int(self, s, dv=0):
        try:
            s = int(s)
        except:
            s = dv
        return s

    def dbref(self, idx=0):
        dbref = self._l_dbref[idx]
        if dbref: return dbref
        
        dbrefs = g_l_dbrefs[idx]
        try:
            dbref = dbrefs.pop()
            try:
                cur = dbref.cur()
                cur.execute('select 1')
                cur.fetchall()
            except:
                dbref = None

        except IndexError, e:
            dbref = None
            
        if not dbref:
            dbc = mysql.connector.connect(**self.app.cfg.sql[idx])
            dbref = DBRef(dbc)
            
        self._l_dbref[idx] = dbref
        return dbref

    def _put_dbref(self, idx=0):
        dbref = self._l_dbref[idx]
        if dbref:
            self._l_dbref[idx] = None
            try:
                dbref.dbc.rollback()
            except:
                pass
            dbref.close_curs()
            g_l_dbrefs[idx].append(dbref)


class RequestHandler:
    def __init__(self, req):
        self.req = req
    
    def setup(self):
        pass
    
    def cleanup(self):
        pass
    
    def check_perm(self, fn_nz, fn_inst):
        pass
    
    def precall_fn(self, fn):
        pass
    
    def postcall_fn(self, fn):
        pass
    
    def handle(self):
        self.setup()
        
        fn = self.req.qsv_str('fn', 'default').lower()
        sfn = fn.replace('_', '')
        if sfn.isalnum():
            mn = 'fn_' + fn
            co = getattr(self.__class__, mn, None)
            if co and self.check_perm(fn, co) != False and self.precall_fn(fn) != False:
                if co(self) != False:
                    self.postcall_fn(fn)
    
    def fn_default(self):
        self.req.write('fn_default -> hello')


class DBRef:
    def __init__(self, dbc):
        self.dbc = dbc
        self.curs = []
    
    def commit(self):
        self.dbc.commit()
        
    def cur(self, new=False):
        if len(self.curs) <= 0 or new:
            cur = self.dbc.cursor()
            self.curs.append(cur)
            return cur
        else:
            return self.curs[0]
    
    def close_curs(self):
        for cur in self.curs:
            try:
                cur.close()
            except:
                pass
        self.curs = []
    
    def close_dbc(self):
        self.close_curs()
        if self.dbc:
            try:
                self.dbc.close()
            except:
                pass
            self.dbc = None
    
    def __del__(self):
        self.close_dbc()
