"""API Discovery Intelligence: dependency-free local HTTP service (Python 3.9+)."""
import os, json, sqlite3, threading, argparse, time, mimetypes, csv, io, math
from pathlib import Path
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlsplit
from collections import Counter
from engine import normalize, classify, extract_rows, comparator_rows, metrics, BASE, LABELS, label_from_features

ROOT=Path(__file__).resolve().parent
DB=Path(os.environ.get('ADI_DB',str(ROOT/'data'/'inspection.sqlite3')))
LOCK=threading.RLock()
MAX_BODY=12*1024*1024

def connect():
    DB.parent.mkdir(parents=True, exist_ok=True)
    cx=sqlite3.connect(DB,timeout=20)
    cx.row_factory=sqlite3.Row
    cx.execute('PRAGMA busy_timeout=20000')
    cx.execute('PRAGMA journal_mode=WAL')
    return cx

def init():
    with connect() as c:
        c.executescript('''CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY,host TEXT,path TEXT,template TEXT,method TEXT,status INTEGER,content_type TEXT,label TEXT,confidence REAL,probability REAL,score REAL,reasons TEXT,features TEXT,origin TEXT,created REAL);
        CREATE TABLE IF NOT EXISTS weights (feature TEXT PRIMARY KEY,weight REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS reviews (id INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT,expected TEXT,predicted TEXT,source TEXT,reviewed INTEGER,created REAL);
        CREATE TABLE IF NOT EXISTS comparisons (id INTEGER PRIMARY KEY AUTOINCREMENT,metrics TEXT,disagreements TEXT,created REAL);
        CREATE TABLE IF NOT EXISTS endpoint_labels (endpoint TEXT PRIMARY KEY,label TEXT,confirmed INTEGER);
        CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT,kind TEXT,details TEXT,created REAL);''')
        c.execute("INSERT OR IGNORE INTO settings VALUES ('mode','off')")
        for k,v in BASE.items(): c.execute('INSERT OR IGNORE INTO weights VALUES (?,?)',(k,v))

def setting(c,key):
    r=c.execute('SELECT value FROM settings WHERE key=?',(key,)).fetchone()
    return r['value'] if r else None

def getweights(c): return {r['feature']:r['weight'] for r in c.execute('SELECT * FROM weights')}

def run_classification(c,raw,origin):
    record=normalize(raw)
    endpoint=record['host']+'|'+record['method']+'|'+record['template']
    stored=c.execute('SELECT label FROM endpoint_labels WHERE endpoint=? AND confirmed=1',(endpoint,)).fetchone()
    result=classify(raw,getweights(c),stored['label'] if stored else None)
    c.execute('''INSERT OR REPLACE INTO events (id,host,path,template,method,status,content_type,label,confidence,probability,score,reasons,features,origin,created)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', (result['id'],result['host'],result['path'],result['template'],result['method'],result['status'],result['content_type'],result['label'],result['confidence'],result['api_probability'],result['score'],json.dumps(result['reasons']),json.dumps(result['features']),origin,time.time()))
    return {k:v for k,v in result.items() if k!='features'}

def state(c):
    rows=[dict(r) for r in c.execute('SELECT id,host,path,template,method,status,content_type,label,confidence,probability,origin,created,reasons FROM events ORDER BY created DESC LIMIT 250')]
    for r in rows: r['reasons']=json.loads(r['reasons'])
    counts=dict(Counter(r['label'] for r in c.execute('SELECT label FROM events')))
    last=c.execute('SELECT * FROM comparisons ORDER BY id DESC LIMIT 1').fetchone()
    reviews=c.execute('SELECT COUNT(*) AS n FROM reviews WHERE reviewed=1').fetchone()['n']
    pending=c.execute('SELECT COUNT(*) AS n FROM reviews WHERE reviewed=0').fetchone()['n']
    return {'mode':setting(c,'mode'),'counts':{k:counts.get(k,0) for k in LABELS},'total':sum(counts.values()),
            'events':rows,'reviewed':reviews,'pending':pending,'comparison':json.loads(last['metrics']) if last else None,
            'disagreements':json.loads(last['disagreements']) if last else []}

def ingest(c,data,origin):
    rows=extract_rows(data)
    if len(rows)>20000: raise ValueError('Maximum 20,000 traffic records per batch')
    results=[]; errors=[]
    for i,row in enumerate(rows):
        try: results.append(run_classification(c,row,origin))
        except Exception as e: errors.append({'index':i,'error':str(e)[:180]})
    return {'received':len(rows),'processed':len(results),'errors':errors[:100],'results':results[:500]}

def compare(c, data):
    ref=comparator_rows(data)
    if len(ref)>20000: raise ValueError('Comparison maximum is 20,000 entries')
    events=[dict(r) for r in c.execute('SELECT * FROM events')]
    by_id={r['id']:r for r in events}
    by_path={}
    for r in events: by_path.setdefault((r['host'],r['method'],r['path']),[]).append(r)
    pairs=[]; disagreements=[]; missed=0; seen=set()
    for r in ref:
        event=by_id.get(r['id'])
        if not event:
            choices=by_path.get((r['host'],r['method'],r['path']),[])
            # Avoid comparing an ambiguous duplicate endpoint as though it were a unique event.
            if len(choices)==1: event=choices[0]
        if not event or event['id'] in seen: missed+=1;continue
        seen.add(event['id']); pairs.append({'reference':r['label'],'ours':event['label']})
        if r['label']!=event['label']:
            gaps=[k for k,v in json.loads(event['features']).items() if v]
            disagreements.append({'event_id':event['id'],'endpoint':event['host']+event['path'],'ours':event['label'],'reference':r['label'],'signals':gaps[:9], 'status':'NEEDS_REVIEW'})
            c.execute('INSERT INTO reviews(event_id,expected,predicted,source,reviewed,created) VALUES(?,?,?,?,0,?)',(event['id'],r['label'],event['label'],'noname_comparison',time.time()))
    m=metrics(pairs); m['unmatched_reference']=missed; m['reference_records']=len(ref)
    c.execute('INSERT INTO comparisons(metrics,disagreements,created) VALUES(?,?,?)',(json.dumps(m),json.dumps(disagreements[:500]),time.time()))
    c.execute('INSERT INTO audit(kind,details,created) VALUES(?,?,?)',('comparison',json.dumps({'matched':len(pairs),'disagreements':len(disagreements)}),time.time()))
    return {'metrics':m,'disagreements':disagreements[:500], 'notice':'Agreement with Noname is not ground-truth accuracy. Review discrepancies before learning.'}

def learn_from_reviews(c):
    examples=[dict(r) for r in c.execute('''SELECT e.features,r.expected FROM reviews r
        JOIN events e ON e.id=r.event_id
        WHERE r.source='human' AND r.reviewed=1 AND r.expected IN ('API','NON_API')
          AND r.id=(SELECT MAX(latest.id) FROM reviews latest
                    WHERE latest.event_id=r.event_id AND latest.source='human' AND latest.reviewed=1)
        ORDER BY r.id DESC LIMIT 1000''')]
    if not examples: return False,None,None,0
    prepared=[]
    for example in examples:
        features=json.loads(example['features'])
        features['known_api']=0
        features['known_nonapi']=0
        prepared.append((features,example['expected']))
    weights=getweights(c)
    def accuracy(candidate):
        return sum(label_from_features(features,candidate)==expected for features,expected in prepared)/len(prepared)
    before=accuracy(weights)
    candidate=dict(weights)
    for epoch in range(80):
        for index in range(len(prepared)):
            features,expected=prepared[(index+epoch)%len(prepared)]
            score=-0.35+sum(candidate[key]*features.get(key,0) for key in BASE)
            probability=1/(1+math.exp(-max(-20,min(20,score))))
            target=1 if expected=='API' else 0
            error=target-probability
            for key in BASE:
                if features.get(key):
                    update=0.06*(error*features[key]-0.02*(candidate[key]-BASE[key]))
                    candidate[key]=max(-4.5,min(4.5,candidate[key]+update))
    after=accuracy(candidate)
    promoted=after>=before
    if promoted:
        for key,value in candidate.items():
            c.execute('UPDATE weights SET weight=? WHERE feature=?',(value,key))
    return promoted,before,after,len(prepared)

def reward_update(c,event_id,truth):
    row=c.execute('SELECT * FROM events WHERE id=?',(event_id,)).fetchone()
    if not row: raise ValueError('Event ID not found')
    if truth not in ('API','NON_API'): raise ValueError('Reviewed labels must be API or NON_API; abstentions cannot train a binary classifier')
    c.execute('INSERT INTO reviews(event_id,expected,predicted,source,reviewed,created) VALUES (?,?,?,?,1,?)',(event_id,truth,row['label'],'human',time.time()))
    endpoint=row['host']+'|'+row['method']+'|'+row['template']
    c.execute('INSERT OR REPLACE INTO endpoint_labels VALUES (?,?,1)',(endpoint,truth))
    c.execute('UPDATE events SET label=?,confidence=1.0,reasons=? WHERE host=? AND method=? AND template=?',
              (truth,json.dumps(['human-verified endpoint memory']),row['host'],row['method'],row['template']))
    c.execute('UPDATE reviews SET reviewed=1 WHERE event_id=? AND source=?',(event_id,'noname_comparison'))
    promoted,before,after,examples=learn_from_reviews(c)
    c.execute('INSERT INTO audit(kind,details,created) VALUES(?,?,?)',('feedback',json.dumps({'event_id':event_id,'truth':truth,'promoted':promoted,'prior_validation':before,'candidate_validation':after,'examples':examples}),time.time()))
    return {'reviewed':True,'reward':round(1.0 if row['label']==truth else -1.0,2),'weight_update_promoted':promoted,
            'validation_accuracy_before':before,'validation_accuracy_candidate':after,'reviewed_examples':examples,
            'endpoint_memory_updated':True,
            'note':'Human corrections train shared feature weights; verified labels are kept for future updates. Endpoint corrections apply exactly, and weight updates are rejected if reviewed-set accuracy falls.'}

class Handler(BaseHTTPRequestHandler):
    server_version='APIIntelligence/1.0'
    def log_message(self, format, *args): pass
    def reply(self,obj,status=200):
        body=json.dumps(obj,ensure_ascii=False).encode()
        self.send_response(status);self.send_header('Content-Type','application/json; charset=utf-8');self.send_header('Content-Length',str(len(body)));self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.end_headers();self.wfile.write(body)
    def do_GET(self):
        route=urlsplit(self.path).path
        if route.startswith('/api/'):
            with LOCK,connect() as c:
                if route=='/api/state':return self.reply(state(c))
                if route=='/api/health':return self.reply({'ok':True,'version':'1.0','mode':setting(c,'mode')})
                if route=='/api/export':return self.reply({'events':state(c)['events'],'version':'1.0'})
            return self.reply({'error':'Not found'},404)
        name='index.html' if route=='/' else route.lstrip('/')
        if name not in ('index.html','style.css','app.js'): return self.reply({'error':'Not found'},404)
        path=ROOT/'static'/name
        body=path.read_bytes();ctype=mimetypes.guess_type(str(path))[0] or 'application/octet-stream'
        self.send_response(200);self.send_header('Content-Type',ctype);self.send_header('Content-Length',str(len(body)));self.send_header('X-Content-Type-Options','nosniff');self.end_headers();self.wfile.write(body)
    def do_POST(self):
        route=urlsplit(self.path).path
        try:
            n=int(self.headers.get('Content-Length','0'))
            if n<=0 or n>MAX_BODY: return self.reply({'error':'Payload must be between 1 byte and 12 MB'},413)
            data=json.loads(self.rfile.read(n))
            with LOCK,connect() as c:
                if route=='/api/mode':
                    mode=data.get('mode')
                    if mode not in ('live','file','off'): raise ValueError('Choose live, file, or off')
                    c.execute("UPDATE settings SET value=? WHERE key='mode'",(mode,))
                    c.execute('INSERT INTO audit(kind,details,created) VALUES(?,?,?)',('mode',mode,time.time()))
                    return self.reply({'mode':mode})
                if route=='/api/ingest':
                    if setting(c,'mode')!='live':return self.reply({'error':'Live inspection is not enabled'},409)
                    return self.reply(ingest(c,data,'live'))
                if route=='/api/upload':
                    if setting(c,'mode')!='file':return self.reply({'error':'File inspection is not enabled'},409)
                    return self.reply(ingest(c,data,'file'))
                if route=='/api/compare':return self.reply(compare(c,data))
                if route=='/api/feedback':return self.reply(reward_update(c,str(data.get('event_id','')),str(data.get('label','')).upper()))
            return self.reply({'error':'Not found'},404)
        except (ValueError,TypeError,json.JSONDecodeError) as e:return self.reply({'error':str(e)},400)
        except sqlite3.Error as e:return self.reply({'error':'Database error: '+str(e)},500)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--host',default='127.0.0.1');parser.add_argument('--port',type=int,default=8765)
    args=parser.parse_args();init()
    http=ThreadingHTTPServer((args.host,args.port),Handler)
    print(f'API Discovery Intelligence: http://{args.host}:{args.port}',flush=True)
    try:http.serve_forever()
    except KeyboardInterrupt:pass
    finally:http.server_close()
if __name__=='__main__':main()
