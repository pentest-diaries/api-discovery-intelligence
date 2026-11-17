"""Explainable API traffic classification, endpoint memory and reviewed online updates."""
import math, re, json, hashlib
from urllib.parse import urlsplit
from collections import Counter

LABELS = ('API', 'NON_API', 'UNIDENTIFIED')
FEATURES = ('path_api','path_rpc','path_docs','path_static','path_page','path_auth','json_req','json_resp','graphql','grpc','soap','rpc','ajax','html','static_type','method_write','api_accept','versioned','machine_client','query_params','structured_response','known_api','known_nonapi')
BASE = {
 'path_api': 1.8, 'path_rpc': 1.6, 'path_docs': -0.6, 'path_static': -3.0, 'path_page': -1.2, 'path_auth': 0.35,
 'json_req': 1.25, 'json_resp': 1.15, 'graphql': 3.6, 'grpc': 3.8, 'soap': 3.5, 'rpc': 3.1,
 'ajax': 0.45, 'html': -2.15, 'static_type': -3.2, 'method_write': 0.35, 'api_accept': 0.65,
 'versioned': 0.8, 'machine_client': 0.6, 'query_params': 0.1, 'structured_response': 0.85,
 'known_api': 2.4, 'known_nonapi': -2.4,
}
SENSITIVE = re.compile(r'(authorization|cookie|set-cookie|x-api-key|token|secret|password|credential)', re.I)
STATIC = re.compile(r'\.(?:css|js|mjs|png|jpg|jpeg|svg|ico|gif|webp|woff2?|ttf|map|pdf|txt|mp4|webm|zip)(?:$|\?)',re.I)
API_PATH = re.compile(r'/(?:api|apis|rest|v[0-9]+|graphql|rpc|services?)(?:/|$)',re.I)
PAGE_PATH = re.compile(r'/(?:home|about|contact|blog|article|login|signup|pricing)(?:/|$)',re.I)
UUID = re.compile(r'^[a-f0-9]{8}-[a-f0-9-]{13,}$',re.I)

def normalize_path(value):
    path = urlsplit(value or '/').path or '/'
    segments = [('{id}' if p.isdigit() or UUID.match(p) else p) for p in path.split('/')]
    return '/'.join(segments) or '/'

def headers_of(obj):
    h = obj if isinstance(obj, dict) else {}
    return {str(k).lower():str(v)[:300] for k,v in h.items() if not SENSITIVE.search(str(k))}

def normalize(raw):
    if not isinstance(raw, dict): raise ValueError('Each traffic record must be an object')
    req = raw.get('request') if isinstance(raw.get('request'),dict) else {}
    resp = raw.get('response') if isinstance(raw.get('response'),dict) else {}
    rh = headers_of(raw.get('request_headers') or raw.get('headers') or req.get('headers'))
    sh = headers_of(raw.get('response_headers') or resp.get('headers'))
    url = str(raw.get('url') or req.get('url') or raw.get('path') or req.get('path') or '/')[:2048]
    parts = urlsplit(url)
    host = str(raw.get('host') or req.get('host') or parts.netloc or rh.get('host','unknown'))[:200].lower()
    path = parts.path or '/'
    method = str(raw.get('method') or req.get('method') or 'GET').upper()[:15]
    status = raw.get('status') or raw.get('status_code') or resp.get('status') or resp.get('status_code') or 0
    try: status = int(status)
    except (TypeError,ValueError): status = 0
    ctype = str(raw.get('content_type') or sh.get('content-type') or resp.get('content_type') or '')[:200].lower()
    reqctype = rh.get('content-type','').lower()
    body = raw.get('body') if 'body' in raw else resp.get('body')
    reqbody = req.get('body')
    if not ctype and isinstance(body,(dict,list)): ctype='application/json'
    if not reqctype and isinstance(reqbody,(dict,list)): reqctype='application/json'
    if not ctype and isinstance(body,str) and body.lstrip().startswith(('{','[')):
        try: json.loads(body[:10000]); ctype='application/json'
        except ValueError: pass
    template = normalize_path(path)
    record_key = str(raw.get('id') or raw.get('traffic_id') or '')[:120]
    if not record_key:
        signature = json.dumps([host,method,path,status,ctype,raw.get('timestamp','')], separators=(',',':'))
        record_key = hashlib.sha256(signature.encode()).hexdigest()[:20]
    return {'id':record_key,'host':host,'path':path[:512],'template':template[:512],'method':method,'status':status,
            'request_type':reqctype,'content_type':ctype,'request_headers':rh,'response_headers':sh,
            'has_query':bool(parts.query or raw.get('query')),'response_structured':isinstance(body,(dict,list)),
            'request_structured':isinstance(reqbody,(dict,list)),'source':str(raw.get('source','traffic'))[:40]}

def features_of(r, known=None):
    p=r['path'].lower(); c=r['content_type']; q=r['request_type']; h=r['request_headers']; sh=r['response_headers']
    ua=h.get('user-agent','').lower(); accept=h.get('accept','').lower()
    f={k:0 for k in FEATURES}
    f['path_api']=int(bool(API_PATH.search(p)))
    f['path_rpc']=int('/rpc' in p or '/jsonrpc' in p)
    f['path_docs']=int(bool(re.search(r'/(?:swagger-ui|docs|redoc)(?:/|$)',p)))
    f['path_static']=int(bool(STATIC.search(p)))
    f['path_page']=int(bool(PAGE_PATH.search(p)))
    f['path_auth']=int(bool(re.search(r'/(?:oauth|auth|token)(?:/|$)',p)))
    f['json_req']=int('json' in q or r['request_structured'])
    f['json_resp']=int('json' in c or r['response_structured'])
    f['graphql']=int('graphql' in p or 'application/graphql' in q or 'application/graphql' in c)
    f['grpc']=int('application/grpc' in c or 'application/grpc' in q or 'grpc-' in ' '.join(sh))
    f['soap']=int('soap' in c or 'soap' in q or ('xml' in c and 'soapaction' in h))
    f['rpc']=int('json-rpc' in c or 'jsonrpc' in p)
    f['ajax']=int(h.get('x-requested-with','').lower()=='xmlhttprequest')
    f['html']=int('text/html' in c)
    f['static_type']=int(c.startswith(('image/','font/','video/','audio/','text/css','application/javascript','text/javascript','application/pdf')))
    f['method_write']=int(r['method'] in ('POST','PUT','PATCH','DELETE'))
    f['api_accept']=int('application/json' in accept or 'application/xml' in accept)
    f['versioned']=int(bool(re.search(r'/(?:api/)?v[0-9]+(?:/|$)',p)))
    f['machine_client']=int(any(t in ua for t in ('curl/','python-requests','go-http-client','postmanruntime','okhttp')))
    f['query_params']=int(r['has_query'])
    f['structured_response']=int(r['response_structured'])
    if known in ('API','NON_API'): f['known_api' if known=='API' else 'known_nonapi']=1
    return f

def label_from_features(features, weights=None):
    w = dict(BASE); w.update({k:float(v) for k,v in (weights or {}).items() if k in BASE})
    if features.get('known_api'): return 'API'
    if features.get('known_nonapi'): return 'NON_API'
    score = -0.35 + sum(w[k]*features.get(k,0) for k in BASE)
    prob = 1/(1+math.exp(-max(-20,min(20,score))))
    strong_api = any(features.get(k) for k in ('graphql','grpc','soap','rpc'))
    strong_non = bool(features.get('static_type') or features.get('path_static'))
    conflict = bool(strong_non and (strong_api or features.get('path_api') or features.get('json_resp')))
    if conflict or 0.28 < prob < 0.76: return 'UNIDENTIFIED'
    return 'API' if prob>=0.76 else 'NON_API'

def classify(raw, weights=None, known=None):
    r = normalize(raw)
    f = features_of(r, known)
    w = dict(BASE); w.update({k:float(v) for k,v in (weights or {}).items() if k in BASE})
    score = -0.35 + sum(w[k]*v for k,v in f.items())
    prob = 1/(1+math.exp(-max(-20,min(20,score))))
    label = label_from_features(f, w)
    if known in ('API','NON_API'):
        confidence = 1.0
    else:
        confidence = max(prob,1-prob) if label!='UNIDENTIFIED' else min(prob,1-prob)
    triggered=sorted(((k,round(w[k],2)) for k,v in f.items() if v), key=lambda kv:abs(kv[1]),reverse=True)
    reasons=['human-verified endpoint memory'] if known in ('API','NON_API') else [k.replace('_',' ') for k,_ in triggered[:5]] or ['insufficient distinguishing evidence']
    return {'id':r['id'],'host':r['host'],'path':r['path'],'template':r['template'],'method':r['method'],
            'status':r['status'],'content_type':r['content_type'],'label':label,'confidence':round(confidence,3),
            'api_probability':round(prob,3),'score':round(score,2),'reasons':reasons,'features':f}

def extract_rows(data):
    if isinstance(data,list): return data
    if isinstance(data,dict):
        for key in ('traffic','records','requests','events','results','items','data'):
            value=data.get(key)
            if isinstance(value,list): return value
        if any(k in data for k in ('url','path','request')): return [data]
    raise ValueError('JSON must be an array or an object containing a traffic/records/requests/events/results/items/data array')

def comparator_rows(data):
    rows=extract_rows(data)
    output=[]
    for item in rows:
        if not isinstance(item,dict): continue
        obj=item.get('classification') if isinstance(item.get('classification'),dict) else {}
        found = item.get('label') or item.get('classification_label') or item.get('category') or item.get('type') or item.get('api_type') or obj.get('label')
        if found is None and isinstance(item.get('is_api'),bool): found='API' if item['is_api'] else 'NON_API'
        if found is None: continue
        label=str(found).strip().upper().replace('-','_').replace(' ','_')
        aliases={'NONAPI':'NON_API','WEB':'NON_API','STATIC':'NON_API','OTHER':'UNIDENTIFIED','UNKNOWN':'UNIDENTIFIED','UNCLASSIFIED':'UNIDENTIFIED'}
        label=aliases.get(label,label)
        if label not in LABELS: continue
        r=normalize(item)
        output.append({'id':r['id'],'host':r['host'],'method':r['method'],'path':r['path'],'template':r['template'],'label':label})
    return output

def metrics(pairs):
    matrix={actual:{pred:0 for pred in LABELS} for actual in LABELS}
    for pair in pairs: matrix[pair['reference']][pair['ours']]+=1
    support={k:sum(matrix[k].values()) for k in LABELS}
    n=len(pairs); correct=sum(matrix[k][k] for k in LABELS)
    stats={}
    for k in LABELS:
        tp=matrix[k][k]; fp=sum(matrix[a][k] for a in LABELS if a!=k); fn=support[k]-tp
        p=tp/(tp+fp) if tp+fp else 0; r=tp/(tp+fn) if tp+fn else 0
        stats[k]={'precision':round(p,3),'recall':round(r,3),'f1':round(2*p*r/(p+r),3) if p+r else 0,'support':support[k]}
    return {'matched':n,'agreement':round(correct/n,4) if n else None,'macro_f1':round(sum(x['f1'] for x in stats.values())/3,3) if n else None,'matrix':matrix,'per_class':stats}
