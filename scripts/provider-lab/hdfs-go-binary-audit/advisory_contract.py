"""Projection of the pinned Go scanner's OSV schema for artifact binding.

Match fields serialized by golang.org/x/vuln v1.9.0. Custom ranges
require a separate evidence ledger; other unsupported applicability fields
fail closed. This projection does not interpret version ranges.
"""
from __future__ import annotations
import re
from datetime import datetime
from audit_contract import need,text_value

def string(value,empty=False,limit=1048576,multiline=False):
    checked=value.replace('\n',' ').replace('\r',' ').replace('\t',' ') if multiline and type(value) is str else value
    need(text_value(checked,limit,empty),'osv_string')
    return value

def strings(value):
    need(type(value) is list and len(value)<=100000,'osv_list')
    return [string(v) for v in value]

def timestamp(value):
    need(type(value) is str and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})',value),'osv_time')
    # Validate calendar fields without truncating sub-microsecond digits.
    try:datetime.fromisoformat(value.replace('Z','+00:00'))
    except ValueError:need(False,'osv_time')
    value=re.sub(r'\.(\d+)(Z|[+-]\d{2}:\d{2})$',lambda m:('.'+m[1].rstrip('0') if m[1].rstrip('0') else '')+m[2],value)
    return value[:-6]+'Z' if value.endswith('+00:00') else value

def obj(value):
    need(type(value) is dict,'osv_object')
    return value

def optional(out,source,key,convert):
    value=source.get(key)
    if value is not None and value!='' and value!=[]:out[key]=convert(value)

def project_import(value):
    value=obj(value)
    need(set(value)<={'path','goos','goarch','symbols'},'osv_unsupported_import')
    out={}
    optional(out,value,'path',string)
    for key in ('goos','goarch','symbols'):optional(out,value,key,strings)
    return out

def project_affected(value,ident,custom_ranges):
    value=obj(value)
    need(set(value)<={'package','ranges','ecosystem_specific','database_specific','severity'},'osv_unsupported_affected')
    package=obj(value.get('package'))
    need(package.get('ecosystem')=='Go','osv_ecosystem')
    out={'package':{'name':string(package.get('name')),'ecosystem':'Go'}}
    ranges=value.get('ranges',[])
    need(type(ranges) is list and len(ranges)<=10000,'osv_ranges')
    if ranges:
        projected=[]
        for item in ranges:
            item=obj(item)
            need(set(item)=={'type','events'} and item['type']=='SEMVER','osv_unsupported_range')
            events=item['events'];need(type(events) is list and 0<len(events)<=10000,'osv_events')
            output=[]
            for event in events:
                event=obj(event);need(set(event)<={'introduced','fixed'} and len(event)==1,'osv_unsupported_event')
                key=next(iter(event));output.append({key:string(event[key])})
            projected.append({'type':'SEMVER','events':output})
        out['ranges']=projected
    eco=obj(value.get('ecosystem_specific',{}))
    need(set(eco)<={'imports','custom_ranges'},'osv_unsupported_ecosystem')
    if eco.get('custom_ranges'):
        need(type(custom_ranges) is list,'osv_custom_ranges_unacknowledged')
        rows=eco['custom_ranges'];need(type(rows) is list and len(rows)<=10000,'osv_custom_ranges')
        preserved=[]
        for row in rows:
            row=obj(row);need(set(row)=={'type','events'} and row['type']=='ECOSYSTEM','osv_custom_ranges')
            events=row['events'];need(type(events) is list and 0<len(events)<=10000,'osv_custom_ranges')
            copied=[]
            for event in events:
                event=obj(event);need(set(event)<={'introduced','fixed'} and len(event)==1,'osv_custom_ranges')
                key=next(iter(event));copied.append({key:string(event[key])})
            preserved.append({'type':'ECOSYSTEM','events':copied})
        custom_ranges.append({'id':ident,'module':package['name'],'ranges':preserved,'scanner_interprets_ranges':False})
    out['ecosystem_specific']={}
    imports=eco.get('imports',[])
    need(type(imports) is list and len(imports)<=100000,'osv_imports')
    if imports:out['ecosystem_specific']['imports']=[project_import(i) for i in imports]
    return out

def project_osv(value,custom_ranges=None):
    value=obj(value)
    ident=value.get('id')
    need(type(ident) is str and re.fullmatch(r'GO-\d{4}-\d{4,}',ident),'osv_id')
    affected=value.get('affected')
    need(type(affected) is list and 0<len(affected)<=10000,'osv_affected')
    out={'id':ident,'modified':timestamp(value.get('modified')),'published':timestamp(value.get('published')),
         'details':string(value.get('details',''),True,multiline=True),'affected':[project_affected(a,ident,custom_ranges) for a in affected]}
    optional(out,value,'schema_version',string)
    optional(out,value,'summary',lambda x:string(x,multiline=True))
    optional(out,value,'withdrawn',timestamp)
    optional(out,value,'aliases',strings)
    references=value.get('references',[])
    need(type(references) is list and len(references)<=10000,'osv_references')
    if references:
        out['references']=[{'type':string(obj(r).get('type')),'url':string(r.get('url'))} for r in references]
    credits=value.get('credits',[])
    need(type(credits) is list and len(credits)<=10000,'osv_credits')
    if credits:out['credits']=[{'name':string(obj(c).get('name'))} for c in credits]
    if value.get('database_specific') is not None:
        database=obj(value['database_specific']);projected={}
        optional(projected,database,'url',string)
        status=database.get('review_status','')
        need(status in ('','UNREVIEWED','REVIEWED'),'osv_review_status')
        if status:projected['review_status']=status
        out['database_specific']=projected
    return out
