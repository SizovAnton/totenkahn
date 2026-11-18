"""Коротке пояснення фактично записаного циклу Atomic."""
from html import escape
import json

LABELS={'check-prerequisite':'Check prerequisite','prepare-prerequisite':'Prepare prerequisite',
        'recheck-prerequisite':'Recheck prerequisite','execute':'Execute test','cleanup':'Cleanup'}


def lifecycle_summary(report):
    execution=report.get('execution',{}).get('status','not_started')
    cleanup=report.get('cleanup',{}).get('status','not_requested')
    detection=report.get('detection',{}).get('status','not_evaluated')
    collection=report.get('collection',{}).get('status','not_started')
    text=f'Test execution: {execution}. Collection: {collection}. Cleanup: {cleanup}. Rule result: {detection}.'
    if report.get('reason'):text+=' '+report['reason']
    if report.get('detection',{}).get('reason'):text+=' '+report['detection']['reason']+'.'
    text+=' Cleanup does not certify full host restoration.'
    chain=[]
    for step in report.get('steps',[]):
        if step['stage']=='execute':
            ready=report.get('collection',{}).get('ready_received_at')
            chain.append('Collector ready' if ready else 'Collector readiness not recorded')
        if step['stage']=='cleanup':chain.append('Collection stopped' if report.get('collection',{}).get('finished_at') else 'Collection stop not recorded')
        chain.append(str(LABELS.get(step['stage'],step['stage']))+': '+str(step['status']))
    chain.append('Rule evaluation: '+detection)
    return text,' -> '.join(chain)


def render_lifecycle(report):
    text,chain=lifecycle_summary(report)
    return '<h3>Atomic lifecycle</h3><p>'+escape(text)+'</p><pre style="white-space:pre-wrap">'+escape(chain)+\
        '</pre><details><summary>Recorded lifecycle details and remaining changes</summary><pre style="white-space:pre-wrap;overflow-wrap:anywhere">'+\
        escape(json.dumps(report,ensure_ascii=False,indent=2))+'</pre></details>'
