"""Контекст джерела і доказові зв'язки процесів; без зміни первинних подій."""
from collections import defaultdict
from ipaddress import ip_address
from uuid import UUID
from handlers.events import parse_event_time


def read_path(value, path):
    for key in path:
        if not isinstance(value, dict) or key not in value:
            return None
        value = value[key]
    return value


def validate_context_profile(profile):
    # Відсутність нового контракту допустима для старих збережених профілів.
    context = profile.get('source_context')
    if context is None:
        return
    if not isinstance(context, dict) or set(context) != {'host_path', 'ip_fields'}:
        raise ValueError('source_context requires host_path and ip_fields')
    def path(value):
        if not isinstance(value,list) or not value or not all(isinstance(k,str) and k.strip() for k in value):
            raise ValueError('Context paths must be non-empty arrays of keys')
    path(context['host_path'])
    if not isinstance(context['ip_fields'],list):
        raise ValueError('source_context.ip_fields must be an array')
    for item in context['ip_fields']:
        if not isinstance(item,dict) or set(item) != {'path','when'}:
            raise ValueError('Each IP mapping requires path and when')
        path(item['path'])
        if not isinstance(item['when'],list):
            raise ValueError('IP mapping when must be an array')
        for predicate in item['when']:
            if not isinstance(predicate,dict) or set(predicate) != {'path','equals'}:
                raise ValueError('IP predicates require path and equals')
            path(predicate['path'])
            if type(predicate['equals']) not in (str,int,bool,type(None)):
                raise ValueError('IP predicate equals must be a scalar')


def source_context(event):
    profile = event.get('source') or {}
    validate_context_profile(profile)
    config = profile.get('source_context')
    # computer — існуюче нормалізоване поле Windows System/Computer.
    host_path = config['host_path'] if config else ['computer']
    host = read_path(event, host_path)
    if not isinstance(host,str) or not host.strip() or host.casefold() == 'unknown':
        host = None
    ips, issues = [], []
    for mapping in config['ip_fields'] if config else []:
        if not all(type(read_path(event,p['path'])) is type(p['equals']) and
                   read_path(event,p['path']) == p['equals'] for p in mapping['when']):
            continue
        raw = read_path(event,mapping['path'])
        try:
            if not isinstance(raw,str):
                raise ValueError('IP must be a string')
            address = ip_address(raw.strip())
            if address.is_unspecified or address.is_multicast:
                raise ValueError('Address does not identify a source host')
        except ValueError:
            issues.append({'path':mapping['path'],'reason':'Missing or invalid source IP'})
            continue
        ips.append({'value':str(address),'path':mapping['path'],'when':mapping['when']})
    return {'host':host,'host_path':host_path,'ips':ips,
            'ip_status':'available' if ips else 'unavailable',
            'basis':'saved_source_profile' if config else 'normalized_computer_only',
            'channel':event.get('channel'),'provider':event.get('provider'),'issues':issues}


def process_identity(event):
    profile = (event.get('source') or {}).get('process_creation')
    if not isinstance(profile,dict):
        return None
    data = event.get('data_fields') or {}
    def identifier(key):
        value = data.get(profile.get(key))
        try:
            parsed=UUID(value.strip()) if isinstance(value,str) else None
            return str(parsed) if parsed and parsed.int else None
        except ValueError:
            return None
    def pid(key,base):
        try:
            value=data.get(profile.get(key))
            value=int(value,profile.get(base,10)) if isinstance(value,str) else None
            return value if value is not None and value>0 else None
        except (ValueError,TypeError):
            return None
    creation = event.get('event_id') == profile.get('event_id')
    host=source_context(event)['host']
    return {'host':host.strip().casefold() if host else None,
            'time':parse_event_time(event.get('system_time')),
            'creation':creation,
            'guid':identifier('guid_field'),
            'parent_guid':identifier('parent_guid_field' if creation else 'guid_field'),
            'pid':pid('pid_field','pid_base'),
            'parent_pid':pid('parent_pid_field','parent_pid_base') if creation else pid('pid_field','pid_base'),
            'profile':profile}


def build_detection_context(events, decisions):
    """decisions: {label: {record_id: True/False/None}}; одна сесія на виклик."""
    by_id={event['record_id']:event for event in events}
    if len(by_id)!=len(events):
        raise ValueError('Detection context requires unique record IDs within a session')
    identities={key:process_identity(event) for key,event in by_id.items()}
    guids,pids=defaultdict(list),defaultdict(list)
    for key,item in identities.items():
        if item and item['creation'] and item['host'] and item['time'] is not None:
            for index,field in ((guids,'guid'),(pids,'pid')):
                if item[field] is not None:index[(item['host'],item[field])].append(key)
    matches=[key for key in by_id if any(values.get(key) is True for values in decisions.values())]
    match_set=set(matches)
    nodes,edges={},[]
    pending=list(matches)
    while pending:
        key=pending.pop()
        if key in nodes:continue
        event=by_id[key];item=identities[key]
        node={'record_id':key,'matched':key in match_set,'source':source_context(event),
              'decisions':{label:values.get(key) for label,values in decisions.items()},
              'time':event.get('system_time'),'parent_status':'unavailable','candidates':[]}
        nodes[key]=node
        if not item or not item['host'] or item['time'] is None:
            node['reason']='Process creation profile, host or valid time is unavailable.';continue
        # GUID має перевагу. Суперечливий GUID не замінюємо слабким PID-збігом.
        method='host_guid_time' if item['parent_guid'] else 'host_pid_time_candidate'
        lookup=guids if item['parent_guid'] else pids
        identifier=item['parent_guid'] or item['parent_pid']
        candidates=[parent for parent in lookup.get((item['host'],identifier),[])
                    if parent!=key and identities[parent]['time']<=item['time']]
        node['method']=method;node['candidates']=candidates
        if not candidates:
            node['reason']='No eligible parent event is present in this saved session.';continue
        if len(candidates)!=1 or not item['parent_guid']:
            node['parent_status']='ambiguous' if len(candidates)>1 else 'candidate'
            node['reason']='Parent is not confirmed; PID reuse or multiple candidates cannot be excluded.'
            continue
        parent=candidates[0]
        # Шукаємо цикл ітеративно: навіть пошкоджений журнал не зависає.
        cursor=parent;seen={key};parents={edge['child']:edge['parent'] for edge in edges}
        while cursor in parents and cursor not in seen:
            seen.add(cursor);cursor=parents[cursor]
        if cursor in seen:
            node['parent_status']='cycle';node['reason']='Cycle detected; parent edge omitted.';continue
        node['parent_status']='linked';node['reason']='Same full host, GUID and non-later creation time.'
        method = method if item['creation'] else 'process_event_context'
        node['method']=method
        edges.append({'parent':parent,'child':key,'method':method,
                      'checks':{'host':item['host'],'parent_guid':item['parent_guid'],
                                'parent_field':item['profile'].get('parent_guid_field' if item['creation'] else 'guid_field'),
                                'identity_field':identities[parent]['profile'].get('guid_field'),
                                'parent_time':by_id[parent].get('system_time'),'child_time':event.get('system_time')}})
        pending.append(parent)
    return {'schema_version':1,'nodes':list(nodes.values()),'edges':edges,'matched_ids':matches,
            'limitations':'Links describe recorded process ancestry, not proof of causality. '
                           'PID-only candidates are not connected. Missing parents may be outside collection.'}
