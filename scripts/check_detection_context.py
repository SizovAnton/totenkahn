import sys, unittest, copy
from pathlib import Path
from uuid import UUID
# Додаємо корінь проєкту для запуску перевірки з будь-якого каталогу.
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from handlers.detection_context import build_detection_context,source_context,validate_context_profile
from reporting.context_view import render_detection_tree

def event(key,guid,parent=None,pid='7',ppid='6',host='host.example',time='2026-11-10T10:00:00Z'):
 return {'record_id':key,'computer':host,'system_time':time,'event_id':'1',
  'channel':'Custom','provider':'Custom','source':{'process_creation':{'event_id':'1',
   'guid_field':'g','parent_guid_field':'pg','pid_field':'p','parent_pid_field':'pp','pid_base':10,'parent_pid_base':10}},
  'data_fields':{'g':str(UUID(int=guid)) if guid else None,'pg':str(UUID(int=parent)) if parent else None,'p':pid,'pp':ppid}}
class ContextTests(unittest.TestCase):
 def graph(self,events,selected='child'):
  return build_detection_context(events,{'rule':{e['record_id']:e['record_id']==selected for e in events}})
 def test_chain_and_input_unchanged(self):
  data=[event('root',1),event('parent',2,1),event('child',3,2),event('unrelated',4)]
  original=copy.deepcopy(data);g=self.graph(data)
  self.assertEqual(len(g['edges']),2);self.assertEqual({n['record_id'] for n in g['nodes']},{'root','parent','child'})
  self.assertEqual(original,data);self.assertIn('Parent context',render_detection_tree(g,lambda k:k))
 def test_full_host_and_time(self):
  for parent in [event('parent',1,host='host.other'), event('parent',1,time='2026-11-10T10:01:00Z')]:
   self.assertFalse(self.graph([parent,event('child',2,1)])['edges'])
 def test_pid_candidates_and_ambiguity(self):
  g=self.graph([event('parent',None,pid='6'),event('child',None)])
  self.assertFalse(g['edges']);self.assertEqual(g['nodes'][0]['parent_status'],'candidate')
  g=self.graph([event('a',1),event('b',1),event('child',2,1)])
  self.assertFalse(g['edges']);self.assertEqual(g['nodes'][0]['parent_status'],'ambiguous')
 def test_cycle(self):
  g=self.graph([event('parent',1,2),event('child',2,1)])
  self.assertEqual(len(g['edges']),1);self.assertTrue(any(n['parent_status']=='cycle' for n in g['nodes']))
 def test_old_profiles_missing_time_and_guid(self):
  e=event('child',2,1);e['source']={}
  self.assertEqual(self.graph([e])['nodes'][0]['parent_status'],'unavailable')
  self.assertEqual(source_context(e)['basis'],'normalized_computer_only')
  e=event('child',0);self.assertFalse(self.graph([event('parent',0),e])['edges'])
 def test_source_ip_guard_and_provenance(self):
  e=event('child',1);e['source']['source_context']={'host_path':['computer'],'ip_fields':[
   {'path':['data_fields','src'],'when':[{'path':['data_fields','out'],'equals':True}]}]}
  e['data_fields'].update(src='192.0.2.4',out=False,dst='203.0.113.6')
  self.assertEqual(source_context(e)['ips'],[])
  e['data_fields']['out']=True
  self.assertEqual(source_context(e)['ips'][0]['value'],'192.0.2.4')
  e['data_fields']['src']='bad';self.assertTrue(source_context(e)['issues'])
  with self.assertRaises(ValueError):validate_context_profile({'source_context':{'host_path':'bad','ip_fields':[]}})
 def test_non_creation_and_regression_removed_match(self):
  e=event('child',1);e['event_id']='3'
  g=build_detection_context([event('parent',1),e],{'baseline':{'child':True},'candidate':{'child':False}})
  self.assertEqual(g['edges'][0]['method'],'process_event_context');self.assertEqual(g['matched_ids'],['child'])
 def test_no_match_and_invalid_time(self):
  self.assertEqual(self.graph([event('unmatched',1)])['nodes'],[])
  self.assertFalse(self.graph([event('parent',1),event('child',2,1,time='invalid')])['edges'])
 def test_graph_is_collapsed_svg_with_separate_details(self):
  from xml.etree import ElementTree as ET
  from html.parser import HTMLParser
  g=self.graph([event('parent',1),event('child',2,1),event('sibling',3,1)],'child')
  h=render_detection_tree(g,lambda key:'event-'+key)
  self.assertIn('<details class="graph-access"><summary>View detection graph</summary>',h)
  self.assertNotIn('<details class="graph-access" open',h)
  svg=h[h.index('<svg '):h.index('</svg>')+6]
  document=ET.fromstring(svg)
  ns={'s':'http://www.w3.org/2000/svg'}
  self.assertEqual(len(document.findall('.//s:rect',ns)),len(g['nodes']))
  self.assertEqual(len(document.findall('.//s:path[@class="graph-edge"]',ns)),len(g['edges']))
  class Links(HTMLParser):
   def __init__(self):super().__init__();self.ids=[];self.links=[]
   def handle_starttag(self,tag,attrs):
    a=dict(attrs)
    if 'id' in a:self.ids.append(a['id'])
    href=a.get('href')
    if tag=='a' and href is not None:self.links.append(href[1:])
  parsed=Links();parsed.feed(h)
  self.assertEqual(len(parsed.ids),len(set(parsed.ids)))
  self.assertTrue(set(parsed.links)<=set(parsed.ids)|{'event-parent','event-child'})
 def test_escaping_and_duplicates(self):
  e=event('<script>',1,host='<img>')
  h=render_detection_tree(self.graph([e],'<script>'),lambda key:key)
  self.assertNotIn('<img>',h);self.assertNotIn('<script>',h)
  with self.assertRaises(ValueError):self.graph([e,e])
if __name__=='__main__':unittest.main()
