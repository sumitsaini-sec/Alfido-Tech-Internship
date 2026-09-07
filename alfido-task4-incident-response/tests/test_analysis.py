import importlib.util, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def module(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/'scripts'/f'{name}.py'); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
analyze=module('analyze_logs').analyze
generate=module('generate_logs').generate
class DetectionTests(unittest.TestCase):
    def test_full_chain(self):
        result=analyze(generate()); self.assertEqual(result['total_events'],56); self.assertEqual([f['rule'] for f in result['findings']],['IR-01','IR-02','IR-03','IR-04','IR-05'])
    def test_benign_background(self):
        self.assertEqual(analyze([r for r in generate() if r['host']=='WS-HR-02'])['finding_count'],0)
    def test_wrong_session_breaks_chain(self):
        rows=generate()
        for r in rows:
            if r.get('process_guid')=='sim-process-001': r['logon_id']='unrelated'
        self.assertEqual([f['rule'] for f in analyze(rows)['findings']],['IR-01','IR-02'])
    def test_wrong_process_breaks_dns_network_link(self):
        rows=generate()
        for r in rows:
            if r['provider']=='Sysmon' and r['event_id']==3: r['process_guid']='unrelated'
        self.assertEqual([f['rule'] for f in analyze(rows)['findings']],['IR-01','IR-02','IR-03'])
    def test_out_of_order_input(self):
        self.assertEqual(analyze(generate()),analyze(list(reversed(generate()))))
if __name__=='__main__': unittest.main()
