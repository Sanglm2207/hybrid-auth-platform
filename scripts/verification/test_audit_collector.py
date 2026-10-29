import importlib.util, json, tempfile, unittest, gzip
from pathlib import Path
from datetime import datetime, timezone
spec=importlib.util.spec_from_file_location('collector',Path(__file__).parents[1]/'audit-collector.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class CollectorTest(unittest.TestCase):
    def test_rotation_restart_dedup_and_alerts_without_secrets(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);source=root/'logs';source.mkdir()
            event=json.dumps({'event':'REFRESH_REUSE','outcome':'DENIED','timestamp':datetime.now(timezone.utc).isoformat(),'actor':'password=secret'})+'\n'
            log=source/'auth-service.jsonl';log.write_text(event)
            collector=module.Collector(source,root/'audit.sqlite3');collector.collect();collector.db.close()
            with gzip.open(source/'auth-service.2026-10-30.0.jsonl.gz','wt') as target:target.write(event)
            collector=module.Collector(source,root/'audit.sqlite3');collector.collect()
            self.assertEqual(collector.db.execute('select count(*) from events').fetchone()[0],1)
            self.assertIsNone(collector.db.execute('select actor from events').fetchone()[0])
            self.assertIn('hybrid_security_alert{rule="refresh_reuse"} 1',collector.metrics())
            self.assertNotIn('secret',collector.metrics());collector.db.close()
if __name__=='__main__':unittest.main()
