import unittest,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from engine import classify,normalize,comparator_rows,metrics
class ClassifierTest(unittest.TestCase):
 def test_api(self): self.assertEqual(classify({'url':'https://x.test/api/v1/users','response_headers':{'Content-Type':'application/json'}})['label'],'API')
 def test_static(self): self.assertEqual(classify({'url':'https://x.test/static/site.css','response_headers':{'Content-Type':'text/css'}})['label'],'NON_API')
 def test_ambiguous(self):
  result=classify({'url':'https://x.test/xyz'})
  self.assertEqual(result['label'],'UNIDENTIFIED')
  self.assertLess(result['confidence'],0.6)
 def test_sensitive(self): self.assertNotIn('authorization',normalize({'headers':{'Authorization':'Bearer SECRET'}})['request_headers'])
 def test_comparator(self): self.assertEqual(comparator_rows({'results':[{'id':'x','label':'non-api'}]})[0]['label'],'NON_API')
 def test_metric(self): self.assertEqual(metrics([{'reference':'API','ours':'API'}])['agreement'],1.0)
 def test_verified_endpoint_overrides_classifier(self):
  result=classify({'url':'https://x.test/api/v1/users'},known='NON_API')
  self.assertEqual(result['label'],'NON_API')
  self.assertEqual(result['confidence'],1.0)
  self.assertIn('human-verified endpoint memory',result['reasons'])
if __name__=='__main__':unittest.main()
