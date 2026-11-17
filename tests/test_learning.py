import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import server


class FeedbackLearningTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir=tempfile.TemporaryDirectory()
        self.db_path=Path(self.temp_dir.name)/'inspection.sqlite3'
        self.db_patch=patch.object(server,'DB',self.db_path)
        self.db_patch.start()
        server.init()
        self.connection=server.connect()

    def tearDown(self):
        self.connection.close()
        self.db_patch.stop()
        self.temp_dir.cleanup()

    def test_correction_updates_model_and_is_remembered_for_endpoint(self):
        traffic={'id':'event-1','url':'https://example.test/api/v1/users',
                 'response_headers':{'Content-Type':'application/json'}}
        event=server.run_classification(self.connection,traffic,'file')
        self.assertEqual(event['label'],'API')
        weights_before=server.getweights(self.connection)

        result=server.reward_update(self.connection,event['id'],'NON_API')
        self.connection.commit()

        weights_after=server.getweights(self.connection)
        self.assertTrue(result['endpoint_memory_updated'])
        self.assertGreater(result['reviewed_examples'],0)
        self.assertTrue(any(weights_after[key]!=weights_before[key] for key in ('path_api','json_resp','versioned')))
        corrected_event=self.connection.execute('SELECT label,confidence FROM events WHERE id=?',(event['id'],)).fetchone()
        self.assertEqual(corrected_event['label'],'NON_API')
        self.assertEqual(corrected_event['confidence'],1.0)
        corrected=server.run_classification(
            self.connection,
            {'id':'event-2','url':'https://example.test/api/v1/users',
             'response_headers':{'Content-Type':'application/json'}},
            'file')
        similar=server.run_classification(
            self.connection,
            {'id':'event-3','url':'https://other.test/api/v1/users',
             'response_headers':{'Content-Type':'application/json'}},
            'file')
        self.assertEqual(corrected['label'],'NON_API')
        self.assertEqual(corrected['confidence'],1.0)
        self.assertEqual(similar['label'],'NON_API')


if __name__=='__main__':
    unittest.main()
