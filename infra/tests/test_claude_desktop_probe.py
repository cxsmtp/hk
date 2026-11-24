import importlib.util
from pathlib import Path
import unittest
import contextlib
import io
from types import SimpleNamespace

path = Path(__file__).parents[1] / 'scripts' / 'claude-desktop-probe.py'
spec = importlib.util.spec_from_file_location('probe', path)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

class ProbeTests(unittest.TestCase):
    def test_no_writes_or_upgrades_allowed(self):
        for method in ['POST', 'PUT', 'PATCH', 'DELETE', 'CONNECT', 'OTHER']:
            self.assertFalse(probe.permit_read(method, False))
        self.assertFalse(probe.permit_read('GET', True))
        self.assertTrue(probe.permit_read('GET', False))

    def test_metadata_does_not_include_identifiers_or_query(self):
        self.assertEqual(probe.route_category('/api/organizations/secret/chat_conversations/private/completion?token=password'), 'completion')
        self.assertEqual(probe.route_category('/unknown/private?password=secret'), 'other')

    def test_scope_has_host_boundary(self):
        self.assertTrue(probe.in_scope('claude.ai'))
        self.assertTrue(probe.in_scope('www.claude.ai'))
        self.assertFalse(probe.in_scope('claude.ai.attacker.example'))
        self.assertFalse(probe.in_scope('notclaude.ai'))

    def test_write_withheld_and_metadata_redacted(self):
        from mitmproxy import http
        flow = SimpleNamespace(
            request=http.Request.make('POST', 'https://claude.ai/api/organizations/private/chat_conversations/secret/completion?token=hidden',
                                      b'{"prompt":"private synthetic text"}', {'cookie': 'secret-cookie'}),
            metadata={}, response=None,
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            probe.Probe().requestheaders(flow)
        self.assertEqual(flow.response.status_code, 403)
        self.assertFalse(flow.metadata['hawk_probe_allowed'])
        for secret in ['private', 'secret', 'hidden', 'cookie', 'prompt']:
            self.assertNotIn(secret, output.getvalue())

    def test_read_response_streams_without_logging_body(self):
        from mitmproxy import http
        flow = SimpleNamespace(
            request=http.Request.make('GET', 'https://claude.ai/new'),
            metadata={}, response=None,
        )
        with contextlib.redirect_stdout(io.StringIO()):
            probe.Probe().requestheaders(flow)
            self.assertIsNone(flow.response)
            flow.response = http.Response.make(200, b'private response')
            probe.Probe().responseheaders(flow)
        self.assertTrue(flow.response.stream)

if __name__ == '__main__':
    unittest.main()
