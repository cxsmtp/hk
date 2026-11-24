import subprocess
import time
import unittest

from hawk_endpoint_agent.enforcers.process_control import ProcessControl


class ProcessControlTests(unittest.TestCase):
    def test_terminate_owned_process(self):
        # Spawn a process we own, then evict it — the real "kick" path.
        proc = subprocess.Popen(["sleep", "30"])
        try:
            control = ProcessControl(enabled=True)
            result = control.terminate(proc.pid)
            self.assertTrue(result.performed)
            self.assertIn(result.method, {"sigterm", "sigkill"})
            time.sleep(0.2)
            self.assertIsNotNone(proc.poll())  # process actually gone
        finally:
            if proc.poll() is None:
                proc.kill()

    def test_disabled_does_not_terminate(self):
        proc = subprocess.Popen(["sleep", "30"])
        try:
            control = ProcessControl(enabled=False)
            result = control.terminate(proc.pid)
            self.assertFalse(result.performed)
            self.assertEqual(result.method, "disabled")
            self.assertIsNone(proc.poll())  # still running
        finally:
            proc.kill()

    def test_nonexistent_pid(self):
        result = ProcessControl(enabled=True).terminate(0)
        self.assertFalse(result.performed)
        self.assertEqual(result.method, "not_found")


if __name__ == "__main__":
    unittest.main()
