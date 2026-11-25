"""Safety and portability gates for the disposable native bootstrap."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("native_local", Path(__file__).with_name("native_local.py"))
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


class NativeBootstrapTests(unittest.TestCase):
    def test_web_production_env_is_refused_without_reading_or_changing_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); web = root / "apps/web"; web.mkdir(parents=True)
            marker = web / ".env.production.local"; marker.write_text("private fixture sentinel")
            with self.assertRaises(ValueError): native.reject_local_environment_files(root)
            self.assertEqual(marker.read_text(), "private fixture sentinel")

    def test_public_example_does_not_block_clean_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / ".env.example").write_text("example")
            native.reject_local_environment_files(root)

    def test_existing_directory_is_refused_without_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve(); marker = path / "keep"; marker.write_text("existing data")
            with self.assertRaises(ValueError): native.fresh_state(path)
            self.assertEqual(marker.read_text(), "existing data")

    def test_symlink_parent_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); (root / "actual").mkdir(); (root / "alias").symlink_to(root / "actual", target_is_directory=True)
            with self.assertRaises(ValueError): native.fresh_state(root / "alias" / "state")

    def test_new_canonical_directory_is_only_planned(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "state"
            self.assertEqual(native.fresh_state(path), path)
            self.assertFalse(path.exists())

    def test_config_injection_path_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            for name in ('bad\nport 6379', 'bad"', 'bad\\'):
                with self.assertRaises(ValueError): native.fresh_state(Path(directory).resolve() / name)

    def test_postgres_18_is_not_substituted_for_supported_16(self):
        with patch.object(native, 'executable', side_effect=lambda n, d=None: '/tools/' + n), \
             patch.object(native.subprocess, 'check_output', side_effect=['postgres (PostgreSQL) 18.4', 'Redis server v=7.4.11']):
            with self.assertRaises(ValueError): native.tool_versions(None, None)

    def test_wrong_redis_major_is_refused(self):
        with patch.object(native, 'executable', side_effect=lambda n, d=None: '/tools/' + n), \
             patch.object(native.subprocess, 'check_output', side_effect=['postgres (PostgreSQL) 16.15', 'Redis server v=8.0.0']):
            with self.assertRaises(ValueError): native.tool_versions(None, None)

    def test_supported_explicit_tools(self):
        with patch.object(native, 'executable', side_effect=lambda n, d=None: '/tools/' + n), \
             patch.object(native.subprocess, 'check_output', side_effect=['postgres (PostgreSQL) 16.15', 'Redis server v=7.4.11']):
            self.assertEqual(native.tool_versions(None, None)['paths']['postgres'], '/tools/postgres')


if __name__ == '__main__': unittest.main()
