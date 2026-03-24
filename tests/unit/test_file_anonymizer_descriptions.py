"""Tests for description anonymization integration in the FileAnonymizer pipeline."""

import io

from netconan.anonymize_files import FileAnonymizer


class TestFileAnonymizerDescriptions:
    """Tests for description anonymization through the FileAnonymizer pipeline."""

    def _anonymize_line(
        self, line, anon_descriptions=True, anon_pwd=False, salt="test"
    ):
        """Helper: run a single line through the anonymizer pipeline."""
        anonymizer = FileAnonymizer(
            anon_pwd=anon_pwd,
            anon_ip=False,
            salt=salt,
            anon_descriptions=anon_descriptions,
        )
        in_io = io.StringIO(line)
        out_io = io.StringIO()
        anonymizer.anonymize_io(in_io, out_io)
        return out_io.getvalue()

    def test_description_only(self):
        """Description line is anonymized when anon_descriptions is enabled."""
        result = self._anonymize_line('description "sensitive host"\n')
        assert "descr_" in result
        assert "sensitive host" not in result

    def test_descriptions_disabled(self):
        """Description line is unchanged when anon_descriptions is disabled."""
        line = 'description "sensitive host"\n'
        result = self._anonymize_line(line, anon_descriptions=False)
        assert result == line

    def test_description_with_passwords(self):
        """Both description and password anonymization work together."""
        lines = 'description "link to core"\npassword foobar\n'
        result = self._anonymize_line(lines, anon_descriptions=True, anon_pwd=True)
        assert "descr_" in result
        assert "link to core" not in result
        assert "foobar" not in result

    def test_non_description_unchanged(self):
        """Non-description lines are not modified."""
        line = "ip address 10.0.0.1 255.255.255.0\n"
        result = self._anonymize_line(line)
        assert result == line

    def test_deterministic_with_salt(self):
        """Same salt produces same anonymized output."""
        line = 'description "test value"\n'
        result1 = self._anonymize_line(line, salt="mysalt")
        result2 = self._anonymize_line(line, salt="mysalt")
        assert result1 == result2

    def test_multiline_file(self):
        """Only description lines are modified in a multi-line file."""
        content = (
            "interface GigabitEthernet0/0\n"
            ' description "uplink to ISP"\n'
            " ip address 10.0.0.1 255.255.255.0\n"
            "!\n"
        )
        result = self._anonymize_line(content)
        lines = result.split("\n")
        assert lines[0] == "interface GigabitEthernet0/0"
        assert "descr_" in lines[1]
        assert "uplink to ISP" not in lines[1]
        assert lines[2] == " ip address 10.0.0.1 255.255.255.0"
        assert lines[3] == "!"
