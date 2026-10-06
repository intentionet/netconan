"""End-to-end tests for description anonymization."""

from netconan.netconan import main

INPUT_CONTENTS = """\
interface GigabitEthernet0/0
 description "uplink to core-router1 (port 14)"
 ip address 10.0.0.1 255.255.255.0
!
interface GigabitEthernet0/1
 description link-to-provider;
 ip address 10.0.0.2 255.255.255.0
!
"""


def test_e2e_descriptions(tmpdir):
    """Test that --anonymize-descriptions replaces description content."""
    filename = "test.cfg"
    input_dir = tmpdir.mkdir("input")
    input_dir.join(filename).write(INPUT_CONTENTS)

    output_dir = tmpdir.mkdir("output")
    args = [
        "-i",
        str(input_dir),
        "-o",
        str(output_dir),
        "-s",
        "E2ESALT",
        "--anonymize-descriptions",
    ]
    main(args)

    with open(str(output_dir.join(filename))) as f:
        output = f.read()

    # Description content should be replaced
    assert "uplink to core-router1 (port 14)" not in output
    assert "link-to-provider" not in output
    assert "descr_" in output

    # Non-description lines should be preserved
    assert "interface GigabitEthernet0/0" in output
    assert "ip address 10.0.0.1 255.255.255.0" in output
    assert "interface GigabitEthernet0/1" in output


def test_e2e_descriptions_deterministic(tmpdir):
    """Test that description anonymization is deterministic with same salt."""
    filename = "test.cfg"

    input_dir1 = tmpdir.mkdir("input1")
    input_dir1.join(filename).write(INPUT_CONTENTS)
    output_dir1 = tmpdir.mkdir("output1")

    input_dir2 = tmpdir.mkdir("input2")
    input_dir2.join(filename).write(INPUT_CONTENTS)
    output_dir2 = tmpdir.mkdir("output2")

    args_base = ["-s", "DETSALT", "--anonymize-descriptions"]

    main(args_base + ["-i", str(input_dir1), "-o", str(output_dir1)])
    main(args_base + ["-i", str(input_dir2), "-o", str(output_dir2)])

    with (
        open(str(output_dir1.join(filename))) as f1,
        open(str(output_dir2.join(filename))) as f2,
    ):
        assert f1.read() == f2.read()
