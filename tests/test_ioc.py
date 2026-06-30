from cti_tracker.ioc import extract_iocs


def test_extract_iocs_normalizes_defanged_values():
    sha256 = "a" * 64
    text = (
        f"Indicators: {sha256} 44d88612fea8a8f36de82e1278abb02f "
        "hxxps://login[.]example[.]com/path 192[.]0[.]2[.]10"
    )

    assert ("file:hashes.'SHA-256'", sha256) in extract_iocs(text)
    assert ("file:hashes.MD5", "44d88612fea8a8f36de82e1278abb02f") in extract_iocs(text)
    assert ("url", "https://login.example.com/path") in extract_iocs(text)
    assert ("domain-name", "login.example.com") in extract_iocs(text)
    assert ("ipv4-addr", "192.0.2.10") in extract_iocs(text)


def test_extract_iocs_rejects_invalid_ipv4_addresses():
    assert ("ipv4-addr", "999.1.2.3") not in extract_iocs("999[.]1[.]2[.]3")


def test_extract_iocs_does_not_treat_filenames_as_domains():
    values = extract_iocs("start.hta cmd.exe archive.zip actual[.]example")
    assert ("domain-name", "actual.example") in values
    assert not any(value in {"start.hta", "cmd.exe", "archive.zip"} for _, value in values)
