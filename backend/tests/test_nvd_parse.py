from app.collectors.nvd import extract_cvss, extract_vendor_product, is_valid_cve_id


def test_prefers_cvss_v4_primary():
    item = {"metrics": {
        "cvssMetricV40": [
            {"type": "Secondary", "cvssData": {"baseScore": 7.0, "baseSeverity": "HIGH", "vectorString": "CVSS:4.0/x", "version": "4.0"}},
            {"type": "Primary", "cvssData": {"baseScore": 9.3, "baseSeverity": "CRITICAL", "vectorString": "CVSS:4.0/y", "version": "4.0"}},
        ],
        "cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM"}}],
    }}
    assert extract_cvss(item) == {"score": "9.3", "severity": "CRITICAL", "vector": "CVSS:4.0/y", "version": "4.0"}


def test_cvss_v2_severity_outside_cvssdata():
    item = {"metrics": {"cvssMetricV2": [{"baseSeverity": "HIGH", "cvssData": {"baseScore": 7.5, "vectorString": "AV:N"}}]}}
    assert extract_cvss(item)["severity"] == "HIGH"


def test_no_metrics():
    assert extract_cvss({"metrics": {}}) is None
    assert extract_cvss({}) is None


def test_vendor_product_from_cpe():
    item = {"configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": False, "criteria": "cpe:2.3:o:linux:linux_kernel:*"},
        {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"},
    ]}]}]}
    assert extract_vendor_product(item) == ("apache", "http server")


def test_cve_validation():
    assert is_valid_cve_id("CVE-2024-3094")
    assert is_valid_cve_id("CVE-2026-1199770")
    assert not is_valid_cve_id("CVE-2024-1")
    assert not is_valid_cve_id("CVE-2024-3094' OR 1=1")
    assert not is_valid_cve_id("cve-2024-3094")
    assert not is_valid_cve_id(None)
