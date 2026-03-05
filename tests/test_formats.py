"""Tests for format detection."""

import io
import json

from protobom.formats import (
    CDX14JSON,
    CDX15JSON,
    CDX16JSON,
    CYCLONEDX,
    Format,
    JSON,
    SPDX,
    SPDX22JSON,
    SPDX23JSON,
    sniff,
    sniff_string,
)


class TestFormat:
    def test_version(self):
        f = Format(CDX15JSON)
        assert f.version() == "1.5"

    def test_major(self):
        f = Format(CDX15JSON)
        assert f.major() == "1"

    def test_minor(self):
        f = Format(CDX15JSON)
        assert f.minor() == "5"

    def test_encoding_json(self):
        f = Format(CDX15JSON)
        assert f.encoding() == JSON

    def test_type_cyclonedx(self):
        f = Format(CDX15JSON)
        assert f.type() == CYCLONEDX

    def test_type_spdx(self):
        f = Format(SPDX23JSON)
        assert f.type() == SPDX

    def test_equality(self):
        f1 = Format(CDX15JSON)
        f2 = Format(CDX15JSON)
        assert f1 == f2

    def test_equality_string(self):
        f = Format(CDX15JSON)
        assert f == CDX15JSON

    def test_str(self):
        f = Format(CDX15JSON)
        assert str(f) == CDX15JSON


class TestSniff:
    def test_detect_cyclonedx_14(self):
        data = {"bomFormat": "CycloneDX", "specVersion": "1.4", "components": []}
        result = sniff_string(json.dumps(data))
        assert result == CDX14JSON

    def test_detect_cyclonedx_15(self):
        data = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}
        result = sniff_string(json.dumps(data))
        assert result == CDX15JSON

    def test_detect_cyclonedx_16(self):
        data = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}
        result = sniff_string(json.dumps(data))
        assert result == CDX16JSON

    def test_detect_spdx_23(self):
        data = {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT"}
        result = sniff_string(json.dumps(data))
        assert result == SPDX23JSON

    def test_detect_spdx_22(self):
        data = {"spdxVersion": "SPDX-2.2", "SPDXID": "SPDXRef-DOCUMENT"}
        result = sniff_string(json.dumps(data))
        assert result == SPDX22JSON

    def test_detect_spdx_tv(self):
        text = "SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0\n"
        result = sniff_string(text)
        assert result is not None
        assert result.type() == SPDX

    def test_unknown_format(self):
        result = sniff_string("not an sbom")
        assert result is None

    def test_invalid_json(self):
        result = sniff_string("{invalid json")
        assert result is None

    def test_sniff_stream(self):
        data = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}
        stream = io.BytesIO(json.dumps(data).encode())
        result = sniff(stream)
        assert result == CDX15JSON
        # Stream should be seeked back to beginning
        assert stream.tell() == 0
