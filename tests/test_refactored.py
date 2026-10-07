"""
tests/test_refactored.py

Comprehensive test suite for refactored components:
  1. AI analyzer refactoring (single OpenAI-compatible provider)
  2. fetcher.py caching mechanism
  3. engine.py concurrent scanning
  4. Type hints validation
  5. Provider abstraction layer
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from scanner.models import Finding, ScanResult
from ai.providers.base import AIProvider, AIResponse
import requests


# ──────────────────────────────────────────────────────────────────────────
# Tests for AI analyzer refactoring (single OpenAI-compatible provider)
# ──────────────────────────────────────────────────────────────────────────

class TestAIAnalyzerRefactoring:
    """Test that the analyzer uses the OpenAI provider correctly."""
    
    def test_analyze_scan_uses_batched_approach(self):
        """Verify analyze_scan() sends all findings in ONE batched AI call, not N calls."""
        from ai.AI_analyzer import analyze_scan

        scan_result = ScanResult(target_url="https://example.com")
        scan_result.add(Finding(
            vuln_type  = "Test XSS",
            severity   = "HIGH",
            url        = "https://example.com/test",
            detail     = "Test detail",
            evidence   = "<script>alert(1)</script>",
            remediation= "Placeholder"
        ))
        scan_result.add(Finding(
            vuln_type  = "Test SQLi",
            severity   = "CRITICAL",
            url        = "https://example.com/search",
            detail     = "SQL error found",
            evidence   = "You have an error in your SQL syntax",
            remediation= "Placeholder"
        ))

        # Mock the provider constructor
        with patch('ai.AI_analyzer.OpenAIProvider') as mock_openai:
            mock_provider = MagicMock(spec=AIProvider)
            # Batch analysis returns analyses array
            mock_provider.complete.return_value = AIResponse(
                content='{"analyses": [{"verified": true, "cvss_score": 7.5, "severity": "HIGH", "confidence": "HIGH"}, {"verified": true, "cvss_score": 9.0, "severity": "CRITICAL", "confidence": "HIGH"}]}',
                model_used="test-model",
                provider="mock"
            )
            mock_openai.return_value = mock_provider

            with patch('ai.AI_analyzer.ENABLE_AI_ANALYSIS', True):
                result = analyze_scan(scan_result)

            # New batched approach: 2 total calls (1 batch + 1 summary), NOT one per finding
            assert mock_provider.complete.call_count == 2, (
                f"Expected 2 calls (batch + summary), got {mock_provider.complete.call_count}. "
                "The batched approach must NOT send one call per finding."
            )
            assert isinstance(result, dict)
    
    def test_analyze_scan_builds_openai_provider(self):
        """Verify analyze_scan() builds the OpenAI provider."""
        from ai.AI_analyzer import analyze_scan
        
        scan_result = ScanResult(target_url="https://example.com")
        scan_result.add(Finding(
            vuln_type="Test Vuln",
            severity="HIGH",
            url="https://example.com",
            detail="Test",
            evidence="test",
            remediation="test"
        ))
        
        with patch('ai.AI_analyzer.OpenAIProvider') as mock_openai:
            mock_provider = MagicMock(spec=AIProvider)
            mock_provider.name = "test-chain"
            mock_provider.complete.return_value = AIResponse(
                content='{"summary": "Test summary"}',
                model_used="test",
                provider="test"
            )
            mock_openai.return_value = mock_provider
            
            with patch('ai.AI_analyzer.ENABLE_AI_ANALYSIS', True):
                result = analyze_scan(scan_result)
            
            mock_openai.assert_called()
            assert isinstance(result, dict)
    
    def test_parse_ai_response_handles_markdown_fences(self):
        """Test that _parse_ai_response strips markdown code fences."""
        from ai.AI_analyzer import _parse_ai_response
        
        # Test with markdown fences
        response_with_fences = '```json\n{"test": "value"}\n```'
        result = _parse_ai_response(response_with_fences)
        assert result == {"test": "value"}
        
        # Test without fences
        response_plain = '{"test": "value"}'
        result = _parse_ai_response(response_plain)
        assert result == {"test": "value"}
        
        # Test malformed JSON
        response_bad = 'not json'
        result = _parse_ai_response(response_bad)
        assert result == {}


# ──────────────────────────────────────────────────────────────────────────
# Tests for fetcher.py caching
# ──────────────────────────────────────────────────────────────────────────

class TestFetcherCaching:
    """Test response caching in fetcher.py to avoid re-fetching."""
    
    def test_fetch_caches_response(self):
        """Verify that fetch() caches responses within a scan."""
        from scanner.fetcher import fetch, _cache_clear
        
        _cache_clear()  # Start fresh
        
        # Mock requests.get and SSRF check (DNS not available in test env)
        with patch('scanner.fetcher._session.get') as mock_get, \
             patch('scanner.fetcher._is_resolved_ip_safe', return_value=True):
            mock_response = Mock(spec=requests.Response)
            mock_response.text = "<html>test</html>"
            mock_response.headers = {"Content-Type": "text/html"}
            mock_get.return_value = mock_response
            
            # First call should hit the network
            result1 = fetch("https://example.com/page1")
            assert mock_get.call_count == 1
            
            # Second call to same URL should use cache
            result2 = fetch("https://example.com/page1")
            assert mock_get.call_count == 1  # Still 1, not 2
            assert result1 == result2
            
            # Different URL should still hit network
            result3 = fetch("https://example.com/page2")
            assert mock_get.call_count == 2
    
    def test_cache_clear_resets_cache(self):
        """Test that _cache_clear() resets the cache for new scans."""
        from scanner.fetcher import fetch, _cache_clear
        
        with patch('scanner.fetcher._session.get') as mock_get, \
             patch('scanner.fetcher._is_resolved_ip_safe', return_value=True):
            mock_response = Mock(spec=requests.Response)
            mock_response.text = "<html>test</html>"
            mock_response.headers = {"Content-Type": "text/html"}
            mock_get.return_value = mock_response
            
            # Populate cache
            fetch("https://example.com/page", _use_cache=True)
            assert mock_get.call_count == 1
            
            # Clear cache
            _cache_clear()
            
            # Same URL should hit network again
            fetch("https://example.com/page", _use_cache=True)
            assert mock_get.call_count == 2
    
    def test_fetch_with_cache_disabled(self):
        """Test fetch() with caching disabled (_use_cache=False)."""
        from scanner.fetcher import fetch, _cache_clear
        
        _cache_clear()
        
        with patch('scanner.fetcher._session.get') as mock_get, \
             patch('scanner.fetcher._is_resolved_ip_safe', return_value=True):
            mock_response = Mock(spec=requests.Response)
            mock_response.text = "<html>test</html>"
            mock_response.headers = {"Content-Type": "text/html"}
            mock_get.return_value = mock_response
            
            # Fetch with cache disabled
            fetch("https://example.com", _use_cache=False)
            fetch("https://example.com", _use_cache=False)
            
            # Should hit network both times
            assert mock_get.call_count == 2


# ──────────────────────────────────────────────────────────────────────────
# Tests for engine.py concurrent scanning
# ──────────────────────────────────────────────────────────────────────────

class TestConcurrentScanning:
    """Test concurrent page scanning in engine.py."""
    
    def test_scan_page_runs_all_checks(self):
        """Verify _scan_page() runs all check functions."""
        from scanner.engine import _scan_page
        
        url = "https://example.com/page"
        mock_response = Mock(spec=requests.Response)
        mock_response.text = "<html><h1>Test</h1></html>"
        mock_response.headers = {"Server": "Apache/2.4.1"}
        
        # Mock all check functions
        with patch('scanner.engine.run_all_header_checks', return_value=[]) as mock_hdr, \
             patch('scanner.engine.run_all_xss_checks', return_value=[]) as mock_xss, \
             patch('scanner.engine.run_all_sqli_checks', return_value=[]) as mock_sql, \
             patch('scanner.engine.run_all_misc_checks', return_value=[]) as mock_misc, \
              patch('scanner.engine.run_all_ssti_checks', return_value=[]) as mock_ssti, \
              patch('scanner.engine.run_all_secrets_checks', return_value=[]) as mock_secrets, \
              patch('scanner.engine.run_all_form_checks', return_value=[]) as mock_forms, \
              patch('scanner.engine.run_all_traversal_checks', return_value=[]) as mock_trav, \
              patch('scanner.engine.run_all_llm_checks', return_value=[]) as mock_llm, \
              patch('scanner.engine.run_all_template_checks', return_value=[]) as mock_tmpl, \
              patch('scanner.engine.run_all_osv_checks', return_value=[]) as mock_osv, \
              patch('scanner.engine.run_all_tls_checks', return_value=[]) as mock_tls:
            
            findings = _scan_page(url, mock_response, url, tls_checked=False)
            
            # Verify all checks were called
            mock_hdr.assert_called_once()
            mock_xss.assert_called_once()
            mock_sql.assert_called_once()
            mock_misc.assert_called_once()
            mock_ssti.assert_called_once()
            mock_secrets.assert_called_once()
            mock_forms.assert_called_once()
            mock_trav.assert_called_once()
            mock_llm.assert_called_once()
            mock_tmpl.assert_called_once()
            mock_osv.assert_called_once()
            mock_tls.assert_called_once()  # TLS called when tls_checked=False
    
    def test_scan_page_skips_tls_when_already_checked(self):
        """Verify TLS checks are skipped on subsequent pages."""
        from scanner.engine import _scan_page
        
        mock_response = Mock(spec=requests.Response)
        
        with patch('scanner.engine.run_all_tls_checks') as mock_tls, \
             patch('scanner.engine.run_all_header_checks', return_value=[]), \
             patch('scanner.engine.run_all_xss_checks', return_value=[]), \
             patch('scanner.engine.run_all_sqli_checks', return_value=[]), \
             patch('scanner.engine.run_all_misc_checks', return_value=[]), \
             patch('scanner.engine.run_all_ssti_checks', return_value=[]), \
             patch('scanner.engine.run_all_form_checks', return_value=[]), \
             patch('scanner.engine.run_all_traversal_checks', return_value=[]), \
             patch('scanner.engine.run_all_llm_checks', return_value=[]), \
             patch('scanner.engine.run_all_template_checks', return_value=[]), \
             patch('scanner.engine.run_all_osv_checks', return_value=[]), \
             patch('scanner.engine.run_all_secrets_checks', return_value=[]):
            
            _scan_page("https://example.com", mock_response, "https://example.com", tls_checked=True)
            
            # TLS should NOT be called
            mock_tls.assert_not_called()
    
    def test_run_scan_with_concurrent_workers(self):
        """Test run_scan() with concurrent execution."""
        from scanner.engine import run_scan
        
        pages = [
            ("https://example.com/page1", Mock(spec=requests.Response)),
            ("https://example.com/page2", Mock(spec=requests.Response)),
        ]
        
        with patch('scanner.engine.crawl', return_value=pages), \
             patch('scanner.engine._scan_page', return_value=[]), \
             patch('scanner.engine._cache_clear'), \
             patch('scanner.engine.ENABLE_AI_ANALYSIS', False):
            
            result, summary = run_scan("https://example.com", max_workers=2)
            
            assert isinstance(result, ScanResult)
            assert result.target_url == "https://example.com"
            assert len(result.pages_crawled) == 2


# ──────────────────────────────────────────────────────────────────────────
# Integration tests
# ──────────────────────────────────────────────────────────────────────────

class TestIntegration:
    """Integration tests combining refactored components."""
    
    def test_full_scan_with_concurrent_and_caching(self):
        """Test full scan with caching and concurrent scanning."""
        from scanner.engine import run_scan
        from scanner.fetcher import _cache_clear
        
        # Setup
        _cache_clear()
        
        mock_page1 = Mock(spec=requests.Response)
        mock_page1.text = "<html><body>Page 1</body></html>"
        mock_page1.headers = {"Server": "Apache"}
        
        mock_page2 = Mock(spec=requests.Response)
        mock_page2.text = "<html><body>Page 2</body></html>"
        mock_page2.headers = {"Server": "Nginx"}
        
        pages = [
            ("https://example.com/page1", mock_page1),
            ("https://example.com/page2", mock_page2),
        ]
        
        with patch('scanner.engine.crawl', return_value=pages), \
             patch('scanner.engine._scan_page', return_value=[]), \
             patch('scanner.engine._cache_clear'), \
             patch('scanner.engine.ENABLE_AI_ANALYSIS', False):
            
            result, _ = run_scan("https://example.com", max_workers=2)
            
            assert len(result.pages_crawled) == 2
            assert result.scan_duration >= 0


# ──────────────────────────────────────────────────────────────────────────
# Tests for the advanced engine: categories, heuristic risk, form checks,
# traversal checks, time-based SQLi, fetcher retry
# ──────────────────────────────────────────────────────────────────────────

class TestResultComprehensiveness:
    """Category mapping, OWASP fallback, heuristic risk, rich summary."""

    def test_finding_category_mapping(self):
        from scanner.models import finding_category
        assert finding_category("SQL Injection (Error-Based)") == "Injection (SQLi)"
        assert finding_category("Cross-Site Scripting (Reflected XSS)") == "Cross-Site Scripting (XSS)"
        assert finding_category("Missing Header: X-Frame-Options") == "Security Misconfiguration"
        assert finding_category("Missing CSRF Token on Form") == "Broken Access Control"
        assert finding_category("Something Entirely New") == "Other"

    def test_finding_owasp_fallback_and_override(self):
        from scanner.models import finding_owasp
        assert finding_owasp("SQL Injection (Error-Based)") == "A03:2021"
        assert finding_owasp("Open Redirect") == "A01:2021"
        assert finding_owasp("Something Entirely New") == "Unmapped"
        # Explicit AI value always wins over the fallback
        assert finding_owasp("Open Redirect", "A05:2021") == "A05:2021"

    def test_heuristic_risk_bands(self):
        from scanner.models import heuristic_risk
        assert heuristic_risk({}) == (0, "LOW")
        assert heuristic_risk({"CRITICAL": 1}) == (25, "CRITICAL")
        assert heuristic_risk({"HIGH": 2}) == (20, "HIGH")
        assert heuristic_risk({"CRITICAL": 5, "HIGH": 5, "MEDIUM": 5}) == (100, "CRITICAL")

    def test_summary_carries_category_owasp_urls_coverage(self):
        result = ScanResult(target_url="https://example.com")
        result.coverage = {"params_tested": 3, "forms_found": 1}
        result.add(Finding(
            vuln_type="SQL Injection (Error-Based)", severity="CRITICAL",
            url="https://example.com/s?q=1", detail="d", evidence="e",
            remediation="r",
        ))
        result.add(Finding(
            vuln_type="Missing Header: X-Frame-Options", severity="MEDIUM",
            url="example.com", detail="d", evidence="e", remediation="r",
        ))
        s = result.summary()
        assert s["by_category"] == {"Injection (SQLi)": 1, "Security Misconfiguration": 1}
        assert s["by_owasp"] == {"A03:2021": 1, "A05:2021": 1}
        assert s["top_urls"][0] == {"url": "https://example.com/s?q=1", "findings": 1}
        assert s["coverage"]["params_tested"] == 3

    def test_heuristic_summary_shape(self):
        result = ScanResult(target_url="https://example.com")
        result.add(Finding(
            vuln_type="SQL Injection (Error-Based)", severity="CRITICAL",
            url="https://example.com/s?q=1", detail="d", evidence="e",
            remediation="r",
        ))
        h = result.heuristic_summary()
        assert h["overall_risk"] == "CRITICAL"
        assert h["risk_score"] == 25
        assert h["source"] == "heuristic"
        assert h["key_risks"] and h["immediate_actions"]
        assert "executive_summary" in h


class TestTraversalChecks:
    """Path traversal confirmation requires real file markers."""

    def _resp(self, text):
        r = Mock(spec=requests.Response)
        r.text = text
        return r

    def test_confirms_unix_passwd_read(self):
        from scanner.traversal_checks import check_path_traversal
        with patch('scanner.traversal_checks._session') as sess:
            sess.get.return_value = self._resp("root:x:0:0: daemon...")
            findings = check_path_traversal("https://example.com/view?file=x")
        assert len(findings) == 1
        assert findings[0].severity == "HIGH"
        assert "Traversal" in findings[0].vuln_type

    def test_no_marker_no_finding(self):
        from scanner.traversal_checks import check_path_traversal
        with patch('scanner.traversal_checks._session') as sess:
            sess.get.return_value = self._resp("<html>not found</html>")
            findings = check_path_traversal("https://example.com/view?file=x")
        assert findings == []

    def test_skips_urls_without_params(self):
        from scanner.traversal_checks import check_path_traversal
        with patch('scanner.traversal_checks._session') as sess:
            assert check_path_traversal("https://example.com/about") == []
            sess.get.assert_not_called()


class TestTimeBasedSqli:
    """Time-based blind SQLi uses the dual delay threshold."""

    def _resp(self):
        r = Mock(spec=requests.Response)
        r.text = "<html>same content</html>"
        return r

    def test_confirms_sleep_delay(self):
        from scanner.sqli_checks import check_time_based_sqli
        with patch('scanner.sqli_checks._timed_get') as timed:
            # baseline fast, first payload slow → confirmed, second payload skipped
            timed.side_effect = [(self._resp(), 0.2), (self._resp(), 3.4)]
            findings = check_time_based_sqli("https://example.com/s?q=1")
        assert len(findings) == 1
        assert findings[0].severity == "CRITICAL"
        assert "Time-Based" in findings[0].vuln_type

    def test_fast_responses_are_clean(self):
        from scanner.sqli_checks import check_time_based_sqli
        with patch('scanner.sqli_checks._timed_get') as timed:
            timed.side_effect = [(self._resp(), 0.2), (self._resp(), 0.25), (self._resp(), 0.3)]
            assert check_time_based_sqli("https://example.com/s?q=1") == []


class TestFormChecks:
    """Active form submission + CSRF token detection."""

    def _page(self, html):
        r = Mock(spec=requests.Response)
        r.text = html
        return r

    def test_get_form_reflection_confirmed(self):
        from scanner.form_checks import check_form_injection
        html = ('<html><form action="/search" method="GET">'
                '<input type="text" name="q"><input type="submit"></form></html>')
        with patch('scanner.form_checks._session') as sess:
            r = self._page("results for xssprobe7x9 \"><svg onload=alert(xssprobe7x9)>")
            sess.get.return_value = r
            findings = check_form_injection("https://example.com/", self._page(html))
        assert len(findings) == 1
        assert findings[0].severity == "HIGH"
        assert "Form" in findings[0].vuln_type

    def test_post_form_without_csrf_flagged(self):
        from scanner.form_checks import check_form_csrf
        html = ('<html><form action="/profile" method="POST">'
                '<input type="text" name="email"></form></html>')
        findings = check_form_csrf("https://example.com/", self._page(html))
        assert len(findings) == 1
        assert findings[0].severity == "MEDIUM"

    def test_post_form_with_csrf_token_passes(self):
        from scanner.form_checks import check_form_csrf
        html = ('<html><form action="/profile" method="POST">'
                '<input type="hidden" name="csrf_token" value="abc">'
                '<input type="text" name="email"></form></html>')
        assert check_form_csrf("https://example.com/", self._page(html)) == []


class TestFetcherRetry:
    """Transient fetch failures get exactly one retry."""

    def test_retry_then_success(self):
        from scanner.fetcher import fetch, _cache_clear
        _cache_clear()
        with patch('scanner.fetcher._session.get') as mock_get, \
             patch('scanner.fetcher._is_resolved_ip_safe', return_value=True):
            ok = Mock(spec=requests.Response)
            ok.text = "<html>ok</html>"
            ok.headers = {"Content-Type": "text/html"}
            mock_get.side_effect = [requests.exceptions.ConnectionError("reset"), ok]
            assert fetch("https://example.com/r", _use_cache=False) is ok
            assert mock_get.call_count == 2

    def test_gives_up_after_second_failure(self):
        from scanner.fetcher import fetch, _cache_clear
        _cache_clear()
        with patch('scanner.fetcher._session.get') as mock_get, \
             patch('scanner.fetcher._is_resolved_ip_safe', return_value=True):
            mock_get.side_effect = requests.exceptions.Timeout("slow")
            assert fetch("https://example.com/t", _use_cache=False) is None
            assert mock_get.call_count == 2


class TestHeuristicFallback:
    """run_scan without AI still returns a complete executive summary."""

    def test_no_ai_gives_heuristic_summary(self):
        from scanner.engine import run_scan
        pages = [("https://example.com/?q=1", Mock(spec=requests.Response))]
        with patch('scanner.engine.crawl', return_value=pages), \
             patch('scanner.engine._scan_page', return_value=[]), \
             patch('scanner.engine._cache_clear'), \
             patch('scanner.engine.ENABLE_AI_ANALYSIS', False):
            result, summary = run_scan("https://example.com", max_workers=1)
            assert summary["source"] == "heuristic"
            assert summary["risk_score"] == 0
            assert result.coverage["params_tested"] == 1


class TestAiFailureSurfacing:
    """AI provider failures must be recorded, not silently swallowed."""

    def _result_with_high(self):
        result = ScanResult(target_url="https://example.com")
        result.add(Finding(
            vuln_type="SQL Injection (Error-Based)", severity="HIGH",
            url="https://example.com/s?q=1", detail="d", evidence="e",
            remediation="r",
        ))
        return result

    def test_batch_provider_error_records_reason(self):
        from ai.AI_analyzer import analyze_scan, get_last_ai_error
        from ai.providers.base import ProviderError
        with patch('ai.AI_analyzer.OpenAIProvider') as mock_openai:
            mock_provider = MagicMock(spec=AIProvider)
            mock_provider.complete.side_effect = ProviderError("Error code: 404 - bad model")
            mock_openai.return_value = mock_provider
            with patch('ai.AI_analyzer.ENABLE_AI_ANALYSIS', True):
                result = self._result_with_high()
                summary = analyze_scan(result)
            assert summary == {}
            assert "404" in get_last_ai_error()
            assert result.findings[0].ai_verified is False

    def test_engine_attaches_ai_error_to_heuristic_summary(self):
        from scanner.engine import run_scan
        pages = [("https://example.com/?q=1", Mock(spec=requests.Response))]
        with patch('scanner.engine.crawl', return_value=pages), \
             patch('scanner.engine._scan_page', return_value=[]), \
             patch('scanner.engine._cache_clear'), \
             patch('ai.AI_analyzer.analyze_scan', return_value={}), \
             patch('ai.AI_analyzer.get_last_ai_error', return_value="Batch analysis failed: 404"):
            _, summary = run_scan("https://example.com", run_ai=True, max_workers=1)
            assert summary["source"] == "heuristic"
            assert summary["ai_error"] == "Batch analysis failed: 404"


class TestModelFallbackChain:
    """AI_MODEL comma list: dead/rate-limited models are skipped, auth fails fast."""

    def _provider(self, models):
        from ai.providers.openai_provider import OpenAIProvider
        p = OpenAIProvider(model=models, api_key="test-key")
        p._client = MagicMock()
        return p

    def _ok(self, content='{"ok": true}'):
        r = MagicMock()
        r.choices = [MagicMock()]
        r.choices[0].message.content = content
        return r

    def test_models_parsed_in_priority_order(self):
        p = self._provider("dead-model, alive-model ,")
        assert p._models == ["dead-model", "alive-model"]
        assert p._model == "dead-model"

    def test_fails_over_on_404(self):
        p = self._provider("dead-model,alive-model")
        create = p._client.chat.completions.create
        create.side_effect = [Exception("Error code: 404 - not found"), self._ok()]
        out = p.complete("sys", "hi")
        assert out.content == '{"ok": true}'
        assert out.model_used == "alive-model"
        assert create.call_count == 2
        assert create.call_args[1]["model"] == "alive-model"

    def test_auth_error_fails_fast_without_retry(self):
        from ai.providers.base import ProviderError
        p = self._provider("m1,m2")
        create = p._client.chat.completions.create
        create.side_effect = Exception("Error code: 401 - invalid_api_key")
        with pytest.raises(ProviderError):
            p.complete("sys", "hi")
        assert create.call_count == 1

    def test_all_models_failing_reports_every_model(self):
        from ai.providers.base import ProviderError
        p = self._provider("m1,m2")
        p._client.chat.completions.create.side_effect = Exception("Error code: 429 - slow down")
        with pytest.raises(ProviderError) as exc:
            p.complete("sys", "hi")
        assert "m1" in str(exc.value) and "m2" in str(exc.value)


class TestAttackChainsAndPrevention:
    """Evidenced exploitation chains + systemic prevention guidance."""

    def _f(self, vuln_type, severity="HIGH", url="https://example.com/"):
        return Finding(vuln_type=vuln_type, severity=severity, url=url,
                       detail="d", evidence="e", remediation="r")

    def test_xss_cookie_chain_links_real_findings(self):
        from scanner.models import build_attack_chains
        findings = [
            self._f("Cross-Site Scripting (Reflected XSS)", "HIGH", "https://example.com/s?q=1"),
            self._f("Insecure Cookie: Missing HttpOnly", "MEDIUM", "https://example.com/"),
        ]
        chains = build_attack_chains(findings)
        assert len(chains) == 1
        assert chains[0]["title"] == "XSS Session Hijack"
        assert chains[0]["severity"] == "HIGH"
        assert "https://example.com/s?q=1" in chains[0]["narrative"]

    def test_no_links_no_chains(self):
        from scanner.models import build_attack_chains
        assert build_attack_chains([self._f("Directory Listing Enabled", "MEDIUM")]) == []

    def test_chains_ordered_by_severity_and_capped(self):
        from scanner.models import build_attack_chains
        findings = [
            self._f("Open Redirect", "HIGH"),
            self._f("Missing CSRF Token on Form", "MEDIUM"),
            self._f("SQL Injection (Error-Based)", "CRITICAL"),
            self._f("JWT Algorithm:None Bypass", "CRITICAL"),
        ]
        chains = build_attack_chains(findings)
        assert chains[0]["severity"] == "CRITICAL"
        assert len(chains) <= 5

    def test_prevention_guidance_per_category(self):
        from scanner.models import prevention_for
        assert "parameterized" in prevention_for("SQL Injection (Error-Based)").lower()
        assert prevention_for("Something Entirely New") == ""


class TestLlmChecks:
    """LLM surface detection with explicit LLM Top 10 ids."""

    def _resp(self, text):
        r = Mock(spec=requests.Response)
        r.text = text
        r.headers = {"Content-Type": "text/html"}
        return r

    def test_model_name_leak_flagged(self):
        from scanner.llm_checks import check_model_disclosure
        f = check_model_disclosure("https://x/", self._resp("var m='gpt-4o-mini';"))
        assert len(f) == 1 and f[0].owasp_id == "LLM10:2025" and f[0].severity == "INFO"

    def test_llm_api_key_is_critical(self):
        from scanner.llm_checks import check_llm_keys
        f = check_llm_keys("https://x/", self._resp('key="sk-ant-abc123XYZ456"'))
        assert len(f) == 1 and f[0].severity == "CRITICAL" and f[0].owasp_id == "LLM02:2025"

    def test_open_chat_endpoint_is_high(self):
        from scanner.llm_checks import check_llm_endpoints
        r = self._resp('{"object":"list","data":[{"id":"m","object":"model"}]}')
        r.status_code = 200
        with patch('scanner.llm_checks._session') as sess:
            sess.get.return_value = r
            findings = check_llm_endpoints("https://x/")
        assert any("Chat Endpoint" in f.vuln_type and f.severity == "HIGH" for f in findings)

    def test_catchall_without_markers_ignored(self):
        from scanner.llm_checks import check_llm_endpoints
        r = self._resp("<html><div id=root></div></html>")
        r.status_code = 200
        with patch('scanner.llm_checks._session') as sess:
            sess.get.return_value = r
            assert check_llm_endpoints("https://x/") == []

    def test_chat_form_surface_flagged(self):
        from scanner.llm_checks import check_prompt_injection_surface
        html = ('<html><form action="/api/chat" method="POST">'
                '<textarea name="prompt"></textarea></form></html>')
        f = check_prompt_injection_surface("https://x/", self._resp(html))
        assert len(f) == 1 and f[0].owasp_id == "LLM01:2025"


class TestTemplateChecks:
    """Declarative JSON templates fire without code changes."""

    def test_git_config_template_matches(self):
        from scanner.template_checks import check_templates
        def fake_get(url, **kw):
            r = Mock(spec=requests.Response)
            if url.endswith("/.git/config"):
                r.status_code = 200
                r.text = "[core]\n\trepositoryformatversion = 0\n"
                r.content = r.text.encode()
                r.headers = {"Content-Type": "text/plain"}
            else:
                r.status_code = 404
                r.text = "not found"
                r.content = b"not found"
                r.headers = {"Content-Type": "text/html"}
            return r
        with patch('scanner.template_checks._session') as sess:
            sess.get.side_effect = fake_get
            findings = check_templates("https://example.com/")
        hit = [f for f in findings if f.vuln_type == "Sensitive Path Exposure: /.git/config"]
        assert len(hit) == 1 and hit[0].severity == "HIGH"
        assert hit[0].owasp_id == "A05:2021"

    def test_templates_skipped_off_base_url(self):
        from scanner.template_checks import run_all_template_checks
        r = Mock(spec=requests.Response)
        assert run_all_template_checks("https://x/page", r, "https://x/") == []


class TestOsvChecks:
    """JS library versions resolved against OSV records."""

    def test_extracts_lib_versions(self):
        from scanner.osv_checks import _extract_libs
        html = ('<html><script src="/js/jquery-3.4.1.min.js"></script>'
                '<script src="https://cdn/x/bootstrap@5.3.2/dist.js"></script></html>')
        assert ("jquery", "3.4.1") in _extract_libs("https://x/", html)
        assert ("bootstrap", "5.3.2") in _extract_libs("https://x/", html)

    def test_vulnerable_lib_flagged_with_cves(self):
        from scanner.osv_checks import check_js_libraries
        html = '<html><script src="/js/jquery-3.4.1.min.js"></script></html>'
        r = Mock(spec=requests.Response)
        r.text = html
        r.headers = {"Content-Type": "text/html"}
        osv_resp = Mock()
        osv_resp.status_code = 200
        osv_resp.json.return_value = {"vulns": [{
            "id": "GHSA-jquery-xss", "summary": "XSS in jQuery",
            "aliases": ["CVE-2020-11022"],
            "database_specific": {"severity": "high"},
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}],
        }]}
        with patch('scanner.osv_checks.requests.post', return_value=osv_resp):
            findings = check_js_libraries("https://x/", r)
        assert len(findings) == 1
        assert findings[0].severity == "HIGH"
        assert "CVE-2020-11022" in findings[0].cve_ids
        assert findings[0].owasp_id == "A06:2021"

    def test_offline_osv_is_silent_skip(self):
        from scanner import osv_checks
        from scanner.osv_checks import check_js_libraries
        osv_checks._osv_cache.clear()
        html = '<html><script src="/js/jquery-3.4.1.min.js"></script></html>'
        r = Mock(spec=requests.Response)
        r.text = html
        r.headers = {"Content-Type": "text/html"}
        with patch('scanner.osv_checks.requests.post',
                   side_effect=requests.exceptions.ConnectionError):
            assert check_js_libraries("https://x/", r) == []


class TestAiChunking:
    """Big priority lists are split into parseable chunks, not one giant call."""

    def _result_with_n_high(self, n):
        result = ScanResult(target_url="https://example.com")
        for i in range(n):
            result.add(Finding(
                vuln_type=f"Test Vuln {i}", severity="HIGH",
                url=f"https://example.com/p{i}", detail="d" * 2000,
                evidence="e" * 2000, remediation="r",
            ))
        return result

    def _batch_response(self, count):
        from ai.providers.base import AIResponse
        analyses = [{
            "verified": True, "confidence": "HIGH", "severity": "HIGH",
            "cvss_score": 7.0, "owasp_id": "A05:2021", "cwe_id": "CWE-693",
            "remediation_steps": ["fix it"], "cve_ids": [],
        } for _ in range(count)]
        import json as _json
        return AIResponse(content=_json.dumps({"analyses": analyses}),
                          model_used="test", provider="test")

    def test_thirty_findings_use_two_chunks_plus_summary(self):
        from ai.AI_analyzer import analyze_scan, AI_BATCH_SIZE
        assert AI_BATCH_SIZE == 25
        from ai.providers.base import AIResponse
        with patch('ai.AI_analyzer.OpenAIProvider') as mock_openai:
            mock_provider = MagicMock(spec=AIProvider)
            mock_provider.complete.side_effect = [
                self._batch_response(25), self._batch_response(5),
                AIResponse(content='{"overall_risk": "HIGH", "risk_score": 50}',
                           model_used="test", provider="test"),
            ]
            mock_openai.return_value = mock_provider
            with patch('ai.AI_analyzer.ENABLE_AI_ANALYSIS', True):
                result = self._result_with_n_high(30)
                summary = analyze_scan(result)
            assert mock_provider.complete.call_count == 3
            assert all(f.ai_verified is True for f in result.findings)
            assert summary["risk_score"] == 50

    def test_failed_chunk_marks_only_its_findings(self):
        from ai.AI_analyzer import analyze_scan, get_last_ai_error
        from ai.providers.base import AIResponse, ProviderError
        with patch('ai.AI_analyzer.OpenAIProvider') as mock_openai:
            mock_provider = MagicMock(spec=AIProvider)
            mock_provider.complete.side_effect = [
                ProviderError("Error code: 429 - slow down"),
                self._batch_response(5),
                AIResponse(content='{"overall_risk": "HIGH", "risk_score": 50}',
                           model_used="test", provider="test"),
            ]
            mock_openai.return_value = mock_provider
            with patch('ai.AI_analyzer.ENABLE_AI_ANALYSIS', True):
                result = self._result_with_n_high(30)
                analyze_scan(result)
            assert sum(1 for f in result.findings if f.ai_verified is False) == 25
            assert sum(1 for f in result.findings if f.ai_verified is True) == 5
            assert "429" in get_last_ai_error()

    def test_batch_size_knob_controls_call_count(self):
        from ai.AI_analyzer import analyze_scan
        from ai.providers.base import AIResponse
        with patch('ai.AI_analyzer.OpenAIProvider') as mock_openai, \
             patch('ai.AI_analyzer.AI_BATCH_SIZE', 1):
            mock_provider = MagicMock(spec=AIProvider)
            mock_provider.complete.side_effect = [
                self._batch_response(1), self._batch_response(1),
                AIResponse(content='{"overall_risk": "HIGH", "risk_score": 50}',
                           model_used="test", provider="test"),
            ]
            mock_openai.return_value = mock_provider
            with patch('ai.AI_analyzer.ENABLE_AI_ANALYSIS', True):
                result = self._result_with_n_high(2)
                analyze_scan(result)
            # AI_BATCH_SIZE=1 → one call per finding + summary
            assert mock_provider.complete.call_count == 3
            assert all(f.ai_verified is True for f in result.findings)

    def test_empty_analyses_records_error(self):
        from ai.AI_analyzer import analyze_scan, get_last_ai_error
        from ai.providers.base import AIResponse
        with patch('ai.AI_analyzer.OpenAIProvider') as mock_openai:
            mock_provider = MagicMock(spec=AIProvider)
            mock_provider.complete.side_effect = [
                AIResponse(content='{"truncated...', model_used="test", provider="test"),
                AIResponse(content='{"overall_risk": "LOW", "risk_score": 0}',
                           model_used="test", provider="test"),
            ]
            mock_openai.return_value = mock_provider
            with patch('ai.AI_analyzer.ENABLE_AI_ANALYSIS', True):
                result = self._result_with_n_high(1)
                analyze_scan(result)
            assert result.findings[0].ai_verified is False
            assert "no usable analyses" in get_last_ai_error()


class TestFalsePositiveFixes:
    """Same form/secret on N pages collapses instead of flooding results."""

    def _page(self, html):
        r = Mock(spec=requests.Response)
        r.text = html
        r.headers = {"Content-Type": "text/html"}
        return r

    def test_secrets_are_site_wide(self):
        from scanner.engine import _is_site_wide
        assert _is_site_wide("Secret Exposure: Google API Key") is True

    def test_llm_module_no_longer_flags_aiza(self):
        from scanner.llm_checks import LLM_KEY_PATTERNS
        assert not any("AIza" in pattern for pattern, _ in LLM_KEY_PATTERNS)

    def test_form_surface_url_is_the_action(self):
        from scanner.xss_checks import check_forms_for_xss
        from scanner.sqli_checks import check_forms_for_sqli
        html = ('<html><form action="/search" method="GET">'
                '<input type="text" name="q"></form></html>')
        page = "https://example.com/some-page/"
        for fn in (check_forms_for_xss, lambda u, r: check_forms_for_sqli(u, r)):
            findings = fn(page, self._page(html))
            assert len(findings) == 1
            assert findings[0].url == "https://example.com/search"

    def test_form_csrf_url_is_the_action(self):
        from scanner.form_checks import check_form_csrf
        html = ('<html><form action="/profile" method="POST">'
                '<input type="text" name="email"></form></html>')
        findings = check_form_csrf("https://example.com/any-page/", self._page(html))
        assert len(findings) == 1
        assert findings[0].url == "https://example.com/profile"

    def test_same_form_on_many_pages_collapses_in_engine(self):
        from scanner.engine import run_scan
        from scanner.models import Finding
        # One shared newsletter form + one shared Maps key, seen on 3 pages
        def page_findings(url):
            return [
                Finding(vuln_type="XSS Attack Surface: Unvalidated Form Input",
                        severity="INFO", url="https://example.com/subscribe",
                        detail="d", evidence="Form action='https://example.com/subscribe', method='GET'",
                        remediation="r"),
                Finding(vuln_type="Secret Exposure: Google API Key",
                        severity="HIGH", url="nirma-test-site",
                        detail="d", evidence="Pattern matched: Google API Key — redacted sample: AIzaSy...g94w",
                        remediation="r"),
            ]
        pages = [(f"https://example.com/p{i}", Mock(spec=requests.Response)) for i in range(3)]
        with patch('scanner.engine.crawl', return_value=pages), \
             patch('scanner.engine._scan_page', side_effect=lambda u, r, t, tls: page_findings(u)), \
             patch('scanner.engine._cache_clear'), \
             patch('scanner.engine.ENABLE_AI_ANALYSIS', False):
            result, _ = run_scan("https://example.com", max_workers=1)
            by_type = {}
            for f in result.findings:
                by_type[f.vuln_type] = by_type.get(f.vuln_type, 0) + 1
            assert by_type == {
                "XSS Attack Surface: Unvalidated Form Input": 1,
                "Secret Exposure: Google API Key": 1,
            }


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
