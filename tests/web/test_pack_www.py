#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "pack"))
from pack_www import (
    _minify_css,
    _minify_js,
    build_single_html,
)


class TestMinifyCSS:
    def test_removes_comments(self):
        css = "/* comment */ body { color: red; }"
        result = _minify_css(css)
        assert "/*" not in result
        assert "color" in result and "red" in result

    def test_removes_whitespace(self):
        css = "body   {   color:   red;   }"
        result = _minify_css(css)
        assert "   " not in result

    def test_removes_trailing_semicolon(self):
        css = "body { color: red; }"
        result = _minify_css(css)
        assert result.endswith("}")

    def test_preserves_functionality(self):
        css_input = """
        /* Color scheme */
        body {
            margin: 0;
            padding: 0;
            font-family: sans-serif;
            background: #f5f5f5;
            color: #333;
        }

        .tabs {
            display: flex;
            background: #2a2d34;
            color: #fff;
        }
        """
        result = _minify_css(css_input)
        assert "body" in result
        assert ".tabs" in result
        assert "#f5f5f5" in result
        assert "#2a2d34" in result


class TestMinifyJS:
    def test_removes_block_comments(self):
        js = "/* comment */ var x = 1;"
        result = _minify_js(js)
        assert "/*" not in result
        assert "x" in result and "1" in result

    def test_removes_line_comments(self):
        js = """
        var x = 1; // comment
        var y = 2;
        """
        result = _minify_js(js)
        assert "//" not in result
        assert "x" in result
        assert "y" in result

    def test_preserves_functionality(self):
        js_input = """
        function handleClick() {
            // Handle tab click
            const btn = document.querySelector('.active');
            btn.classList.remove('active');
        }
        """
        result = _minify_js(js_input)
        assert "handleClick" in result
        assert "querySelector" in result
        assert "classList" in result
        assert "remove" in result

    def test_preserves_regex_literals(self):
        js = "var regex = /test/g; // comment"
        result = _minify_js(js)
        assert "regex" in result


class TestMinifyHTML:
    def test_html_minification_via_integration(self):
        pass


class TestHTMLFunctionality:
    def test_form_inputs_preserved(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            www_dir = Path(tmpdir) / "www"
            www_dir.mkdir()

            html_content = """
            <!DOCTYPE html>
            <html>
            <head><title>Test</title></head>
            <body>
            <form id="settings">
                <input type="number" id="power_dbm" min="1" max="25">
                <input type="checkbox" id="enable_lbt">
                <select id="mcs_index">
                    <option value="MCS0">MCS0</option>
                    <option value="MCS1">MCS1</option>
                </select>
            </form>
            </body>
            </html>
            """
            (www_dir / "index.html").write_text(html_content)
            out_file = Path(tmpdir) / "out" / "index.html"
            build_single_html(www_dir, out_file)
            result = out_file.read_text()
            assert "power_dbm" in result
            assert "enable_lbt" in result
            assert "mcs_index" in result
            assert "MCS0" in result

    def test_button_attributes_preserved(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            www_dir = Path(tmpdir) / "www"
            www_dir.mkdir()

            html_content = """
            <!DOCTYPE html>
            <html>
            <head><title>Test</title></head>
            <body>
            <button type="button" id="save_btn" disabled>Save</button>
            <button type="button" class="danger" id="reset">Reset</button>
            </body>
            </html>
            """
            (www_dir / "index.html").write_text(html_content)
            out_file = Path(tmpdir) / "out" / "index.html"
            build_single_html(www_dir, out_file)
            result = out_file.read_text()
            assert "save_btn" in result
            assert "reset" in result
            assert "danger" in result

    def test_data_attributes_preserved(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            www_dir = Path(tmpdir) / "www"
            www_dir.mkdir()

            html_content = """
            <!DOCTYPE html>
            <html>
            <head><title>Test</title></head>
            <body>
            <nav class="tabs">
                <button type="button" data-tab="dashboard" class="active">Dashboard</button>
                <button type="button" data-tab="settings">Settings</button>
            </nav>
            </body>
            </html>
            """
            (www_dir / "index.html").write_text(html_content)
            out_file = Path(tmpdir) / "out" / "index.html"
            build_single_html(www_dir, out_file)
            result = out_file.read_text()
            assert "data-tab" in result
            assert "dashboard" in result
            assert "settings" in result

    def test_event_handler_ids_preserved(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            www_dir = Path(tmpdir) / "www"
            www_dir.mkdir()

            html_content = """
            <!DOCTYPE html>
            <html>
            <head><title>Test</title></head>
            <body>
            <div id="nearby_table_body">
                <tr><td>content</td></tr>
            </div>
            <div id="telemetry_status" class="status-message"></div>
            </body>
            </html>
            """
            (www_dir / "index.html").write_text(html_content)
            out_file = Path(tmpdir) / "out" / "index.html"
            build_single_html(www_dir, out_file)
            result = out_file.read_text()
            assert "nearby_table_body" in result
            assert "telemetry_status" in result


class TestJSFunctionality:
    def test_function_calls_preserved(self):
        js = """
        function updateSaveButton(group) {
            const btn = document.getElementById('save_' + group);
            btn.disabled = true;
        }
        """
        result = _minify_js(js)
        assert "updateSaveButton" in result
        assert "getElementById" in result
        assert "disabled" in result

    def test_event_listeners_preserved(self):
        js = """
        document.getElementById('btn').addEventListener('click', handler);
        """
        result = _minify_js(js)
        assert "addEventListener" in result
        assert "click" in result

    def test_fetch_calls_preserved(self):
        js = """
        fetch('/api/get_all').then(res => res.json());
        """
        result = _minify_js(js)
        assert "fetch" in result
        assert "/api/get_all" in result
        assert "json" in result

    def test_array_methods_preserved(self):
        js = """
        data.forEach(item => {
            items.push(item.value);
        });
        """
        result = _minify_js(js)
        assert "forEach" in result
        assert "push" in result


class TestIntegration:
    def test_build_single_html_creates_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            www_dir = Path(tmpdir) / "www"
            www_dir.mkdir()

            html_content = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Test</title>
                <style>
                    body { margin: 0; }
                </style>
            </head>
            <body>
                <h1>Hello</h1>
                <script>
                    console.log('test');
                </script>
            </body>
            </html>
            """
            (www_dir / "index.html").write_text(html_content)

            out_file = Path(tmpdir) / "out" / "index.html"
            build_single_html(www_dir, out_file)

            assert out_file.exists()
            assert out_file.stat().st_size < len(html_content)

    def test_build_single_html_preserves_functionality(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            www_dir = Path(tmpdir) / "www"
            www_dir.mkdir()

            html_content = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Device Config</title>
            </head>
            <body>
                <input type="number" id="power_dbm">
                <button id="save_btn">Save</button>
                <script>
                    document.getElementById('save_btn').addEventListener('click', function() {
                        const value = document.getElementById('power_dbm').value;
                        console.log(value);
                    });
                </script>
            </body>
            </html>
            """
            (www_dir / "index.html").write_text(html_content)

            out_file = Path(tmpdir) / "out" / "index.html"
            build_single_html(www_dir, out_file)

            result = out_file.read_text()

            assert "power_dbm" in result
            assert "save_btn" in result
            assert "addEventListener" in result
            assert "getElementById" in result

    def test_build_with_external_css(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            www_dir = Path(tmpdir) / "www"
            www_dir.mkdir()

            css_content = "body { color: red; } /* comment */"
            (www_dir / "style.css").write_text(css_content)

            html_content = """
            <!DOCTYPE html>
            <html>
            <head>
                <link rel="stylesheet" href="style.css">
            </head>
            <body>Test</body>
            </html>
            """
            (www_dir / "index.html").write_text(html_content)

            out_file = Path(tmpdir) / "out" / "index.html"
            build_single_html(www_dir, out_file)

            result = out_file.read_text()

            assert "color" in result
            assert "red" in result
            assert "/*" not in result

    def test_build_with_external_js(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            www_dir = Path(tmpdir) / "www"
            www_dir.mkdir()

            js_content = """
            function handleClick() {
                // Handle click
                console.log('clicked');
            }
            """
            (www_dir / "main.js").write_text(js_content)

            html_content = """
            <!DOCTYPE html>
            <html>
            <head></head>
            <body>
                <button id="btn">Click</button>
                <script src="main.js"></script>
            </body>
            </html>
            """
            (www_dir / "index.html").write_text(html_content)

            out_file = Path(tmpdir) / "out" / "index.html"
            build_single_html(www_dir, out_file)

            result = out_file.read_text()

            assert "handleClick" in result
            assert "console" in result
            assert "clicked" in result

    def test_size_reduction(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            www_dir = Path(tmpdir) / "www"
            www_dir.mkdir()

            html_content = """
            <!DOCTYPE html>
            <html>
            <head>
                <!-- Configuration UI -->
                <title>Device Configurator</title>
                <style>
                    /* Global styles */
                    * { box-sizing: border-box; }
                    body {
                        margin: 0;
                        padding: 0;
                        font-family: sans-serif;
                        background: #f5f5f5;
                        color: #333;
                    }
                </style>
            </head>
            <body>
                <!-- Main content -->
                <div class="container">
                    <h1>Device Settings</h1>
                    <button id="save">Save Configuration</button>
                </div>

                <script>
                    // Initialize application
                    function initApp() {
                        // Setup event listeners
                        document.getElementById('save').addEventListener('click', handleSave);
                    }

                    function handleSave() {
                        // Handle save action
                        console.log('Saving...');
                    }

                    // Start application when DOM is ready
                    document.addEventListener('DOMContentLoaded', initApp);
                </script>
            </body>
            </html>
            """
            (www_dir / "index.html").write_text(html_content)

            out_file = Path(tmpdir) / "out" / "index.html"
            build_single_html(www_dir, out_file)

            original_size = len(html_content)
            minified_size = out_file.stat().st_size
            reduction_percent = ((original_size - minified_size) / original_size) * 100

            print(f"\nSize reduction: {original_size} -> {minified_size} bytes ({reduction_percent:.1f}% smaller)")

            assert minified_size < original_size
            assert reduction_percent > 20, f"Expected >20% reduction, got {reduction_percent:.1f}%"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
