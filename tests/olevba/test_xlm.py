"""Tests for the built-in Excel 4.0 (XL4/XLM) macro sheet parser."""

import os
import tempfile
import unittest

from oletools import olevba
from oletools import xlm_parser
from tests.test_utils import DATA_BASE_DIR


class TestXL4Samples(unittest.TestCase):
    """Parse representative XL4 sample files and validate report compatibility."""

    sample_dir = os.path.join(DATA_BASE_DIR, 'excel4-macros')

    def parse_sample(self, filename):
        full_name = os.path.join(self.sample_dir, filename)
        parser = olevba.VBA_Parser_CLI(full_name)
        try:
            return parser.process_file_json()
        finally:
            parser.close()

    def assert_xl4_report(self, filename, sheet_name):
        result = self.parse_sample(filename)
        self.assertTrue(result['json_conversion_successful'])
        self.assertEqual(len(result['macros']), 1)

        macro = result['macros'][0]
        self.assertEqual(macro['vba_filename'], 'xlm_macro.txt')
        self.assertIn('Excel 4.0 macro sheet: %s' % sheet_name, macro['code'])
        self.assertIn('Auto_Open', macro['code'])
        self.assertIn('ALERT(', macro['code'])
        self.assertIn('HALT()', macro['code'])
        self.assertIn('DANGEROUS FUNCTIONS: HALT', macro['code'])

        analysis = result['analysis']
        self.assertIn(
            {'type': 'AutoExec', 'keyword': 'Auto_Open',
             'description': 'Runs when the Excel Workbook is opened'},
            analysis
        )
        self.assertIn(
            {'type': 'Suspicious', 'keyword': 'XLM macro',
             'description': 'XLM macro found. It may contain malicious code'},
            analysis
        )
        self.assertIn(
            {'type': 'Suspicious', 'keyword': 'HALT',
             'description': xlm_parser.DANGEROUS_FUNCTIONS['HALT']},
            analysis
        )

    def test_xls_macro_sheet(self):
        """BIFF8 XLS macro sheet is parsed and reported like VBA macros."""
        self.assert_xl4_report('excel4_sample_macro.xls', 'Macro')

    def test_xlt_macro_sheet(self):
        """BIFF8 XLT template macro sheet is parsed."""
        self.assert_xl4_report('excel4_sample_macro.xlt', 'Macro')

    def test_xlsm_macro_sheet(self):
        """OOXML XLSM macro sheet XML is parsed."""
        self.assert_xl4_report('excel4_sample_macro.xlsm', 'Macro1')

    def test_xltm_macro_sheet(self):
        """OOXML XLTM macro sheet XML is parsed."""
        self.assert_xl4_report('excel4_sample_macro.xltm', 'Macro1')

    def test_xlsb_macro_sheet(self):
        """XLSB binary macro sheet formulas are parsed."""
        self.assert_xl4_report('excel4_sample_macro.xlsb', 'Macro1')

    def test_dangerous_function_annotations(self):
        """Dangerous XL4 functions produce report-compatible annotations."""
        formula = 'EXEC("cmd.exe /c calc")&CALL("kernel32","WinExec","JC")'
        results = xlm_parser.annotate_formula(formula)
        self.assertEqual(
            [result[:2] for result in results],
            [('Suspicious', 'EXEC'), ('Suspicious', 'CALL')]
        )
        self.assertIn('May run an executable file',
                      results[0][2])
        self.assertIn('DLL', results[1][2])

        sample = tempfile.NamedTemporaryFile(
            mode='w', suffix='.slk', delete=False)
        try:
            sample.write(
                'ID;PWXL;N;E\n'
                'O;L;E;D;V0;K47\n'
                'NN;NAuto_Open;ER1C1\n'
                'C;Y1;X1;EEXEC("cmd.exe /c calc")\n'
                'C;Y2;X1;ECALL("kernel32","WinExec","JC")\n'
            )
            sample.close()
            parser = olevba.VBA_Parser_CLI(sample.name)
            try:
                result = parser.process_file_json()
            finally:
                parser.close()
            annotations = set(
                (entry['type'], entry['keyword'])
                for entry in result['analysis']
            )
            self.assertIn(('Suspicious', 'EXEC'), annotations)
            self.assertIn(('Suspicious', 'CALL'), annotations)
        finally:
            os.unlink(sample.name)


if __name__ == '__main__':
    unittest.main()
