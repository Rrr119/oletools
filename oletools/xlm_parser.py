"""Parser for Excel 4.0 (XLM/XL4) macro sheets.

The parser supports the formats that can contain XLM macro sheets:

* BIFF5/BIFF8 workbooks in OLE files (XLS/XLT)
* OOXML macro sheets (XLSM/XLTM)
* XLSB macro sheets
* SYLK/SLK files

It intentionally returns plain Python objects and report-compatible tuples so
that it can be used by :mod:`oletools.olevba` without changing its public output
format.
"""

import binascii
import csv
import io
import posixpath
import re
import struct
import zipfile

import olefile

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

from oletools.thirdparty.oledump.plugin_biff import cBIFF, ParseExpression


def _parse_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# Descriptions are kept in the same style as olevba's existing suspicious
# keyword descriptions.
DANGEROUS_FUNCTIONS = {
    'EXEC': 'May run an executable file or a system command using Excel 4 Macros (XLM/XLF)',
    'CALL': 'May call a DLL using Excel 4 Macros (XLM/XLF)',
    'REGISTER': 'May call a DLL using Excel 4 Macros (XLM/XLF)',
    'REGISTER.ID': 'May call a DLL using Excel 4 Macros (XLM/XLF)',
    'FOPEN': 'May open a file using Excel 4 Macros (XLM/XLF)',
    'FWRITE': 'May write to a file using Excel 4 Macros (XLM/XLF)',
    'FWRITELN': 'May write to a file using Excel 4 Macros (XLM/XLF)',
    'FILE.DELETE': 'May delete a file using Excel 4 Macros (XLM/XLF)',
    'SAVE.AS': 'May save a file to a user-controlled location using Excel 4 Macros (XLM/XLF)',
    'SAVE.COPY.AS': 'May save a file to a user-controlled location using Excel 4 Macros (XLM/XLF)',
    'OPEN': 'May open a file using Excel 4 Macros (XLM/XLF)',
    'OPEN.TEXT': 'May open a text file using Excel 4 Macros (XLM/XLF)',
    'OPEN.DIALOG': 'May open a file dialog using Excel 4 Macros (XLM/XLF)',
    'RUN': 'May run another macro or command using Excel 4 Macros (XLM/XLF)',
    'SEND.KEYS': 'May simulate keyboard input using Excel 4 Macros (XLM/XLF)',
    'ON.KEY': 'May install a keyboard-triggered macro using Excel 4 Macros (XLM/XLF)',
    'ON.TIME': 'May schedule macro execution using Excel 4 Macros (XLM/XLF)',
    'CREATE.OBJECT': 'May create an OLE object using Excel 4 Macros (XLM/XLF)',
    'DIALOG.BOX': 'May display a dialog box using Excel 4 Macros (XLM/XLF)',
    'INITIATE': 'May initiate a DDE conversation using Excel 4 Macros (XLM/XLF)',
    'REQUEST': 'May request data through DDE using Excel 4 Macros (XLM/XLF)',
    'POKE': 'May send data through DDE using Excel 4 Macros (XLM/XLF)',
    'EXECUTE': 'May execute a DDE command using Excel 4 Macros (XLM/XLF)',
    'TERMINATE': 'May terminate a DDE conversation using Excel 4 Macros (XLM/XLF)',
    'EVALUATE': 'May evaluate a formula dynamically using Excel 4 Macros (XLM/XLF)',
    'FORMULA.FILL': 'May modify formulas at runtime using Excel 4 Macros (XLM/XLF)',
    'HALT': 'May terminate macro execution using Excel 4 Macros (XLM/XLF)',
}

# Keep an alias with the terminology used in the rest of oletools/olevba.
SUSPICIOUS_FUNCTIONS = DANGEROUS_FUNCTIONS


# Function IDs from MS-XLS / MS-XLSB. Only the IDs relevant for annotations are
# needed here; formula rendering is delegated to plugin_biff's full function
# table.
DANGEROUS_FUNCTION_IDS = {
    0x0036: 'HALT',
    0x006E: 'EXEC',
    0x0084: 'FOPEN',
    0x0089: 'FWRITELN',
    0x008A: 'FWRITE',
    0x0095: 'REGISTER',
    0x0096: 'CALL',
    0x00A1: 'DIALOG.BOX',
    0x00AF: 'INITIATE',
    0x00B0: 'REQUEST',
    0x00B1: 'POKE',
    0x00B2: 'EXECUTE',
    0x00B3: 'TERMINATE',
    0x00EC: 'CREATE.OBJECT',
    0x0101: 'EVALUATE',
    0x010B: 'REGISTER.ID',
    0x8001: 'OPEN',
    0x8005: 'SAVE.AS',
    0x8006: 'FILE.DELETE',
    0x8011: 'RUN',
    0x8061: 'FORMULA.FILL',
    0x8083: 'SEND.KEYS',
    0x8094: 'ON.TIME',
    0x80A8: 'ON.KEY',
    0x81C8: 'SAVE.COPY.AS',
    0x81B9: 'OPEN.TEXT',
    0x0163: 'OPEN.DIALOG',
}


_FUNCTION_RE = re.compile(r'(?<![A-Z0-9_.])([A-Z][A-Z0-9.]*)\s*\(', re.IGNORECASE)
_CELL_RE = re.compile(r'^([A-Z]+)([0-9]+)$')
_XLSB_RECORD_ROW_HDR = 0x0000
_XLSB_RECORD_FMLA_STRING = 0x0008
_XLSB_RECORD_FMLA_NUM = 0x0009
_XLSB_RECORD_FMLA_BOOL = 0x000A
_XLSB_RECORD_FMLA_ERROR = 0x000B
_XLSB_RECORD_BUNDLE_SH = 0x009C
_XLSB_FORMULA_RECORDS = {
    _XLSB_RECORD_FMLA_STRING,
    _XLSB_RECORD_FMLA_NUM,
    _XLSB_RECORD_FMLA_BOOL,
    _XLSB_RECORD_FMLA_ERROR,
}


def _local_name(tag):
    """Return an XML tag/attribute name without its namespace."""
    return tag.rsplit('}', 1)[-1]


def _xml_root(data):
    """Parse XML data, allowing XML declarations with any encoding."""
    return ET.fromstring(data)


def _column_name(column_index):
    """Convert a zero-based column index to Excel letters."""
    if column_index < 0:
        return '?'
    result = ''
    column_index += 1
    while column_index:
        column_index, remainder = divmod(column_index - 1, 26)
        result = chr(ord('A') + remainder) + result
    return result


def _clean_sheet_name(name):
    """Remove NUL padding added by old BIFF dumpers."""
    return name.replace('\x00', '').strip()


def _decode_bytes(data, encodings=('utf-8', 'cp1252', 'latin1')):
    for encoding in encodings:
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode('latin1', errors='replace')


def _read_utf16_leb128(stream, offset):
    """Read a BIFF12/XLSB UTF-16 string prefixed by a 32-bit character count."""
    if offset + 4 > len(stream):
        return '', offset
    count = struct.unpack_from('<I', stream, offset)[0]
    offset += 4
    end = offset + count * 2
    if end > len(stream):
        end = len(stream)
    return stream[offset:end].decode('utf-16le', errors='replace'), end


def _find_dangerous_functions(formula, function_ids=None):
    """Return ordered names of dangerous XL4 functions in a formula."""
    found = []
    seen = set()
    for match in _FUNCTION_RE.finditer(formula or ''):
        name = match.group(1).upper()
        if name in DANGEROUS_FUNCTIONS and name not in seen:
            found.append(name)
            seen.add(name)
    for function_id in sorted(function_ids or ()):
        name = DANGEROUS_FUNCTION_IDS.get(function_id)
        if name and name not in seen:
            found.append(name)
            seen.add(name)
    return found


def annotate_formula(formula, function_ids=None):
    """
    Return report-compatible annotations for dangerous XL4 functions.

    :param str formula: Excel 4.0 formula text
    :param iterable function_ids: optional numeric function IDs from XLSB
    :return: list of ``('Suspicious', function, description)`` tuples
    """
    return [
        ('Suspicious', name, DANGEROUS_FUNCTIONS[name])
        for name in _find_dangerous_functions(formula, function_ids)
    ]


class XL4Macro(object):
    """A single formula found in an Excel 4.0 macro sheet."""

    def __init__(self, sheet, cell, formula, value=None, function_ids=None):
        self.sheet = _clean_sheet_name(sheet or '')
        self.cell = cell or ''
        self.formula = formula or ''
        self.value = value
        self.function_ids = set(function_ids or ())

    @property
    def location(self):
        if self.sheet:
            return '%s!%s' % (self.sheet, self.cell)
        return self.cell

    @property
    def dangerous_functions(self):
        return _find_dangerous_functions(self.formula, self.function_ids)


class XL4Parser(object):
    """Extract formulas and defined names from XL4 macro sheets."""

    def __init__(self, filename=None, data=None):
        if filename is None and data is None:
            raise ValueError('filename or data is required')
        self.filename = filename
        self.data = data
        self.macros = []
        self.sheet_names = []
        self.defined_names = []
        self.contains_xl4 = False
        self.source = filename

    def _raw_data(self):
        if self.data is not None:
            if isinstance(self.data, str):
                return self.data.encode('latin1')
            return self.data
        with open(self.filename, 'rb') as file_handle:
            return file_handle.read()

    def parse(self):
        """Parse the input and return True if an XL4 macro sheet was found."""
        self.macros = []
        self.sheet_names = []
        self.defined_names = []
        self.contains_xl4 = False
        raw = self._raw_data()

        if raw.startswith(b'ID'):
            self._parse_slk(raw)
        elif olefile.isOleFile(io.BytesIO(raw)):
            self._parse_ole(raw)
        elif zipfile.is_zipfile(io.BytesIO(raw)):
            self._parse_zip(raw)
        else:
            return False

        self.contains_xl4 = bool(self.sheet_names or self.macros)
        return self.contains_xl4

    def get_analysis(self):
        """Return unique report-compatible suspicious function annotations."""
        results = []
        seen = set()
        for macro in self.macros:
            for result in annotate_formula(macro.formula, macro.function_ids):
                key = (result[0], result[1])
                if key not in seen:
                    results.append(result)
                    seen.add(key)
        return results

    def format_lines(self):
        """Return human-readable macro lines without leading quote markers."""
        lines = []
        source = self.filename or 'in-memory data'
        lines.append('Formulas and XLM/Excel 4 macros extracted from %s:' % source)
        if not self.sheet_names and self.macros:
            self.sheet_names = sorted(set(macro.sheet for macro in self.macros if macro.sheet))
        for sheet_name in self.sheet_names:
            lines.append('Excel 4.0 macro sheet: %s' % sheet_name)
        for name in self.defined_names:
            lines.append('Named cell: %s' % name)
        if not self.macros:
            lines.append('(macro sheet contains no formulas)')
        for macro in self.macros:
            line = '%s = %s' % (macro.location, macro.formula)
            if macro.value not in (None, ''):
                line += ' ; value=%s' % macro.value
            dangerous = macro.dangerous_functions
            if dangerous:
                line += ' ; DANGEROUS FUNCTIONS: %s' % ', '.join(dangerous)
            lines.append(line)
        return lines

    def format_code(self):
        """Return the extracted macros in olevba's comment-style code format."""
        return '\n'.join("' " + line for line in self.format_lines())

    def _parse_slk(self, raw):
        text = _decode_bytes(raw)
        macro_sheet = False
        current_cell = None
        current_column = 1
        for line in text.splitlines():
            if line.startswith('O') and 'E' in line.split(';'):
                macro_sheet = True
            elif line.startswith('NN') and macro_sheet:
                parts = line.split(';')
                if len(parts) > 1 and parts[1].startswith('N'):
                    name = parts[1][1:]
                    if name:
                        self.defined_names.append(name)
            elif line.startswith('C') and macro_sheet:
                parts = line.split(';')
                cell = None
                column = None
                row = None
                formula = None
                for part in parts[1:]:
                    if part.startswith('X'):
                        column = _parse_int(part[1:])
                    elif part.startswith('Y'):
                        row = _parse_int(part[1:])
                    elif part.startswith('E'):
                        formula = part[1:]
                if column is not None and row is not None:
                    cell = '%s%d' % (_column_name(column - 1), row)
                    current_column = column
                elif row is not None:
                    cell = '%s%d' % (_column_name(current_column - 1), row)
                if formula is not None:
                    self.macros.append(XL4Macro('Macro', cell or current_cell, formula))
                    current_cell = cell
        if macro_sheet:
            self.sheet_names.append('Macro')

    def _parse_ole(self, raw):
        ole = olefile.OleFileIO(io.BytesIO(raw))
        try:
            stream_name = None
            for candidate in ('Workbook', 'Book'):
                if ole.exists(candidate):
                    stream_name = candidate
                    break
            if stream_name is None:
                return
            stream_data = ole.openstream(stream_name).read()
        finally:
            ole.close()

        biff = cBIFF(name=[stream_name], stream=stream_data, options='-o BOUNDSHEET')
        boundsheets = [str(line) for line in biff.Analyze()]
        macro_sheet_names = []
        for line in boundsheets:
            if 'Excel 4.0 macro sheet' not in line:
                continue
            sheet_name = line.rsplit(' - ', 1)[-1]
            sheet_name = _clean_sheet_name(sheet_name)
            if sheet_name:
                macro_sheet_names.append(sheet_name)
        if not macro_sheet_names:
            return

        self.sheet_names.extend(macro_sheet_names)

        biff = cBIFF(name=[stream_name], stream=stream_data, options='-o LABEL -r LN')
        for line in biff.Analyze():
            match = re.search(r'built-in-name\s+\d+\s+(\S+)', str(line))
            if match:
                name = match.group(1)
                if name not in self.defined_names:
                    self.defined_names.append(name)

        biff = cBIFF(name=[stream_name], stream=stream_data, options='-c -r LN')
        csv_lines = [str(line) for line in biff.Analyze()]
        if not csv_lines:
            return
        reader = csv.reader(io.StringIO('\n'.join(csv_lines)))
        rows = list(reader)
        if not rows:
            return
        # plugin_biff outputs a header row followed by one row per formula.
        for row in rows[1:]:
            if len(row) < 3:
                continue
            sheet, cell, formula = row[0], row[1], row[2]
            sheet = _clean_sheet_name(sheet)
            if sheet not in macro_sheet_names:
                continue
            value = row[3] if len(row) > 3 else None
            self.macros.append(XL4Macro(sheet, cell, formula, value))

    def _parse_zip(self, raw):
        archive = zipfile.ZipFile(io.BytesIO(raw))
        try:
            names = set(archive.namelist())
            workbook_path = self._find_workbook_path(archive, names)
            if workbook_path is None:
                return
            rels_path = posixpath.join(
                posixpath.dirname(workbook_path),
                '_rels',
                posixpath.basename(workbook_path) + '.rels'
            )
            sheet_names_by_rid = self._read_workbook_sheet_names(
                archive, workbook_path, names)
            macro_targets = self._find_macro_targets(
                archive, rels_path, workbook_path, names)
            if not macro_targets:
                macro_targets = [
                    (name, None) for name in sorted(names)
                    if '/macrosheets/' in name and
                    (name.endswith('.xml') or name.endswith('.bin')) and
                    '/_rels/' not in name and 'binaryIndex' not in name
                ]
            if not macro_targets:
                return

            self.defined_names.extend(
                self._read_workbook_defined_names(
                    archive, workbook_path, names))

            for target, relationship_id in macro_targets:
                if target not in names:
                    continue
                sheet_name = sheet_names_by_rid.get(
                    relationship_id,
                    posixpath.splitext(posixpath.basename(target))[0]
                )
                if sheet_name not in self.sheet_names:
                    self.sheet_names.append(sheet_name)
                data = archive.read(target)
                if target.endswith('.xml'):
                    self._parse_macrosheet_xml(data, sheet_name)
                else:
                    self._parse_macrosheet_bin(data, sheet_name)
        finally:
            archive.close()

    def _find_workbook_path(self, archive, names):
        if '_rels/.rels' in names:
            try:
                root = _xml_root(archive.read('_rels/.rels'))
                for relationship in root:
                    if not isinstance(relationship.tag, str):
                        continue
                    rel_type = relationship.attrib.get('Type', '')
                    if rel_type.endswith('/officeDocument'):
                        target = relationship.attrib.get('Target', '').lstrip('/')
                        if target in names:
                            return target
            except Exception:
                pass
        for candidate in ('xl/workbook.xml', 'xl/workbook.bin'):
            if candidate in names:
                return candidate
        return None

    def _read_workbook_sheet_names(self, archive, workbook_path, names):
        sheet_names = {}
        try:
            data = archive.read(workbook_path)
        except KeyError:
            return sheet_names
        if workbook_path.endswith('.xml'):
            try:
                root = _xml_root(data)
                for element in root.iter():
                    if _local_name(element.tag) != 'sheet':
                        continue
                    relationship_id = None
                    for key, value in element.attrib.items():
                        if _local_name(key) == 'id':
                            relationship_id = value
                            break
                    sheet_name = element.attrib.get('name')
                    if relationship_id and sheet_name:
                        sheet_names[relationship_id] = sheet_name
            except Exception:
                pass
        else:
            for record_type, payload in self._iter_xlsb_records(data):
                if record_type != _XLSB_RECORD_BUNDLE_SH:
                    continue
                if len(payload) < 12:
                    continue
                relationship_id, offset = _read_utf16_leb128(payload, 8)
                sheet_name, _ = _read_utf16_leb128(payload, offset)
                if relationship_id and sheet_name:
                    sheet_names[relationship_id] = sheet_name
        return sheet_names

    def _find_macro_targets(self, archive, rels_path, workbook_path, names):
        targets = []
        if rels_path not in names:
            return targets
        try:
            root = _xml_root(archive.read(rels_path))
        except Exception:
            return targets
        workbook_dir = posixpath.dirname(workbook_path)
        for relationship in root:
            if not isinstance(relationship.tag, str):
                continue
            rel_type = relationship.attrib.get('Type', '')
            if not rel_type.endswith('/xlMacrosheet'):
                continue
            relationship_id = relationship.attrib.get('Id')
            target = relationship.attrib.get('Target', '')
            if target.startswith('/'):
                target = target.lstrip('/')
            else:
                target = posixpath.normpath(posixpath.join(workbook_dir, target))
            targets.append((target, relationship_id))
        return targets

    def _read_workbook_defined_names(self, archive, workbook_path, names):
        defined_names = []
        try:
            data = archive.read(workbook_path)
        except KeyError:
            return defined_names
        if workbook_path.endswith('.xml'):
            try:
                root = _xml_root(data)
                for element in root.iter():
                    if _local_name(element.tag) != 'definedName':
                        continue
                    name = element.attrib.get('name', '')
                    if not name:
                        continue
                    short_name = name
                    if short_name.startswith('_xlnm.'):
                        short_name = short_name[6:]
                    if short_name not in defined_names:
                        defined_names.append(short_name)
            except Exception:
                pass
        else:
            # BrtName contains several variable-length fields and differs
            # between Excel versions. For the report, extracting the built-in
            # XL4 auto-exec names from the UTF-16 strings is sufficient.
            for name in ('Auto_Open', 'Auto_Close'):
                if name.encode('utf-16le') in data and name not in defined_names:
                    defined_names.append(name)
        return defined_names

    def _parse_macrosheet_xml(self, data, sheet_name):
        try:
            root = _xml_root(data)
        except Exception:
            return
        for cell in root.iter():
            if _local_name(cell.tag) != 'c':
                continue
            formula = None
            value = None
            for child in cell:
                child_name = _local_name(child.tag)
                if child_name == 'f':
                    formula = child.text or ''
                elif child_name == 'v':
                    value = child.text
            if formula:
                self.macros.append(
                    XL4Macro(sheet_name, cell.attrib.get('r'), formula, value))

    def _parse_macrosheet_bin(self, data, sheet_name):
        current_row = 0
        for record_type, payload in self._iter_xlsb_records(data):
            if record_type == _XLSB_RECORD_ROW_HDR and len(payload) >= 4:
                current_row = struct.unpack_from('<I', payload, 0)[0]
                continue
            if record_type not in _XLSB_FORMULA_RECORDS or len(payload) < 8:
                continue
            column = struct.unpack_from('<I', payload, 0)[0]
            cell = '%s%d' % (_column_name(column), current_row + 1)
            formula_start, formula_length = self._find_xlsb_formula(payload)
            if formula_start is None:
                continue
            formula_data = payload[formula_start:formula_start + formula_length]
            function_ids = self._find_xlsb_function_ids(formula_data)
            formula = self._decode_xlsb_formula(formula_data, [sheet_name])
            self.macros.append(
                XL4Macro(sheet_name, cell, formula, function_ids=function_ids))

    @staticmethod
    def _iter_xlsb_records(data):
        offset = 0
        data_len = len(data)
        while offset < data_len:
            record_type = data[offset]
            offset += 1
            if record_type & 0x80:
                if offset >= data_len:
                    return
                record_type = ((record_type & 0x7F) |
                               ((data[offset] & 0x7F) << 7))
                offset += 1
            record_size = 0
            shift = 0
            while offset < data_len:
                value = data[offset]
                offset += 1
                record_size |= (value & 0x7F) << shift
                shift += 7
                if not value & 0x80:
                    break
            end = offset + record_size
            if end > data_len:
                return
            yield record_type, data[offset:end]
            offset = end

    @staticmethod
    def _find_xlsb_formula(payload):
        """Locate the CellParsedFormula inside an XLSB formula cell."""
        candidates = []
        for offset in range(9, len(payload) - 4):
            formula_length = struct.unpack_from('<I', payload, offset)[0]
            start = offset + 4
            if formula_length <= 0 or start + formula_length > len(payload):
                continue
            trailing = len(payload) - start - formula_length
            first_token = payload[start]
            if trailing <= 4 and first_token not in (0x00,):
                candidates.append((trailing, offset, formula_length))
        if not candidates:
            return None, None
        candidates.sort()
        _, offset, formula_length = candidates[0]
        return offset + 4, formula_length

    @staticmethod
    def _find_xlsb_function_ids(formula_data):
        function_ids = []
        offset = 0
        while offset < len(formula_data):
            token = formula_data[offset]
            if token in (0x21, 0x41, 0x61) and offset + 3 <= len(formula_data):
                function_ids.append(struct.unpack_from('<H', formula_data, offset + 1)[0])
                offset += 3
            elif token in (0x22, 0x42, 0x62) and offset + 4 <= len(formula_data):
                function_ids.append(struct.unpack_from('<H', formula_data, offset + 2)[0])
                offset += 4
            elif token == 0x17 and offset + 3 <= len(formula_data):
                count = struct.unpack_from('<H', formula_data, offset + 1)[0]
                offset += 3 + count * 2
            else:
                # Unknown tokens are skipped one byte at a time. This is only
                # used for annotations; formula rendering has its own parser.
                offset += 1
        return function_ids

    @staticmethod
    def _decode_xlsb_formula(formula_data, sheet_names):
        converted = XL4Parser._xlsb_formula_to_biff8(formula_data)
        try:
            _, stack = ParseExpression(converted, [], sheet_names or [''], 'LN')
            if stack:
                formula = stack[-1]
                if formula and '*' not in formula:
                    return formula
        except Exception:
            pass
        return 'XLSB_FORMULA(0x%s)' % binascii.hexlify(
            formula_data).decode('ascii')

    @staticmethod
    def _xlsb_formula_to_biff8(formula_data):
        """Convert the XLSB-specific UTF-16 PtgStr token to BIFF8 form."""
        output = bytearray()
        offset = 0
        while offset < len(formula_data):
            token = formula_data[offset]
            if token == 0x17 and offset + 3 <= len(formula_data):
                count = struct.unpack_from('<H', formula_data, offset + 1)[0]
                start = offset + 3
                end = start + count * 2
                if end <= len(formula_data):
                    text = formula_data[start:end].decode(
                        'utf-16le', errors='replace')
                    try:
                        encoded = text.encode('cp1252')
                    except UnicodeEncodeError:
                        encoded = text.encode('utf-8')
                    output.extend((0x17, min(len(encoded), 255), 0))
                    output.extend(encoded)
                    offset = end
                    continue
            output.append(token)
            offset += 1
        return bytes(output)


# Compatibility aliases for callers using the alternative XLM naming.
XLM_Parser = XL4Parser


def parse_xl4(filename=None, data=None):
    """Parse an XL4 source and return the populated :class:`XL4Parser`."""
    parser = XL4Parser(filename=filename, data=data)
    parser.parse()
    return parser
