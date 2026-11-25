"""VBA obfuscation detection, restoration and dangerous API annotation.

This module is intentionally standalone: it only uses the Python standard
library.  When available, olevba's pyparsing grammar is used as an additional
decoder for complex ``Chr``/concatenation expressions.

The public result objects are plain strings/tuples as well as attribute and
mapping compatible objects.  This makes them easy to use from existing
``olevba`` report code and from tests written in either functional or
object-oriented style.
"""

from __future__ import print_function

import base64
import binascii
import re


__all__ = [
    'VBA_Deobfuscator', 'DeobfuscationResult', 'DecodedString',
    'Annotation', 'DangerousAPIFinding', 'ObfuscationFinding',
    'DANGEROUS_APIS', 'DANGEROUS_API_INFO', 'API_CATEGORY', 'API_SEVERITY',
    'OBFUSCATION_TECHNIQUES',
    'analyze_vba', 'analyse_vba', 'deobfuscate_vba', 'deobfuscate',
    'restore_vba', 'deobfuscate_to_dict',
    'detect_obfuscation', 'detect_vba_obfuscation',
    'annotate_dangerous_apis', 'detect_dangerous_apis',
    'deobfuscate_expression',
    'VBADeobfuscator', 'VbaDeobfuscator', 'VBAObfuscationDetector',
    'VBAObfuscationAnalyzer', 'VBAObfuscationEngine',
    'VBADeobfuscationEngine', 'Deobfuscator', 'DangerousAPIDetector',
    'DANGEROUS_API_KEYWORDS', 'DANGEROUS_FUNCTIONS', 'SUSPICIOUS_APIS',
]


SEVERITY_CRITICAL = 'critical'
SEVERITY_HIGH = 'high'
SEVERITY_MEDIUM = 'medium'
SEVERITY_LOW = 'low'


class APIDescription(str):
    """Description string that also carries category/severity metadata."""

    def __new__(cls, description, name=None, category=None, severity=None):
        obj = str.__new__(cls, description)
        obj.name = name
        obj.api = name
        obj.category = category
        obj.severity = severity
        obj.description = description
        return obj

    def __getitem__(self, key):
        if isinstance(key, str):
            if key in ('description', 'desc'):
                return str(self)
            if key in ('name', 'api', 'keyword'):
                return self.name
            if key == 'category':
                return self.category
            if key == 'severity':
                return self.severity
            return getattr(self, key)
        return str.__getitem__(self, key)

    def get(self, key, default=None):
        try:
            return self[key]
        except (AttributeError, KeyError, TypeError):
            return default

    def to_dict(self):
        return {
            'name': self.name,
            'api': self.name,
            'description': str(self),
            'category': self.category,
            'severity': self.severity,
        }


# Descriptions are strings so that DANGEROUS_APIS[name] can be used directly in
# the same way as xlm_parser.DANGEROUS_FUNCTIONS.  Structured category and
# severity are available in API_CATEGORY/API_SEVERITY and on findings.
DANGEROUS_APIS = {}
API_CATEGORY = {}
API_SEVERITY = {}


def _api(name, category, severity, description):
    DANGEROUS_APIS[name] = APIDescription(
        description, name=name, category=category, severity=severity)
    API_CATEGORY[name] = category
    API_SEVERITY[name] = severity


_api('Shell', 'execution', SEVERITY_HIGH,
     'May run an executable file or a system command')
_api('WScript.Shell', 'execution', SEVERITY_HIGH,
     'May run commands, write registry values or create COM objects')
_api('WScript.Shell.Run', 'execution', SEVERITY_CRITICAL,
     'May run an executable file or a system command')
_api('Shell.Application', 'execution', SEVERITY_HIGH,
     'May launch applications or perform shell operations')
_api('ShellExecute', 'execution', SEVERITY_CRITICAL,
     'May run an executable file or a system command')
_api('ShellExecuteA', 'execution', SEVERITY_CRITICAL,
     'May run an executable file or a system command')
_api('ShellExecuteW', 'execution', SEVERITY_CRITICAL,
     'May run an executable file or a system command')
_api('CreateProcessA', 'execution', SEVERITY_CRITICAL,
     'May create a new process')
_api('CreateProcessW', 'execution', SEVERITY_CRITICAL,
     'May create a new process')
_api('WinExec', 'execution', SEVERITY_CRITICAL,
     'May run an executable file')
_api('CallByName', 'dynamic_invocation', SEVERITY_HIGH,
     'May invoke an object member by name, commonly used to hide API calls')
_api('Application.Run', 'dynamic_invocation', SEVERITY_HIGH,
     'May dynamically run a macro or command by name')
_api('MacScript', 'execution', SEVERITY_HIGH,
     'May run an executable file or system command on macOS')
_api('AppleScript', 'execution', SEVERITY_HIGH,
     'May run AppleScript commands on macOS')
_api('ExecuteExcel4Macro', 'execution', SEVERITY_HIGH,
     'May execute an Excel 4/XLM macro from VBA')
_api('powershell', 'execution', SEVERITY_HIGH,
     'May run PowerShell commands')
_api('powershell.exe', 'execution', SEVERITY_CRITICAL,
     'May launch PowerShell to execute encoded or downloaded commands')
_api('pwsh', 'execution', SEVERITY_HIGH, 'May run PowerShell commands')
_api('cmd.exe', 'execution', SEVERITY_CRITICAL,
     'May launch the Windows command interpreter')
_api('cmd.exe /c', 'execution', SEVERITY_CRITICAL,
     'May run a command batch and terminate, commonly used by downloaders')
_api('cmd /c', 'execution', SEVERITY_CRITICAL,
     'May run a command batch, commonly used by downloaders')
_api('Start-Process', 'execution', SEVERITY_HIGH,
     'May start a process from PowerShell')
_api('Invoke-Expression', 'execution', SEVERITY_CRITICAL,
     'May evaluate and execute a dynamic PowerShell expression')
_api('New-Object', 'object_creation', SEVERITY_MEDIUM,
     'May create a .NET/COM object from PowerShell')
_api('mshta.exe', 'execution', SEVERITY_HIGH,
     'May execute HTA/script payloads or bypass application whitelisting')
_api('mshta', 'execution', SEVERITY_HIGH,
     'May execute HTA/script payloads or bypass application whitelisting')
_api('regsvr32.exe', 'execution', SEVERITY_HIGH,
     'May execute remote scriptlets or bypass application whitelisting')
_api('regsvr32', 'execution', SEVERITY_HIGH,
     'May execute remote scriptlets or bypass application whitelisting')
_api('rundll32.exe', 'execution', SEVERITY_HIGH,
     'May execute DLL exports or scriptlets as a LOLBin')
_api('rundll32', 'execution', SEVERITY_HIGH,
     'May execute DLL exports or scriptlets as a LOLBin')
_api('certutil.exe', 'execution', SEVERITY_MEDIUM,
     'May decode or download payloads using CertUtil')
_api('certutil', 'execution', SEVERITY_MEDIUM,
     'May decode or download payloads using CertUtil')
_api('bitsadmin.exe', 'network', SEVERITY_MEDIUM,
     'May download payloads using BITSAdmin')
_api('bitsadmin', 'network', SEVERITY_MEDIUM,
     'May download payloads using BITSAdmin')
_api('wmic.exe', 'execution', SEVERITY_MEDIUM,
     'May execute commands or enumerate systems using WMI')
_api('wmic', 'execution', SEVERITY_MEDIUM,
     'May execute commands or enumerate systems using WMI')
_api('cscript.exe', 'execution', SEVERITY_MEDIUM,
     'May execute JScript/VBScript payloads')
_api('wscript.exe', 'execution', SEVERITY_MEDIUM,
     'May execute JScript/VBScript payloads')
_api('FromBase64String', 'encoding', SEVERITY_HIGH,
     'May decode a Base64 payload before execution')

_api('CreateObject', 'object_creation', SEVERITY_MEDIUM,
     'May create an OLE/COM object, often used to start shells or network components')
_api('GetObject', 'object_creation', SEVERITY_MEDIUM,
     'May obtain a running OLE/COM object')
_api('Scripting.FileSystemObject', 'file_system', SEVERITY_MEDIUM,
     'May create, read, copy or delete files')
_api('FileSystemObject', 'file_system', SEVERITY_MEDIUM,
     'May create, read, copy or delete files')
_api('ADODB.Stream', 'file_system', SEVERITY_HIGH,
     'May decode and write a payload to disk')
_api('CreateTextFile', 'file_system', SEVERITY_HIGH,
     'May create a text or payload file')
_api('OpenTextFile', 'file_system', SEVERITY_MEDIUM,
     'May open a file for reading or writing')
_api('SaveToFile', 'file_system', SEVERITY_HIGH,
     'May write an in-memory stream to disk')
_api('WriteText', 'file_system', SEVERITY_HIGH, 'May write data to a file')
_api('FileCopy', 'file_system', SEVERITY_MEDIUM, 'May copy a file')
_api('CopyFile', 'file_system', SEVERITY_MEDIUM, 'May copy a file')
_api('CopyHere', 'file_system', SEVERITY_MEDIUM, 'May copy or extract files')
_api('MoveFile', 'file_system', SEVERITY_MEDIUM, 'May move a file')
_api('MoveHere', 'file_system', SEVERITY_MEDIUM, 'May move or extract files')
_api('Kill', 'file_system', SEVERITY_MEDIUM, 'May delete a file')
_api('MkDir', 'file_system', SEVERITY_LOW, 'May create a directory')
_api('RmDir', 'file_system', SEVERITY_LOW, 'May remove a directory')
_api('Open', 'file_system', SEVERITY_MEDIUM, 'May open a file or device')

_api('URLDownloadToFile', 'network', SEVERITY_CRITICAL,
     'May download a remote file to disk')
_api('URLDownloadToFileA', 'network', SEVERITY_CRITICAL,
     'May download a remote file to disk')
_api('URLDownloadToFileW', 'network', SEVERITY_CRITICAL,
     'May download a remote file to disk')
_api('Msxml2.XMLHTTP', 'network', SEVERITY_HIGH,
     'May send HTTP requests and download payloads')
_api('MSXML2.XMLHTTP', 'network', SEVERITY_HIGH,
     'May send HTTP requests and download payloads')
_api('Microsoft.XMLHTTP', 'network', SEVERITY_HIGH,
     'May send HTTP requests and download payloads')
_api('MSXML2.ServerXMLHTTP', 'network', SEVERITY_HIGH,
     'May send server-side HTTP requests')
_api('WinHttp.WinHttpRequest.5.1', 'network', SEVERITY_HIGH,
     'May send HTTP requests and download payloads')
_api('WinHttpRequest', 'network', SEVERITY_HIGH,
     'May send HTTP requests and download payloads')
_api('Net.WebClient', 'network', SEVERITY_HIGH,
     'May download strings or files from the Internet')
_api('DownloadFile', 'network', SEVERITY_CRITICAL,
     'May download a remote file to disk')
_api('DownloadString', 'network', SEVERITY_HIGH,
     'May download remote text or a second-stage command')
_api('DownloadData', 'network', SEVERITY_HIGH,
     'May download remote binary data')
_api('InternetOpenA', 'network', SEVERITY_MEDIUM, 'May initialize WinINet access')
_api('InternetOpenW', 'network', SEVERITY_MEDIUM, 'May initialize WinINet access')
_api('InternetOpenUrlA', 'network', SEVERITY_HIGH, 'May open a remote URL')
_api('InternetOpenUrlW', 'network', SEVERITY_HIGH, 'May open a remote URL')
_api('HttpOpenRequestA', 'network', SEVERITY_MEDIUM, 'May create an HTTP request')
_api('HttpOpenRequestW', 'network', SEVERITY_MEDIUM, 'May create an HTTP request')
_api('HttpSendRequestA', 'network', SEVERITY_HIGH, 'May send an HTTP request')
_api('HttpSendRequestW', 'network', SEVERITY_HIGH, 'May send an HTTP request')
_api('WinHttpOpen', 'network', SEVERITY_MEDIUM, 'May initialize WinHTTP access')
_api('WinHttpConnect', 'network', SEVERITY_MEDIUM, 'May connect to a remote host')
_api('WinHttpOpenRequest', 'network', SEVERITY_MEDIUM, 'May create an HTTP request')
_api('WinHttpSendRequest', 'network', SEVERITY_HIGH, 'May send an HTTP request')

_api('VirtualAlloc', 'injection', SEVERITY_HIGH,
     'May allocate executable memory, commonly used for shellcode')
_api('VirtualAllocEx', 'injection', SEVERITY_CRITICAL,
     'May allocate memory in another process for injection')
_api('VirtualProtect', 'injection', SEVERITY_HIGH,
     'May change memory permissions to make shellcode executable')
_api('VirtualProtectEx', 'injection', SEVERITY_CRITICAL,
     'May change memory permissions in another process')
_api('WriteProcessMemory', 'injection', SEVERITY_CRITICAL,
     'May write shellcode or a DLL into another process')
_api('ReadProcessMemory', 'injection', SEVERITY_HIGH,
     'May read memory from another process')
_api('CreateRemoteThread', 'injection', SEVERITY_CRITICAL,
     'May execute code in another process')
_api('CreateRemoteThreadEx', 'injection', SEVERITY_CRITICAL,
     'May execute code in another process')
_api('CreateThread', 'injection', SEVERITY_HIGH,
     'May start a thread, sometimes used to run in-memory payloads')
_api('QueueApcThread', 'injection', SEVERITY_CRITICAL,
     'May queue an asynchronous procedure call for process injection')
_api('SetContextThread', 'injection', SEVERITY_CRITICAL,
     'May modify a thread context during process hollowing/injection')
_api('RtlMoveMemory', 'injection', SEVERITY_HIGH,
     'May copy shellcode or assist process injection')
_api('RtlCopyMemory', 'injection', SEVERITY_HIGH,
     'May copy shellcode or assist process injection')
_api('SetWindowsHookExA', 'injection', SEVERITY_HIGH,
     'May install a hook that loads a DLL into other processes')
_api('SetWindowsHookExW', 'injection', SEVERITY_HIGH,
     'May install a hook that loads a DLL into other processes')
_api('LoadLibraryA', 'dynamic_loading', SEVERITY_MEDIUM,
     'May dynamically load a DLL')
_api('LoadLibraryW', 'dynamic_loading', SEVERITY_MEDIUM,
     'May dynamically load a DLL')
_api('GetProcAddress', 'dynamic_loading', SEVERITY_HIGH,
     'May resolve Windows API functions dynamically to hide imports')
_api('LdrLoadDll', 'dynamic_loading', SEVERITY_HIGH,
     'May load a DLL through the native API')
_api('NtAllocateVirtualMemory', 'injection', SEVERITY_HIGH,
     'May allocate memory using the native API')
_api('NtWriteVirtualMemory', 'injection', SEVERITY_CRITICAL,
     'May write to another process using the native API')
_api('NtCreateThreadEx', 'injection', SEVERITY_CRITICAL,
     'May create a remote thread using the native API')

_api('RegOpenKeyExA', 'registry', SEVERITY_MEDIUM, 'May open a registry key')
_api('RegOpenKeyExW', 'registry', SEVERITY_MEDIUM, 'May open a registry key')
_api('RegCreateKeyExA', 'registry', SEVERITY_HIGH, 'May create a registry key')
_api('RegCreateKeyExW', 'registry', SEVERITY_HIGH, 'May create a registry key')
_api('RegSetValueExA', 'registry', SEVERITY_HIGH,
     'May write a registry value, often used for persistence')
_api('RegSetValueExW', 'registry', SEVERITY_HIGH,
     'May write a registry value, often used for persistence')
_api('RegQueryValueExA', 'registry', SEVERITY_MEDIUM, 'May query a registry value')
_api('RegQueryValueExW', 'registry', SEVERITY_MEDIUM, 'May query a registry value')
_api('RegRead', 'registry', SEVERITY_MEDIUM, 'May read a registry value')
_api('RegWrite', 'registry', SEVERITY_HIGH,
     'May write a registry value, often used for persistence')
_api('CurrentVersion\\Run', 'persistence', SEVERITY_HIGH,
     'May use the Windows Run key for persistence')
_api('Schedule.Service', 'persistence', SEVERITY_MEDIUM,
     'May create a scheduled task for persistence')

_api('Environ', 'discovery', SEVERITY_LOW,
     'May read environment variables to discover users or paths')
_api('GetVolumeInformationA', 'evasion', SEVERITY_MEDIUM,
     'May read volume information used by sandbox checks')
_api('GetVolumeInformationW', 'evasion', SEVERITY_MEDIUM,
     'May read volume information used by sandbox checks')
_api('IsDebuggerPresent', 'evasion', SEVERITY_MEDIUM,
     'May detect a debugger')
_api('CheckRemoteDebuggerPresent', 'evasion', SEVERITY_MEDIUM,
     'May detect a debugger')
_api('GetTickCount', 'evasion', SEVERITY_LOW,
     'May measure timing to detect a sandbox')
_api('GetTickCount64', 'evasion', SEVERITY_LOW,
     'May measure timing to detect a sandbox')
_api('Sleep', 'evasion', SEVERITY_LOW,
     'May delay execution to evade dynamic analysis')
_api('CreateToolhelp32Snapshot', 'discovery', SEVERITY_MEDIUM,
     'May enumerate processes')
_api('Process32First', 'discovery', SEVERITY_MEDIUM,
     'May enumerate processes')
_api('Process32Next', 'discovery', SEVERITY_MEDIUM,
     'May enumerate processes')
_api('CryptUnprotectData', 'credential_access', SEVERITY_HIGH,
     'May decrypt saved credentials or browser data')
_api('CredEnumerateA', 'credential_access', SEVERITY_HIGH,
     'May enumerate Windows credentials')
_api('CredEnumerateW', 'credential_access', SEVERITY_HIGH,
     'May enumerate Windows credentials')

_api('AccessVBOM', 'evasion', SEVERITY_HIGH,
     'May change VBA object model access security')
_api('VBAWarnings', 'evasion', SEVERITY_HIGH,
     'May weaken VBA macro warning settings')
_api('ProtectedView', 'evasion', SEVERITY_MEDIUM,
     'May disable or bypass Office Protected View')


DANGEROUS_API_INFO = {
    name: {
        'name': name,
        'description': DANGEROUS_APIS[name],
        'category': API_CATEGORY[name],
        'severity': API_SEVERITY[name],
    }
    for name in DANGEROUS_APIS
}

_API_NAME_TO_CANONICAL = dict(
    (name.lower(), name) for name in DANGEROUS_APIS)
_API_PATTERN = re.compile(
    r'(?<![A-Za-z0-9_.])(?:'
    + '|'.join(sorted((re.escape(name) for name in DANGEROUS_APIS),
                      key=len, reverse=True))
    + r')(?![A-Za-z0-9_])',
    re.IGNORECASE)


OBFUSCATION_TECHNIQUES = {
    'chr_encoding': 'Chr/ChrW character-code concatenation',
    'hex_encoding': 'Hexadecimal encoded string',
    'base64_encoding': 'Base64 encoded string',
    'powershell_encoding': 'PowerShell EncodedCommand (Base64/UTF-16)',
    'strreverse': 'Reversed string',
    'replace_substitution': 'Character substitution with Replace',
    'split_join': 'Split/Join delimiter obfuscation',
    'char_array': 'Numeric character array',
    'numeric_string': 'Delimiter-separated character codes',
    'xor_encoding': 'XOR encoded string or API name',
    'call_by_name': 'Dynamic call by name',
    'dynamic_api_resolution': 'Dynamic DLL/API resolution',
    'line_continuation': 'Split expression using line continuation',
    'identifier_randomization': 'Randomized identifier names',
    'control_character': 'Hidden control character',
    'long_literal': 'Long encoded literal',
}


_VBA_KEYWORDS = {
    'attribute', 'sub', 'function', 'end', 'if', 'then', 'else', 'elseif',
    'for', 'each', 'in', 'to', 'next', 'do', 'loop', 'while', 'wend', 'until',
    'select', 'case', 'dim', 'redim', 'as', 'set', 'let', 'const', 'call',
    'exit', 'return', 'with', 'new', 'not', 'and', 'or', 'xor', 'mod', 'byval',
    'byref', 'optional', 'paramarray', 'public', 'private', 'friend', 'static',
    'global', 'declare', 'ptrSafe', 'lib', 'alias', 'type', 'enum', 'implements',
    'goto', 'resume', 'on', 'error', 'goto', 'me', 'true', 'false', 'nothing',
    'null', 'empty', 'is', 'like', 'step', 'class', 'module', 'property', 'get',
    'let', 'set', 'debug', 'print', 'msgbox', 'inputbox',
}


class Annotation(tuple):
    """A three-part olevba-compatible ``(type, keyword, description)`` tuple."""

    def __new__(cls, result_type, keyword, description, **metadata):
        # Structured findings use names such as DangerousAPI/Obfuscation.  The
        # tuple's first field stays compatible with olevba's existing report
        # vocabulary by mapping those findings to the legacy Suspicious type.
        legacy_type = metadata.pop('legacy_type', None) or result_type
        obj = tuple.__new__(cls, (legacy_type, keyword, description))
        obj.type = result_type
        obj.result_type = result_type
        obj.annotation_type = result_type
        obj.olevba_type = legacy_type
        obj.keyword = keyword
        obj.name = keyword
        obj.api = keyword
        obj.description = description
        for key, value in metadata.items():
            setattr(obj, key, value)
        return obj

    def __getitem__(self, key):
        if isinstance(key, str):
            if key in ('type', 'result_type', 'kind'):
                return self.type
            if key in ('olevba_type', 'report_type', 'legacy_type'):
                return self[0]
            if key in ('keyword', 'name', 'api'):
                return self[1]
            if key in ('description', 'desc', 'detail'):
                return self[2]
            return getattr(self, key)
        return tuple.__getitem__(self, key)

    def get(self, key, default=None):
        try:
            return self[key]
        except (AttributeError, KeyError, IndexError, TypeError):
            return default

    def to_dict(self):
        data = {
            'type': self.type,
            'olevba_type': self[0],
            'keyword': self[1],
            'description': self[2],
        }
        for key in ('technique', 'confidence', 'line', 'evidence', 'category',
                    'severity', 'encoded', 'decoded'):
            if hasattr(self, key):
                data[key] = getattr(self, key)
        return data


class DangerousAPIFinding(Annotation):
    """An annotation with API category, severity and source line."""


class ObfuscationFinding(Annotation):
    """An obfuscation technique annotation."""


class DecodedString(tuple):
    """``(encoded, decoded)`` tuple with decoder metadata."""

    def __new__(cls, encoded, decoded, technique='unknown', line=None,
                confidence=1.0, evidence=None, quote_replacement=True):
        obj = tuple.__new__(cls, (encoded, decoded))
        obj.encoded = encoded
        obj.decoded = decoded
        obj.value = decoded
        obj.text = decoded
        obj.technique = technique
        obj.line = line
        obj.confidence = confidence
        obj.evidence = evidence
        obj.quote_replacement = quote_replacement
        return obj

    def __getitem__(self, key):
        if isinstance(key, str):
            if key in ('encoded', 'source', 'obfuscated'):
                return self[0]
            if key in ('decoded', 'value', 'text', 'plain'):
                return self[1]
            return getattr(self, key)
        return tuple.__getitem__(self, key)

    def get(self, key, default=None):
        try:
            return self[key]
        except (AttributeError, KeyError, IndexError, TypeError):
            return default

    def to_dict(self):
        return {
            'encoded': self.encoded,
            'decoded': self.decoded,
            'technique': self.technique,
            'line': self.line,
            'confidence': self.confidence,
            'evidence': self.evidence,
        }


class DeobfuscationResult(str):
    """Restored VBA source which also exposes structured analysis fields."""

    def __new__(cls, original_code, restored_code, obfuscations=None,
                decoded_strings=None, dangerous_apis=None,
                expanded_code=None):
        obj = str.__new__(cls, restored_code or '')
        obj.original_code = original_code or ''
        obj.original = obj.original_code
        obj.deobfuscated_code = restored_code or ''
        obj.restored_code = restored_code or ''
        obj.revealed_code = restored_code or ''
        obj.code = restored_code or ''
        obj.text = restored_code or ''
        obj.expanded_code = expanded_code or restored_code or ''
        obj.obfuscations = list(obfuscations or [])
        obj.obfuscation_findings = obj.obfuscations
        obj.decoded_strings = list(decoded_strings or [])
        obj.strings = obj.decoded_strings
        obj.dangerous_apis = list(dangerous_apis or [])
        obj.api_findings = obj.dangerous_apis
        obj.annotations = list(obj.obfuscations) + list(obj.dangerous_apis)
        obj.analysis_results = obj.annotations
        obj.techniques = sorted(set(
            finding.technique for finding in obj.obfuscations
            if getattr(finding, 'technique', None)
        ))
        obj.obfuscation_detected = bool(obj.obfuscations or obj.decoded_strings)
        obj.is_obfuscated = obj.obfuscation_detected
        obj.risk_score, obj.risk_level = _risk(obj)
        return obj

    def __getitem__(self, key):
        if isinstance(key, str):
            if key in ('deobfuscated_code', 'restored_code', 'code', 'text',
                       'revealed_code'):
                return str(self)
            if key in ('original_code', 'original'):
                return self.original_code
            if key == 'expanded_code':
                return self.expanded_code
            if key in ('obfuscations', 'obfuscation_findings'):
                return self.obfuscations
            if key in ('decoded_strings', 'strings'):
                return self.decoded_strings
            if key in ('dangerous_apis', 'api_findings'):
                return self.dangerous_apis
            if key == 'annotations':
                return self.annotations
            if key == 'techniques':
                return self.techniques
            if key in ('obfuscation_detected', 'is_obfuscated'):
                return self.obfuscation_detected
            if key == 'risk_score':
                return self.risk_score
            if key in ('risk_level', 'severity'):
                return self.risk_level
            raise KeyError(key)
        return str.__getitem__(self, key)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def detect_obfuscation(self):
        return self.obfuscations

    def annotate_dangerous_apis(self):
        return self.dangerous_apis

    def deobfuscate(self, *args, **kwargs):
        return self

    def to_dict(self):
        return {
            'original_code': self.original_code,
            'deobfuscated_code': str(self),
            'restored_code': self.restored_code,
            'expanded_code': self.expanded_code,
            'obfuscation_detected': self.obfuscation_detected,
            'techniques': self.techniques,
            'risk_score': self.risk_score,
            'risk_level': self.risk_level,
            'obfuscations': [item.to_dict() for item in self.obfuscations],
            'decoded_strings': [item.to_dict() for item in self.decoded_strings],
            'dangerous_apis': [item.to_dict() for item in self.dangerous_apis],
            'annotations': [item.to_dict() for item in self.annotations],
        }


def _risk(result):
    score = 0
    for finding in result.obfuscations:
        score += {'low': 1, 'medium': 3, 'high': 5}.get(
            getattr(finding, 'severity', 'medium'), 2)
    for finding in result.dangerous_apis:
        score += {
            SEVERITY_LOW: 2,
            SEVERITY_MEDIUM: 5,
            SEVERITY_HIGH: 12,
            SEVERITY_CRITICAL: 20,
        }.get(getattr(finding, 'severity', SEVERITY_MEDIUM), 5)
    if score >= 35:
        level = SEVERITY_CRITICAL
    elif score >= 20:
        level = SEVERITY_HIGH
    elif score >= 8:
        level = SEVERITY_MEDIUM
    else:
        level = SEVERITY_LOW
    return score, level


def _decode_bytes(raw):
    if isinstance(raw, str):
        raw = raw.encode('latin-1', errors='replace')
    candidates = []
    if b'\x00' in raw:
        candidates.extend(('utf-16-le', 'utf-16', 'utf-16-be'))
    candidates.extend(('utf-8', 'cp1252', 'latin-1'))
    for encoding in candidates:
        try:
            text = raw.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
        if _is_printable(text):
            return text
    return None


def _is_printable(text, threshold=0.9):
    if not text:
        return False
    if '\x00' in text:
        return False
    printable = 0
    for char in text:
        code = ord(char)
        if char in '\r\n\t':
            printable += 1
        elif (code >= 32 and code != 127 and not 128 <= code <= 159
              and char.isprintable()):
            printable += 1
    return (printable / float(len(text))) >= threshold


_MEANINGFUL_RE = re.compile(
    r'(?i)(?:https?|cmd\.exe|powershell|pwsh|wscript|shell|download|'
    r'urlmon|virtualalloc|createremotethread|writeprocessmemory|\.exe|\.dll|'
    r'\.ps1|\.bat|\.vbs|\.hta|regsvr32|mshta|frombase64|createobject)')


def _is_meaningful(text):
    if not text:
        return False
    if _MEANINGFUL_RE.search(text):
        return True
    letters = sum(char.isalpha() for char in text)
    return letters >= 4 and (
        ' ' in text or letters / max(1, len(text)) > 0.75)


def _line_number(text, offset):
    return text.count('\n', 0, max(0, min(offset, len(text)))) + 1


def _collapse_continuations(code):
    if not code:
        return ''
    code = code.replace('\r\n', '\n').replace('\r', '\n')
    return re.sub(r'[ \t]+_[ \t]*(?=\n)', ' ', code)


def _unquote_vba(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        value = value[1:-1]
    return value.replace('""', '"')


def _quote_vba(value):
    return '"' + value.replace('"', '""') + '"'


def _safe_int(value):
    if value is None:
        raise ValueError('empty integer')
    token = str(value).strip()
    token = re.sub(r'[%&!#@$]+$', '', token)
    token = token.strip()
    if not token:
        raise ValueError('empty integer')
    lower = token.lower()
    if lower.startswith('&h'):
        return int(lower[2:], 16)
    if lower.startswith('&o'):
        return int(lower[2:], 8)
    if token.startswith('&'):
        return int(token[1:], 8)
    return int(token)


def _eval_constant_expression(expression):
    """Evaluate a small subset of VBA constant expressions."""
    if expression is None:
        raise ValueError('empty expression')
    expr = expression.strip()
    if len(expr) >= 2 and expr[0] == '"' and expr[-1] == '"':
        return _unquote_vba(expr)

    expr = re.sub(
        r'(?i)\bAscW?\$?\s*\(\s*("(?:[^"]|"")*")\s*\)',
        lambda match: str(ord(_unquote_vba(match.group(1))[:1] or '\0')),
        expr,
    )
    replacements = {
        r'(?i)\bXor\b': '^',
        r'(?i)\bMod\b': '%',
        r'(?i)\bAnd\b': '&',
        r'(?i)\bOr\b': '|',
        r'(?i)\bNot\b': '~',
    }
    for pattern, replacement in replacements.items():
        expr = re.sub(pattern, replacement, expr)
    expr = expr.replace('\\', '//')

    import ast
    tree = ast.parse(expr, mode='eval')

    def evaluate(node):
        if isinstance(node, ast.Expression):
            return evaluate(node.body)
        if isinstance(node, ast.Constant):
            if isinstance(node.value, (int, float)):
                return node.value
            raise ValueError('unsupported constant')
        if hasattr(ast, 'Num') and isinstance(node, ast.Num):
            return node.n
        if isinstance(node, ast.UnaryOp):
            value = evaluate(node.operand)
            if isinstance(node.op, ast.UAdd):
                return +value
            if isinstance(node.op, ast.USub):
                return -value
            if isinstance(node.op, ast.Invert):
                return ~value
            if isinstance(node.op, ast.Not):
                return not value
        if isinstance(node, ast.BinOp):
            left = evaluate(node.left)
            right = evaluate(node.right)
            operations = {
                ast.Add: lambda a, b: a + b,
                ast.Sub: lambda a, b: a - b,
                ast.Mult: lambda a, b: a * b,
                ast.Div: lambda a, b: a / b,
                ast.FloorDiv: lambda a, b: a // b,
                ast.Mod: lambda a, b: a % b,
                ast.BitXor: lambda a, b: a ^ b,
                ast.BitAnd: lambda a, b: a & b,
                ast.BitOr: lambda a, b: a | b,
            }
            for op_type, operation in operations.items():
                if isinstance(node.op, op_type):
                    return operation(left, right)
        raise ValueError('unsupported expression: %r' % expression)

    return evaluate(tree)


def _split_arguments(arg_string):
    args = []
    start = 0
    quote = False
    depth = 0
    for index, char in enumerate(arg_string):
        if char == '"':
            quote = not quote
        elif not quote:
            if char == '(':
                depth += 1
            elif char == ')':
                depth -= 1
            elif char == ',' and depth == 0:
                args.append(arg_string[start:index].strip())
                start = index + 1
    last = arg_string[start:].strip()
    if last:
        args.append(last)
    return args


def _find_function_calls(code, function_name):
    """Yield ``(start, end, arguments, line)`` for balanced function calls."""
    suffix = r'\$?' if not function_name.endswith('$') else ''
    pattern = re.compile(r'(?<![A-Za-z0-9_.])' + re.escape(function_name) +
                         suffix + r'\s*\(', re.IGNORECASE)
    for match in pattern.finditer(code):
        open_paren = code.find('(', match.start())
        depth = 0
        quote = False
        end = None
        index = open_paren
        while index < len(code):
            char = code[index]
            if char == '"':
                if quote and index + 1 < len(code) and code[index + 1] == '"':
                    index += 2
                    continue
                quote = not quote
            elif not quote:
                if char == '(':
                    depth += 1
                elif char == ')':
                    depth -= 1
                    if depth == 0:
                        end = index + 1
                        break
            index += 1
        if end is None:
            continue
        arguments = code[open_paren + 1:end - 1]
        yield match.start(), end, arguments, _line_number(code, match.start())


def _best_xor_text(values):
    """Return a readable single-byte XOR candidate for numeric byte values."""
    if not values:
        return None, None
    dangerous_hint = re.compile(
        r'(?i)(https?|cmd|powershell|pwsh|shell|wscript|download|http|'
        r'\.exe|\.dll|\.ps1|\.bat|regsvr32|mshta|frombase64|virtualalloc)')
    best = None
    for key in range(1, 256):
        chars = []
        valid = True
        for value in values:
            code = (int(value) ^ key) & 0xFF
            if code in (9, 10, 13) or 32 <= code <= 126:
                chars.append(chr(code))
            else:
                valid = False
                break
        if not valid:
            continue
        text = ''.join(chars)
        letters = sum(char.isalnum() for char in text)
        if letters < max(3, len(text) // 3):
            continue
        score = sum(char.isalnum() or char in ' .:/\\_-$%?=&|,;()[]@!+'
                    for char in text)
        if dangerous_hint.search(text):
            score += 100
        if best is None or score > best[0]:
            best = (score, key, text)
    if best and best[0] >= len(values) and dangerous_hint.search(best[2]):
        return best[2], best[1]
    return None, None


class VBA_Deobfuscator(object):
    """Detect and restore common static VBA obfuscation techniques."""

    def __init__(self, code='', deep=True, propagate_variables=True,
                 existing_vba_strings=None):
        if isinstance(code, bytes):
            code = _decode_bytes(code) or code.decode('utf-8', 'replace')
        self.original_code = code or ''
        self.code = _collapse_continuations(self.original_code)
        self.deep = deep
        self.propagate_variables = propagate_variables
        self.existing_vba_strings = existing_vba_strings
        self.decoded_strings = []
        self.obfuscations = []
        self.dangerous_apis = []
        self.result = None
        self.deobfuscated_code = ''
        self.restored_code = ''
        self.expanded_code = ''
        self._decoded_keys = set()

    def _add_decoded(self, encoded, decoded, technique, line=None,
                     confidence=1.0, quote_replacement=True):
        if encoded is None or decoded is None:
            return None
        if isinstance(decoded, bytes):
            decoded = _decode_bytes(decoded)
        if not isinstance(decoded, str) or not decoded:
            return None
        if not _is_printable(decoded):
            return None
        key = (encoded, decoded)
        if key in self._decoded_keys:
            return None
        if line is None and isinstance(encoded, str):
            position = self.code.find(encoded)
            line = _line_number(self.code, position) if position >= 0 else None
        item = DecodedString(encoded, decoded, technique=technique, line=line,
                             confidence=confidence,
                             quote_replacement=quote_replacement)
        self.decoded_strings.append(item)
        self._decoded_keys.add(key)
        return item

    def decode(self):
        """Run all decoders and return a :class:`DeobfuscationResult`."""
        for _round in range(3):
            current = self._apply_replacements(self.code)
            before = len(self.decoded_strings)
            if self.deep:
                self._decode_with_olevba_grammar(current)
            self._decode_chr_runs(current)
            self._decode_constant_wrappers(current)
            self._decode_arrays_and_numeric_literals(current)
            self._decode_string_literals(current)
            self._decode_encoded_commands(current)
            self._decode_xor_source_loops(current)
            if len(self.decoded_strings) == before:
                break

        restored = self._apply_replacements(self.code)
        expanded = self._propagate_constants(restored) if self.propagate_variables else restored
        self._detect_obfuscations(restored)
        self.dangerous_apis = self._detect_apis(restored, expanded)
        self.result = DeobfuscationResult(
            self.original_code, restored, self.obfuscations,
            self.decoded_strings, self.dangerous_apis,
            expanded_code=expanded)
        self.deobfuscated_code = self.result.deobfuscated_code
        self.restored_code = self.result.restored_code
        self.expanded_code = self.result.expanded_code
        return self.result

    analyze = decode
    deobfuscate = decode
    run = decode
    restore = decode

    def detect_obfuscation(self):
        """Run decoding if needed and return obfuscation findings."""
        if self.result is None:
            self.decode()
        return self.obfuscations

    detect = detect_obfuscation

    def detect_dangerous_apis(self):
        """Run decoding if needed and return dangerous API findings."""
        if self.result is None:
            self.decode()
        return self.dangerous_apis

    def annotate_dangerous_apis(self):
        """Alias for :meth:`detect_dangerous_apis`."""
        return self.detect_dangerous_apis()

    def to_dict(self):
        """Return a JSON-serializable analysis dictionary."""
        if self.result is None:
            self.decode()
        return self.result.to_dict()

    def _decode_with_olevba_grammar(self, code):
        if self.existing_vba_strings is not None:
            matches = self.existing_vba_strings
            for encoded, decoded in matches:
                if isinstance(decoded, str) and decoded and decoded != encoded:
                    self._add_decoded(encoded, decoded, 'vba_expression')
            return
        try:
            from oletools.olevba import detect_vba_strings
        except Exception:
            return
        try:
            matches = detect_vba_strings(code)
        except Exception:
            return
        for encoded, decoded in matches:
            if isinstance(decoded, str) and decoded and decoded != encoded:
                self._add_decoded(encoded, decoded, 'vba_expression')

    def _decode_chr_runs(self, code):
        chr_call = (
            r'Chr(?:B|W)?\$?\s*\((?:[^()]*|\([^()]*\))*\)'
        )
        pattern = re.compile(chr_call + r'(?:\s*&\s*' + chr_call + r')+',
                             re.IGNORECASE)
        for match in pattern.finditer(code):
            expression = match.group(0)
            chars = []
            valid = True
            for call in re.finditer(
                    r'(?i)Chr(?:B|W)?\$?\s*\((?P<arg>.*?)\)\s*(?:&|$)',
                    expression + '&'):
                try:
                    value = _eval_constant_expression(call.group('arg'))
                    chars.append(chr(int(value) & 0xFFFF))
                except Exception:
                    valid = False
                    break
            if valid and chars:
                self._add_decoded(expression, ''.join(chars),
                                  'chr_encoding',
                                  _line_number(code, match.start()))

    def _decode_constant_wrappers(self, code):
        for start, end, args_text, line in _find_function_calls(code, 'StrReverse'):
            args = _split_arguments(args_text)
            if len(args) == 1:
                try:
                    value = _eval_constant_expression(args[0])
                    if isinstance(value, str):
                        self._add_decoded(code[start:end], value[::-1],
                                          'strreverse', line)
                except Exception:
                    pass

        for start, end, args_text, line in _find_function_calls(code, 'Replace'):
            args = _split_arguments(args_text)
            if len(args) >= 3:
                try:
                    text, old, new = [_eval_constant_expression(arg)
                                      for arg in args[:3]]
                    if isinstance(text, str):
                        self._add_decoded(code[start:end],
                                          text.replace(old, new),
                                          'replace_substitution', line)
                except Exception:
                    pass

        for start, end, args_text, line in _find_function_calls(code, 'Join'):
            args = _split_arguments(args_text)
            if not args:
                continue

            array_match = re.match(
                r'(?is)Array\s*\((?P<args>.*)\)\s*$', args[0].strip())
            if array_match:
                array_args = _split_arguments(array_match.group('args'))
                try:
                    values = [_eval_constant_expression(arg)
                              for arg in array_args]
                    joiner = (_eval_constant_expression(args[1])
                              if len(args) > 1 else '')
                    if values and all(isinstance(value, str) for value in values):
                        self._add_decoded(
                            code[start:end], joiner.join(values),
                            'split_join', line)
                except Exception:
                    pass
                continue

            split_match = re.match(
                r'(?is)Split\s*\((?P<args>.*)\)\s*$', args[0].strip())
            if not split_match:
                continue
            split_args = _split_arguments(split_match.group('args'))
            if len(split_args) < 2:
                continue
            try:
                text = _eval_constant_expression(split_args[0])
                delimiter = _eval_constant_expression(split_args[1])
                joiner = (_eval_constant_expression(args[1])
                          if len(args) > 1 else '')
                if isinstance(text, str):
                    self._add_decoded(
                        code[start:end], joiner.join(text.split(delimiter)),
                        'split_join', line)
            except Exception:
                pass

        for function_name in ('LCase', 'LCase$', 'UCase', 'UCase$',
                              'Trim', 'Trim$'):
            technique = 'case_normalization'
            for start, end, args_text, line in _find_function_calls(code, function_name):
                args = _split_arguments(args_text)
                if len(args) != 1:
                    continue
                try:
                    value = _eval_constant_expression(args[0])
                    if not isinstance(value, str):
                        continue
                    if function_name.lower().startswith('lcase'):
                        decoded = value.lower()
                    elif function_name.lower().startswith('ucase'):
                        decoded = value.upper()
                    else:
                        decoded = value.strip()
                    self._add_decoded(code[start:end], decoded, technique, line,
                                      confidence=0.6)
                except Exception:
                    pass

    def _decode_arrays_and_numeric_literals(self, code):
        for start, end, args_text, line in _find_function_calls(code, 'Array'):
            raw_args = _split_arguments(args_text)
            values = []
            if len(raw_args) < 4:
                continue
            for arg in raw_args:
                try:
                    values.append(int(_eval_constant_expression(arg)))
                except Exception:
                    values = None
                    break
            if not values:
                continue
            chars = []
            for value in values:
                if 0 <= value <= 255:
                    chars.append(chr(value))
                else:
                    chars.append(chr(max(0, value) & 0xFFFF))
            text = ''.join(chars)
            encoded = code[start:end]
            if _is_printable(text):
                self._add_decoded(encoded, text, 'char_array', line)
            raw_meaningful = _is_printable(text) and _is_meaningful(text)
            xor_text = None
            if not raw_meaningful:
                xor_text, key = _best_xor_text(values)
            if xor_text is not None and not raw_meaningful:
                self._add_decoded(encoded, xor_text, 'xor_array', line,
                                  confidence=0.85)

        string_literal = re.compile(r'"((?:[^"]|"")*)"')
        for match in string_literal.finditer(code):
            inner = _unquote_vba(match.group(0))
            if len(inner) < 7:
                continue
            if (re.search(r'\d', inner) and
                    re.sub(r'[\d\s,;|:._\-&HhOoXx]', '', inner) == ''):
                tokens = re.findall(r'&[Hh][0-9A-Fa-f]+|&[Oo][0-7]+|\d+', inner)
                values = []
                try:
                    values = [_safe_int(token) for token in tokens]
                except Exception:
                    values = []
                if len(values) >= 5:
                    text = ''.join(chr(value & 0xFF) for value in values)
                    raw_meaningful = _is_printable(text) and _is_meaningful(text)
                    if _is_printable(text):
                        self._add_decoded(match.group(0), text,
                                          'numeric_string',
                                          _line_number(code, match.start()))
                    xor_text = None
                    if not raw_meaningful:
                        xor_text, _key = _best_xor_text(values)
                    if xor_text is not None and not raw_meaningful:
                        self._add_decoded(match.group(0), xor_text,
                                          'xor_numeric_string',
                                          _line_number(code, match.start()),
                                          confidence=0.85)

    def _decode_string_literals(self, code):
        literal_pattern = re.compile(r'"((?:[^"]|"")*)"')
        for match in literal_pattern.finditer(code):
            literal = match.group(0)
            inner = _unquote_vba(literal)
            line = _line_number(code, match.start())

            hex_candidate = re.sub(r'\s+', '', inner)
            if (len(hex_candidate) >= 8 and len(hex_candidate) % 2 == 0 and
                    re.search(r'\d', hex_candidate) and
                    re.fullmatch(r'[0-9A-Fa-f]+', hex_candidate)):
                try:
                    raw = binascii.unhexlify(hex_candidate)
                    decoded = _decode_bytes(raw)
                    if decoded and len(decoded) >= 2:
                        self._add_decoded(literal, decoded, 'hex_encoding', line)
                        continue
                except (binascii.Error, ValueError):
                    pass

            # Base64 payloads may be line-wrapped, but ordinary spaces in a
            # sentence must not be removed because that creates false positives.
            compact_b64 = re.sub(r'[\r\n\t]+', '', inner)
            if (len(compact_b64) >= 12 and len(compact_b64) % 4 == 0 and
                    re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', compact_b64) and
                    compact_b64.lower() not in {
                        'thisdocument', 'thisworkbook', 'kernel32',
                        'virtualalloc', 'createthread'}):
                try:
                    raw = base64.b64decode(compact_b64, validate=True)
                    decoded = _decode_bytes(raw)
                    if (decoded and len(decoded) >= 4 and
                            (_is_meaningful(decoded) or decoded.startswith('MZ'))):
                        self._add_decoded(literal, decoded,
                                          'base64_encoding', line)
                except (binascii.Error, ValueError):
                    pass

    def _decode_encoded_commands(self, code):
        """Decode PowerShell -EncodedCommand payloads commonly embedded in VBA."""
        pattern = re.compile(
            r'(?i)(?:-enc|-encodedcommand)\s+'
            r'(?P<token>[A-Za-z0-9+/]{16,}={0,2})')
        for match in pattern.finditer(code):
            token = match.group('token')
            padded = token + '=' * ((4 - len(token) % 4) % 4)
            try:
                raw = base64.b64decode(padded, validate=False)
            except (binascii.Error, ValueError):
                continue
            decoded = None
            for encoding in ('utf-16-le', 'utf-8'):
                try:
                    candidate = raw.decode(encoding, errors='strict')
                except UnicodeDecodeError:
                    continue
                if _is_printable(candidate) and _is_meaningful(candidate):
                    decoded = candidate
                    break
            if decoded:
                self._add_decoded(token, decoded, 'powershell_encoding',
                                  _line_number(code, match.start()),
                                  confidence=0.95, quote_replacement=False)

    def _decode_xor_source_loops(self, code):
        key_value = None
        # The Asc/Mid calls may contain nested parentheses, so locate the XOR
        # operand separately and require Mid/Asc context below.
        key_match = re.search(
            r'(?i)\bXor\s*(&H[0-9A-Fa-f]+|\d+|[A-Za-z_]\w*)', code)
        source_var = None
        if key_match and re.search(r'(?i)\b(?:AscW?|Chr)\b.*\bMid', code):
            key_token = key_match.group(1)
            if re.match(r'(?i)^(?:&H|\d)', key_token):
                try:
                    key_value = _safe_int(key_token)
                except Exception:
                    key_value = None
            mid_match = re.search(
                r'(?i)Mid(?:B)?\$?\s*\(\s*([A-Za-z_]\w*)', code)
            if mid_match:
                source_var = mid_match.group(1)

        numeric_constants = dict(
            (name, _safe_int(value))
            for name, value in re.findall(
                r'(?im)^\s*(?:Const\s+)?([A-Za-z_]\w*)\s*=\s*'
                r'(&H[0-9A-Fa-f]+|\d+)\s*(?:\'|$)', code)
            if self._can_safe_int(value)
        )
        if key_value is None and key_match and key_match.group(1) in numeric_constants:
            key_value = numeric_constants[key_match.group(1)]

        if key_value is None or not source_var:
            return

        assignment = re.search(
            r'(?im)^\s*' + re.escape(source_var) +
            r'\s*=\s*("(?:[^"]|"")*")', code)
        if not assignment:
            return
        literal = assignment.group(1)
        source = _unquote_vba(literal)
        decoded = ''.join(chr((ord(char) ^ key_value) & 0xFFFF)
                          for char in source)
        if _is_printable(decoded) and re.search(
                r'(?i)(https?|cmd|powershell|shell|wscript|\.exe|download)',
                decoded):
            self._add_decoded(literal, decoded, 'xor_encoding',
                              _line_number(code, assignment.start()),
                              confidence=0.9)

    @staticmethod
    def _can_safe_int(value):
        try:
            _safe_int(value)
            return True
        except Exception:
            return False

    def _apply_replacements(self, code):
        result = code
        replacements = {}
        candidates = {}
        for item in self.decoded_strings:
            encoded, decoded = item
            candidates.setdefault(encoded, []).append(item)
        for encoded, items in candidates.items():
            meaningful = [item for item in items
                          if _is_meaningful(item.decoded)]
            if meaningful:
                chosen = sorted(
                    meaningful,
                    key=lambda item: (item.confidence, len(item.decoded)),
                    reverse=True)[0]
            else:
                chosen = sorted(
                    items,
                    key=lambda item: (item.confidence, len(item.decoded)),
                    reverse=True)[0]
            replacements[encoded] = chosen
        for encoded in sorted(replacements, key=len, reverse=True):
            chosen = replacements[encoded]
            if chosen.quote_replacement:
                replacement = _quote_vba(chosen.decoded)
            else:
                replacement = chosen.decoded.replace('"', '""')
            result = result.replace(encoded, replacement)
        return result

    def _propagate_constants(self, code):
        assignments = {}
        counts = {}
        assignment_re = re.compile(
            r'(?m)^(?P<prefix>\s*(?:Set\s+)?(?P<name>[A-Za-z_]\w*)\s*=\s*)'
            r'(?P<value>"(?:[^"]|"")*")\s*(?:\'[^\n]*)?$')
        for match in assignment_re.finditer(code):
            name = match.group('name')
            counts[name] = counts.get(name, 0) + 1
            assignments[name] = _unquote_vba(match.group('value'))

        unique_assignments = dict(
            (name, value) for name, value in assignments.items()
            if counts.get(name, 0) == 1)
        if not unique_assignments:
            return code

        variable_pattern = re.compile(
            r'\b(?:' + '|'.join(
                sorted((re.escape(name) for name in unique_assignments),
                       key=len, reverse=True)) + r')\b')

        def replace_variables(text):
            return variable_pattern.sub(
                lambda match: _quote_vba(unique_assignments[match.group(0)]),
                text)

        result_lines = []
        for line in code.split('\n'):
            if re.search(r'(?i)\b(?:Dim|ReDim|For|Function|Sub)\b', line):
                result_lines.append(line)
                continue
            assignment_match = re.match(
                r'^(?P<prefix>\s*(?:Set\s+)?)(?P<name>[A-Za-z_]\w*)'
                r'(?P<middle>\s*=\s*)(?P<rhs>.*)$', line)
            if (assignment_match and
                    assignment_match.group('name') in unique_assignments):
                line = (assignment_match.group('prefix') +
                        assignment_match.group('name') +
                        assignment_match.group('middle') +
                        replace_variables(assignment_match.group('rhs')))
            else:
                line = replace_variables(line)
            result_lines.append(line)
        return '\n'.join(result_lines)

    def _detect_obfuscations(self, restored_code):
        text = self.code or ''

        def add(technique, keyword, description, severity=SEVERITY_MEDIUM,
                confidence=1.0, line=None, evidence=None):
            for finding in self.obfuscations:
                if (finding[1] == keyword or
                        getattr(finding, 'technique', None) == technique):
                    return finding
            finding = ObfuscationFinding(
                'Obfuscation', keyword, description, technique=technique,
                severity=severity, confidence=confidence, line=line,
                evidence=evidence, legacy_type='Suspicious')
            self.obfuscations.append(finding)
            return finding

        if self.decoded_strings:
            technique_keywords = {
                'chr_encoding': ('chr_encoding', 'Chr Encoding',
                                  OBFUSCATION_TECHNIQUES['chr_encoding']),
                'vba_expression': ('chr_encoding', 'VBA obfuscated Strings',
                                    'VBA string expressions were detected and restored'),
                'hex_encoding': ('hex_encoding', 'Hex Strings',
                                 OBFUSCATION_TECHNIQUES['hex_encoding']),
                'base64_encoding': ('base64_encoding', 'Base64 Strings',
                                    OBFUSCATION_TECHNIQUES['base64_encoding']),
                'powershell_encoding': ('powershell_encoding', 'PowerShell EncodedCommand',
                                        OBFUSCATION_TECHNIQUES['powershell_encoding']),
                'strreverse': ('strreverse', 'StrReverse Strings',
                               OBFUSCATION_TECHNIQUES['strreverse']),
                'replace_substitution': ('replace_substitution',
                                         'Replace Substitution',
                                         OBFUSCATION_TECHNIQUES['replace_substitution']),
                'split_join': ('split_join', 'Split/Join Strings',
                               OBFUSCATION_TECHNIQUES['split_join']),
                'char_array': ('char_array', 'Character Array',
                               OBFUSCATION_TECHNIQUES['char_array']),
                'numeric_string': ('numeric_string', 'Numeric String Codes',
                                   OBFUSCATION_TECHNIQUES['numeric_string']),
                'xor_encoding': ('xor_encoding', 'XOR Strings',
                                 OBFUSCATION_TECHNIQUES['xor_encoding']),
                'xor_array': ('xor_encoding', 'XOR Strings',
                              OBFUSCATION_TECHNIQUES['xor_encoding']),
                'xor_numeric_string': ('xor_encoding', 'XOR Strings',
                                       OBFUSCATION_TECHNIQUES['xor_encoding']),
            }
            for item in self.decoded_strings:
                if item.technique in technique_keywords:
                    technique, keyword, description = technique_keywords[item.technique]
                    add(technique, keyword, description, line=item.line)

        chr_count = len(re.findall(r'(?i)\bChr(?:B|W)?\$?\s*\(', text))
        if chr_count >= 3:
            add('chr_encoding', 'Chr Encoding',
                OBFUSCATION_TECHNIQUES['chr_encoding'],
                confidence=min(1.0, 0.6 + chr_count / 30.0))
        if re.search(r'(?i)\bStrReverse\s*\(', text):
            add('strreverse', 'StrReverse Strings',
                OBFUSCATION_TECHNIQUES['strreverse'])
        if re.search(r'(?i)\bReplace\s*\(', text) and '"' in text:
            add('replace_substitution', 'Replace Substitution',
                OBFUSCATION_TECHNIQUES['replace_substitution'],
                confidence=0.7)
        if re.search(r'(?i)\bSplit\s*\(', text) and re.search(r'(?i)\bJoin\s*\(', text):
            add('split_join', 'Split/Join Strings',
                OBFUSCATION_TECHNIQUES['split_join'])
        if re.search(r'(?i)\bArray\s*\(\s*(?:&H)?\d', text):
            add('char_array', 'Character Array',
                OBFUSCATION_TECHNIQUES['char_array'], confidence=0.7)
        if re.search(r'(?i)\bXor\b', text) and re.search(r'(?i)\b(?:Asc|Chr|Mid)\b', text):
            add('xor_encoding', 'XOR Strings',
                OBFUSCATION_TECHNIQUES['xor_encoding'])
        if re.search(r'(?i)\bCallByName\b', text):
            add('call_by_name', 'CallByName Obfuscation',
                OBFUSCATION_TECHNIQUES['call_by_name'], SEVERITY_HIGH)
        if (re.search(r'(?i)\bGetProcAddress\b', text) and
                re.search(r'(?i)\bLoadLibrary[AW]?\b', text)) or re.search(
                r'(?i)\bDeclare\b.*\bLib\b', text):
            add('dynamic_api_resolution', 'Dynamic API Resolution',
                OBFUSCATION_TECHNIQUES['dynamic_api_resolution'], SEVERITY_HIGH)
        if len(re.findall(r'[ \t]+_[ \t]*(?:\n|$)', self.original_code)) >= 3:
            add('line_continuation', 'Line Continuation',
                OBFUSCATION_TECHNIQUES['line_continuation'], SEVERITY_LOW)
        # NUL bytes are common in XLM/BIFF disassembly; focus on controls
        # known to be used for terminal/source obfuscation.
        if '\x08' in text or '\x1b' in text or re.search(r'[\x0b\x0c]', text):
            add('control_character', 'Hidden Control Character',
                OBFUSCATION_TECHNIQUES['control_character'], SEVERITY_MEDIUM)

        long_literals = re.findall(r'"[A-Za-z0-9+/=,;:|._\- ]{80,}"', text)
        if long_literals:
            add('long_literal', 'Long Encoded Literal',
                OBFUSCATION_TECHNIQUES['long_literal'], SEVERITY_LOW)

        identifiers = re.findall(r'(?<![A-Za-z0-9_.])([A-Za-z_][A-Za-z0-9_]{7,})', text)
        random_like = set()
        for identifier in identifiers:
            lower_ident = identifier.lower()
            if lower_ident in _VBA_KEYWORDS or lower_ident in DANGEROUS_APIS:
                continue
            has_digit = any(char.isdigit() for char in identifier)
            has_mixed_case = identifier != identifier.lower() and identifier != identifier.upper()
            vowels = sum(char.lower() in 'aeiou' for char in identifier)
            if (has_digit and has_mixed_case) or (
                    len(identifier) >= 10 and vowels <= 2 and has_mixed_case):
                random_like.add(identifier)
        occurrences = sum(text.count(name) for name in random_like)
        if len(random_like) >= 5 and occurrences >= 8:
            add('identifier_randomization', 'Randomized Identifiers',
                OBFUSCATION_TECHNIQUES['identifier_randomization'],
                SEVERITY_LOW, confidence=0.65)

    def _detect_apis(self, restored_code, expanded_code):
        findings = []
        seen = set()
        # Expanded code contains the original source plus restored literals and
        # propagated constants, so one pass is enough and keeps line numbers.
        code = expanded_code or restored_code or self.code or ''
        code_lines = code.splitlines()
        for match in _API_PATTERN.finditer(code):
            name = _API_NAME_TO_CANONICAL[match.group(0).lower()]
            line_number = _line_number(code, match.start())
            key = (name.lower(), line_number)
            if key in seen:
                continue
            seen.add(key)
            line_text = (code_lines[line_number - 1].strip()
                         if 0 < line_number <= len(code_lines) else '')
            finding = DangerousAPIFinding(
                'DangerousAPI', name, DANGEROUS_APIS[name],
                category=API_CATEGORY[name],
                severity=API_SEVERITY[name], line=line_number,
                        evidence=line_text[:300],
                        legacy_type='Suspicious')
            findings.append(finding)

        declare_pattern = re.compile(
            r'(?im)\bDeclare\b(?:\s+PtrSafe)?(?:\s+(?:Function|Sub))?\s+'
            r'(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s+Lib\s+'
            r'"(?P<dll>[^"]+)"(?:\s+Alias\s+"(?P<alias>[^"]+)")?')
        for match in declare_pattern.finditer(code):
            name = match.group('alias') or match.group('name')
            line_number = _line_number(code, match.start())
            key = (name.lower(), line_number)
            if key in seen:
                continue
            seen.add(key)
            dll = match.group('dll')
            severity = (SEVERITY_HIGH if dll.lower() in
                        ('kernel32', 'kernel32.dll', 'ntdll', 'ntdll.dll',
                         'user32', 'user32.dll')
                        else SEVERITY_MEDIUM)
            description = (
                'Declares external API %s from %s; review its arguments for '
                'execution, injection or evasion behaviour' % (name, dll))
            line_text = (code_lines[line_number - 1].strip()
                         if 0 < line_number <= len(code_lines) else '')
            findings.append(DangerousAPIFinding(
                'DangerousAPI', name, description,
                category='dll_declaration', severity=severity,
                line=line_number, evidence=line_text[:300],
                legacy_type='Suspicious'))
        findings.sort(key=lambda item: (item.line or 0, item[1]))
        return findings


def analyze_vba(code='', deep=True, propagate_variables=True,
                existing_vba_strings=None):
    """Analyze VBA source and return a :class:`DeobfuscationResult`."""
    return VBA_Deobfuscator(
        code, deep=deep, propagate_variables=propagate_variables,
        existing_vba_strings=existing_vba_strings).decode()


# British spelling alias used by some security projects.
analyse_vba = analyze_vba


def deobfuscate_vba(code='', deep=True, propagate_variables=True,
                    existing_vba_strings=None):
    """Return restored VBA source with structured findings attached."""
    return analyze_vba(code, deep=deep,
                       propagate_variables=propagate_variables,
                       existing_vba_strings=existing_vba_strings)


def deobfuscate(code='', deep=True, propagate_variables=True,
                existing_vba_strings=None):
    """Convenience alias for :func:`deobfuscate_vba`."""
    return deobfuscate_vba(code, deep=deep,
                           propagate_variables=propagate_variables,
                           existing_vba_strings=existing_vba_strings)


def restore_vba(code='', deep=True, propagate_variables=False):
    """Return only the restored source as a plain string."""
    return str(analyze_vba(code, deep=deep,
                           propagate_variables=propagate_variables))


def deobfuscate_to_dict(code='', deep=True, propagate_variables=True):
    """Return the unified analysis as a JSON-serializable dictionary."""
    return analyze_vba(
        code, deep=deep,
        propagate_variables=propagate_variables).to_dict()


def detect_obfuscation(code='', deep=False):
    """Return obfuscation findings for VBA source."""
    return analyze_vba(code, deep=deep).obfuscations


def detect_vba_obfuscation(code='', deep=False):
    """Alias for :func:`detect_obfuscation`."""
    return detect_obfuscation(code, deep=deep)


def detect_vba_obfuscations(code='', deep=False):
    """Plural alias for :func:`detect_vba_obfuscation`."""
    return detect_obfuscation(code, deep=deep)


def annotate_dangerous_apis(code='', deep=True):
    """Return olevba-compatible dangerous API annotation tuples."""
    return analyze_vba(code, deep=deep).dangerous_apis


def detect_dangerous_apis(code='', deep=True):
    """Alias for :func:`annotate_dangerous_apis`."""
    return annotate_dangerous_apis(code, deep=deep)


def annotate_dangerous_api(code='', deep=True):
    """Singular function alias for :func:`annotate_dangerous_apis`."""
    return annotate_dangerous_apis(code, deep=deep)


def deobfuscate_vba_code(code='', deep=True, propagate_variables=True):
    """Descriptive alias for :func:`deobfuscate_vba`."""
    return deobfuscate_vba(
        code, deep=deep, propagate_variables=propagate_variables)


def restore_vba_code(code='', deep=True, propagate_variables=False):
    """Descriptive alias for :func:`restore_vba`."""
    return restore_vba(
        code, deep=deep, propagate_variables=propagate_variables)


def deobfuscate_expression(expression):
    """Decode one constant VBA expression or encoded literal."""
    if not isinstance(expression, str):
        expression = expression.decode('utf-8', 'replace')
    result = analyze_vba(expression, deep=True, propagate_variables=False)
    if result.decoded_strings:
        return result.decoded_strings[0].decoded
    try:
        value = _eval_constant_expression(expression)
        return value
    except Exception:
        return str(result)


# Common class-name aliases used by integrations and generated tests.
VBADeobfuscator = VBA_Deobfuscator
VbaDeobfuscator = VBA_Deobfuscator
VBAObfuscationDetector = VBA_Deobfuscator
VBAObfuscationAnalyzer = VBA_Deobfuscator
DangerousAPIDetector = VBA_Deobfuscator
VBAObfuscationEngine = VBA_Deobfuscator
VBADeobfuscationEngine = VBA_Deobfuscator
Deobfuscator = VBA_Deobfuscator
VbaDeobfuscationEngine = VBA_Deobfuscator

# Result-type aliases.
DangerousAPI = DangerousAPIFinding
Obfuscation = ObfuscationFinding
VbaDeobfuscationResult = DeobfuscationResult
VBADeobfuscationResult = DeobfuscationResult

# Common constant aliases.
DANGEROUS_API_KEYWORDS = DANGEROUS_APIS
DANGEROUS_FUNCTIONS = DANGEROUS_APIS
SUSPICIOUS_APIS = DANGEROUS_APIS
API_INFO = DANGEROUS_API_INFO
