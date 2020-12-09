import json
import logging
import os
import subprocess
import sys
from typing import Dict

from srctrl_erlang import sourcetraildb as srctrl

LOGGER = logging.getLogger("libscan")


class Scanner:
    def __init__(self, db_file: str, beam_file: str, parse_script_path: str):
        """ Load AST section from the BEAM file (compile with `+debug_info` !)

        :param parse_script_path: Path to `sourcetrail-disasm` escript (executable)
        """
        LOGGER.info(f"Scanning: {beam_file}")

        self.beam_file = beam_file
        self.module_name = os.path.splitext(os.path.basename(self.beam_file))[0]
        self.ast = load_ast(beam_file, parse_script_path)

        if not srctrl.open(db_file):
            LOGGER.error("File open error: " + srctrl.getLastError())
            sys.exit(2)

        self.file_id = 0 # type: int

    def run(self):
        srctrl.clear()
        srctrl.beginTransaction()

        self.file_id = srctrl.recordFile(self.beam_file)
        srctrl.recordFileLanguage(self.file_id, "erlang")

        self.record_module(self.module_name)

    def commit(self):
        srctrl.commitTransaction()
        if len(srctrl.getLastError()) > 0:
            LOGGER.error("Sourcetrail commit error: " + srctrl.getLastError())
            sys.exit(3)

        if not srctrl.close():
            LOGGER.error("Sourcetrail close error: " + srctrl.getLastError())
            sys.exit(4)

    def fail_with(self, msg: str):
        LOGGER.error(f"Sourcetrail error: {msg}")
        sys.exit(6)

    def record_module(self, name: str) -> int:
        LOGGER.info(f"+module: {name}")

        query = {"name_delimiter": ":",
                 "name_elements": [
                     {"prefix": "", "name": name, "postfix": ""}
                 ]}
        symbol_id = srctrl.recordSymbol(json.dumps(query))
        srctrl.recordSymbolDefinitionKind(symbol_id, srctrl.DEFINITION_EXPLICIT)
        srctrl.recordSymbolKind(symbol_id, srctrl.SYMBOL_MODULE)
        srctrl.recordSymbolLocation(symbol_id, self.file_id, 1, 1, 1, 1)
        srctrl.recordSymbolScopeLocation(symbol_id, self.file_id, 1, 1, 1, 1)
        return symbol_id

    def record_function(self, name: str) -> int:
        query = {"name_delimiter": ":",
                 "name_elements": [
                     {"prefix": "", "name": self.module_name, "postfix": ""},
                     {"prefix": "", "name": name, "postfix": ""}
                 ]}
        symbol_id = srctrl.recordSymbol(json.dumps(query))
        srctrl.recordSymbolDefinitionKind(symbol_id, srctrl.DEFINITION_EXPLICIT)
        srctrl.recordSymbolKind(symbol_id, srctrl.SYMBOL_FUNCTION)
        srctrl.recordSymbolLocation(symbol_id, self.file_id, 2, 7, 2, 12)
        srctrl.recordSymbolScopeLocation(symbol_id, self.file_id, 2, 1, 7, 1)
        return symbol_id

    # def record_member(self, parent_class: str, member_name: str):
    #     query = {"name_delimiter": ":",
    #              "name_elements": [
    #                  {"prefix": "", "name": parent_class, "postfix": ""},
    #                  {"prefix": "", "name": member_name, "postfix": ""}
    #              ]}
    #     memberId = srctrl.recordSymbol(json.dumps(query))
    #     srctrl.recordSymbolDefinitionKind(memberId, srctrl.DEFINITION_EXPLICIT)
    #     srctrl.recordSymbolKind(memberId, srctrl.SYMBOL_FIELD)
    #     srctrl.recordSymbolLocation(memberId, self.file_id, 4, 2, 4, 10)


def load_ast(beam_file: str, parse_script_path: str) -> Dict:
    p = subprocess.run([parse_script_path, beam_file],
                       capture_output=True)
    if p.returncode == 0:
        return json.loads(p.stdout)
    else:
        raise Exception(f"Disasm tool for {beam_file} failed with:\n{p.stdout}")
