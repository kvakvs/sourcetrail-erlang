import json
import logging
import sys
from typing import List

from beam_file.beam_file import BEAMFile
from beam_file.form import Form
from sourcetrail_erlang import sourcetraildb as srctrl

LOGGER = logging.getLogger("disasm-reader")


class Scanner:
    def __init__(self, db_file: str, beam_file: str, parse_script_path: str):
        """ Load AST section from the BEAM file (compile with `+debug_info` !)

        :param parse_script_path: Path to `sourcetrail-disasm` escript (executable)
        """
        LOGGER.info(f"Scanning: {beam_file}")

        self.beam_file = beam_file

        disasm = load_ast(beam_file)  # type: List[Form]
        self.ast = disasm["forms"]
        self.module_name = disasm["module_name"]
        self.source_path = disasm["source"]

        if not srctrl.open(db_file):
            LOGGER.error("File open error: " + srctrl.getLastError())
            sys.exit(2)

        self.file_id = 0  # type: int

    def run(self):
        # srctrl.clear()
        srctrl.beginTransaction()

        self.file_id = srctrl.recordFile(self.source_path)
        srctrl.recordFileLanguage(self.file_id, "erlang")

        self.record_module(self.module_name)

        functions = filter(lambda node: node['type'] == 'function', self.ast)
        for node in functions:
            self.record_function(f"{node['name']}/{node['arity']}", node["line"])

            # Flatten the code and filter out all local and external fun references
            self.scan_code(node["code"])

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

    def record_function(self, name: str, line: int) -> int:
        query = {"name_delimiter": ":",
                 "name_elements": [
                     {"prefix": "", "name": self.module_name, "postfix": ""},
                     {"prefix": "", "name": name, "postfix": ""}
                 ]}
        symbol_id = srctrl.recordSymbol(json.dumps(query))
        srctrl.recordSymbolDefinitionKind(symbol_id, srctrl.DEFINITION_EXPLICIT)
        srctrl.recordSymbolKind(symbol_id, srctrl.SYMBOL_FUNCTION)
        srctrl.recordSymbolLocation(symbol_id, self.file_id, line, 1, line, len(name))
        srctrl.recordSymbolScopeLocation(symbol_id, self.file_id, line, 1, line, len(name))
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

    def scan_code(self, code: List):
        for e in code:
            e_type = e["type"]
            if e_type == "clause":
                self.scan_code(e["code"])
            elif e_type == "call":
                LOGGER.info(f"Call: {e['target']}")
            else:
                LOGGER.error(f"Unhandled node type {e_type}")


def load_ast(beam_file: str) -> List[Form]:
    beam = BEAMFile(beam_file)
    return []
