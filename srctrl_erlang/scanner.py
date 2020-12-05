import sys

import sourcetraildb as srctrl


class Scanner:
    def __init__(self, db_file: str, beam_file: str):
        self.beam_file = beam_file

        if not srctrl.open(db_file):
            print("ERROR: " + srctrl.getLastError())
            sys.exit(1)

        print(f"Scanning: {self.beam_file}")
        srctrl.clear()
        srctrl.beginTransaction()

        self.file_id = srctrl.recordFile(self.beam_file)

    def run(self):
        srctrl.recordFileLanguage(self.file_id, "erlang")

    def commit(self):
        srctrl.commitTransaction()
        if len(srctrl.getLastError()) > 0:
            print("ERROR: " + srctrl.getLastError())
            sys.exit(1)

        if not srctrl.close():
            print("ERROR: " + srctrl.getLastError())
            sys.exit(1)

    def fail_with(self, msg: str):
        print(f"ERROR: {msg}")
        sys.exit(1)

    def record_symbol(self, name: str) -> int:
        symbol_id = srctrl.recordSymbol(
            '{ "name_delimiter": ".", "name_elements": [ '
            f'  {"prefix": "", "name": "{name}", "postfix": "" } '
            '  ] }')
        srctrl.recordSymbolDefinitionKind(symbol_id, srctrl.DEFINITION_EXPLICIT)
        srctrl.recordSymbolKind(symbol_id, srctrl.SYMBOL_CLASS)
        srctrl.recordSymbolLocation(symbol_id, self.file_id, 2, 7, 2, 12)
        srctrl.recordSymbolScopeLocation(symbol_id, self.file_id, 2, 1, 7, 1)
        return symbol_id

    def record_member(self, parent_class: str, member_name: str):
        memberId = srctrl.recordSymbol(
            '{ "name_delimiter": ".", "name_elements": [ '
            f'{"prefix": "", "name": "{parent_class}", "postfix": "" }, '
            f'{"prefix": "", "name": "{member_name}", "postfix": "" } '
            '] }')
        srctrl.recordSymbolDefinitionKind(memberId, srctrl.DEFINITION_EXPLICIT)
        srctrl.recordSymbolKind(memberId, srctrl.SYMBOL_FIELD)
        srctrl.recordSymbolLocation(memberId, self.file_id, 4, 2, 4, 10)
