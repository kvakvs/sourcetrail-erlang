#!/usr/bin/env python3

import argparse
import logging
import os
import sys
import traceback

from sourcetrail_erlang.disasm_reader import Scanner


def setup_logging():
    logging.basicConfig(filename='sourcetrail-python.log',
                        filemode="at",
                        level=logging.DEBUG)
    return logging.getLogger("scan")


LOGGER = setup_logging()


def parse_args():
    parser = argparse.ArgumentParser(description='Parse Erlang files and create Sourcetrail DB')
    parser.add_argument('--db', type=str, required=True,
                        help='Path to the Sourcetrail database for this project')
    parser.add_argument('--file', type=str, required=True,
                        help='Path to the Erlang source for this project')

    # here = os.path.dirname(os.path.abspath(__file__))
    default_path = "/home/kv/proj/sourcetrail-erlang/_build/default/bin/sourcetrail-disasm"
    parser.add_argument('--disasm', type=str, required=False, default=default_path,
                        help='Path to the Escript <sourcetrail-disasm> which will read BEAM files')

    args = parser.parse_args()
    return args


def main():
    args = parse_args()

    db_path = args.db  # type: str
    input_path = args.file  # type: str
    disasm_path = args.disasm  # type: str

    if not input_path.endswith(".beam"):
        # Ignore files other than BEAM
        LOGGER.info(f"Ignored file: {input_path} (not a BEAM)")
        sys.exit(1)

    # if not src_path.endswith(".erl") and not src_path.endswith(".hrl"):
    # Ignore files other than ERL and HRL
    # return

    try:
        s = Scanner(db_file=db_path, beam_file=input_path, parse_script_path=disasm_path)
        s.run()
        s.commit()
    except Exception as e:
        exc_type, exc_val, tb = sys.exc_info()
        formatted_tb = '\n'.join(traceback.format_tb(tb))
        LOGGER.error(f"ERR {e}\n{formatted_tb}")


main()
