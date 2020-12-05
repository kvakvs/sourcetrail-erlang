#!/usr/bin/env python3

import argparse

from srctrl_erlang.scanner import Scanner


def main():
    parser = argparse.ArgumentParser(description='Parse Erlang files and create Sourcetrail DB')

    parser.add_argument('--db', type=str, required=True,
                        help='Path to the Sourcetrail database for this project')
    parser.add_argument('--file', type=str, required=True,
                        help='Path to the Erlang source for this project')

    args = parser.parse_args()

    db_path = args.db  # type: str
    input_path = args.file  # type: str

    if not input_path.endswith(".beam"):
        # Ignore files other than BEAM
        return
    # if not src_path.endswith(".erl") and not src_path.endswith(".hrl"):
        # Ignore files other than ERL and HRL
        # return

    s = Scanner(db_file=db_path, beam_file=input_path)
    s.run()
    s.commit()


main()
