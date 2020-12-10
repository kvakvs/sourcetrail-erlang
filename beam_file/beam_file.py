from typing import Dict


class BinaryReader:
    def __init__(self, filename: str):
        self.f = open(filename, "rb")

    def ensure_bytes(self, b: bytes):
        sample = self.f.read(len(b))
        assert sample == b

    def read_u32be(self) -> int:
        return int.from_bytes(self.f.read(4), byteorder="big", signed=False)

    def read_bytes(self, sz: int) -> bytes:
        return self.f.read(sz)


class BEAMChunk:
    def __init__(self, name: str, data: bytes):
        self.name = name
        self.data = data

    def __str__(self) -> str:
        return f"BEAMChunk('{self.name}', {str(self.data)})"


class BEAMDebugInfoChunk(BEAMChunk):

    def __init__(self, data: bytes):
        super().__init__("Dbgi", data)

        from term import codec
        self.ast = codec.binary_to_term(data)


class BEAMFile:
    def __init__(self, beam_file: str):
        self.code = b''
        self.chunks = {}  # type: Dict[str, BEAMChunk]
        self._load(beam_file)

    def _load(self, beam_file: str):
        """ Load BEAM file header. It begins with FOR1 for a IFF container
        https://en.wikipedia.org/wiki/Interchange_File_Format

        :param beam_file: Filename
        """
        br = BinaryReader(beam_file)
        br.ensure_bytes(b"FOR1")

        # IFF section for BEAM ->
        br.read_u32be()  # beam_size
        br.ensure_bytes(b"BEAM")

        while True:
            chunk_name = br.read_bytes(4)
            if chunk_name == b'':
                break  # end of file

            chunk_sz = br.read_u32be()

            chunk = self._load_chunk(str(chunk_name, "ascii"), chunk_sz, br)
            self._align_after_chunk(chunk_sz, br)

            self.chunks[chunk_name] = chunk

    def _load_chunk(self, chunk_name: str, chunk_sz: int, br: BinaryReader) -> BEAMChunk:
        """ Load a generic chunk of BEAM file. If the name is not interesting for this program, by default
        the chunk is loaded as bytes and the contents are ignored. Some special chunk types are fully parsed.

        :param chunk_name: 4 byte ASCII code for chunk type
        :param chunk_sz: size
        :type br: BinaryReader
        :return: Loaded chunk, or generic BEAMChunk if not interesting for us
        """
        if chunk_name == "Dbgi":
            return BEAMDebugInfoChunk(br.read_bytes(chunk_sz))

        return BEAMChunk(chunk_name, br.read_bytes(chunk_sz))

    def _align_after_chunk(self, chunk_sz: int, br: BinaryReader):
        """ Align chunk size to the multiple of 4 and read the necessary bytes

        :param chunk_sz: Chunk size just loaded
        :type br: BinaryReader
        """
        ALIGN: int = 4
        skip_size = ALIGN * int((chunk_sz + ALIGN - 1) / ALIGN) - chunk_sz
        if skip_size > 0:
            br.read_bytes(skip_size)
