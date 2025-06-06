import re
import struct
import zlib
import olefile
import unicodedata

class HWPExtractor(object):
    FILE_HEADER_SECTION = "FileHeader"
    HWP_SUMMARY_SECTION = "\x05HwpSummaryInformation"
    SECTION_NAME_LENGTH = len("Section")
    BODYTEXT_SECTION = "BodyText"
    HWP_TEXT_TAGS = [67]

    def __init__(self, filename):
        self._ole = self.load(filename)
        self._dirs = self._ole.listdir()
        self._compressed = self.is_compressed(self._ole)
        self.text = self._get_text()

    # 파일 불러오기
    def load(self, filename):
        return olefile.OleFileIO(filename)

    def is_compressed(self, ole):
        header = self._ole.openstream("FileHeader")
        header_data = header.read()
        return (header_data[36] & 1) == 1

    def get_body_sections(self, dirs):
        m = []
        for d in dirs:
            if d[0] == self.BODYTEXT_SECTION:
                m.append(int(d[1][self.SECTION_NAME_LENGTH:]))

        return ["BodyText/Section" + str(x) for x in sorted(m)]

    def get_text(self):
        return self.text

    def _get_text(self):
        sections = self.get_body_sections(self._dirs)
        text = ""
        for section in sections:
            text += self.get_text_from_section(section)
            text += "\n"

        self.text = text
        return self.text

    def get_text_from_section(self, section):
        def remove_control_characters(s):
            return "".join(ch for ch in s if unicodedata.category(ch)[0] != "C")

        def remove_chinese_characters(s: str):
            return re.sub(r'[\u4e00-\u9fff]+', '', s)

        bodytext = self._ole.openstream(section)
        data = bodytext.read()

        unpacked_data = zlib.decompress(data, -15) if self.is_compressed else data
        size = len(unpacked_data)

        i = 0

        text = ""
        while i < size:
            header = struct.unpack_from("<I", unpacked_data, i)[0]
            rec_type = header & 0x3ff
            level = (header >> 10) & 0x3ff
            rec_len = (header >> 20) & 0xfff

            if rec_type in self.HWP_TEXT_TAGS:
                rec_data = unpacked_data[i + 4:i + 4 + rec_len]

                decode_text = rec_data.decode('utf-16')
                # 문자열을 담기 전 정제하기
                res = remove_control_characters(remove_chinese_characters(decode_text))

                text += res
                text += "\n"

            i += 4 + rec_len

        return text