'''
Python2/3 base64
https://gist.github.com/ajdavis/5735965
'''
import base64
import sys
import unittest

PY3 = sys.version_info[0] >= 3


def base64ify(bytes_or_str):
    if PY3 and isinstance(bytes_or_str, str):
        input_bytes = bytes_or_str.encode('utf8')
    else:
        input_bytes = bytes_or_str

    output_bytes = base64.urlsafe_b64encode(input_bytes)
    if PY3:
        return output_bytes.decode('ascii')
    else:
        return output_bytes


class Test(unittest.TestCase):
    def test_bytes_in(self):
        self.assertTrue(isinstance(base64ify(b'asdf'), type('hi')))

    def test_str_in(self):
        self.assertTrue(isinstance(base64ify('asdf'), type('hi')))


if __name__ == '__main__':
    unittest.main()
