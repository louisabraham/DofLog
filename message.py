from binrw import Data

class Msg():

    def __init__(self, buf):
        self.b = True
        try:
            header = int.from_bytes(buf.read(2), 'big')
            lenData = int.from_bytes(buf.read(header & 3), 'big')
            self.id = header >> 2
            self.data = Data(buf.read(lenData))
        except IndexError:
            buf.pos = 0
            self.b = False
        else:
            buf.end()

    def __bool__(self):
        return self.b
