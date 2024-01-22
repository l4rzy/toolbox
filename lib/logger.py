import io

class Logger:
    def __init__(self):
        self.buffer = io.BytesIO

    def write(self, log):
        self.buffer.write(log)

    def persist(self, filename):
        with open(filename, 'wb+') as f:
            f.write(self.buffer.getbuffer())

    def clear(self):
        self.buffer.truncate()
