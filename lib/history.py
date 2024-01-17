from pathlib import Path
print('Running' if __name__ == '__main__' else 'Importing', Path(__file__).resolve())

class History:
    def __init__(self, histFile='history.txt'):
        self.histFile = histFile

    def read(self):
        pass