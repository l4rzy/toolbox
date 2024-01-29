from collections import deque
class Nav:
    def __init__(self):
        self.list = deque([None]*10, maxlen=10)
        self.list.append(None)
        self.index = 0

    def debug(self):
        print(f'list: {self.list}\nindex: {self.index}')

    def append(self, entry):
        if self.index == 0 and self.list[0] is None:
            self.list[0] = entry
        elif self.index == 9:
            self.list.append(entry)
        else:
            self.index += 1
            self.list[self.index] = entry
            for i in range(self.index + 1, 10):
                self.list[i] = None

    def back(self):
        if self.index > 0:
            self.index -=1
        else:
            return None
        
    def forw(self):
        if self.index < 8:
            self.index += 1
        else:
            return None
        
n = Nav()
n.append('1.1.1.1')
n.debug()
n.append('2.2.2.2')
n.debug()
n.back()
n.debug()
n.append('3.3.3.3')
n.append('3.3.3.3')
n.append('3.3.3.3')
n.append('3.3.3.3')
n.append('3.3.3.3')
n.append('3.3.3.3')
n.append('3.3.3.3')
n.append('3.3.3.3')
n.append('3.3.3.3')
n.append('3.3.3.3')
n.append('5.5.5.5')
n.append('3.3.3.3')
n.debug()
n.back()
n.back()
n.back()
n.debug()
n.append('x.x.x.x')
n.debug()
