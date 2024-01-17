import os
import customtkinter as widget
from lib.config import Config
from lib.analyzer import Analyzer
from lib.worker import AbuseIPDB
from threading import Thread

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

class DTSTabView(widget.CTkTabview):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.tabNames = ["Auto", "AbuseIPDB", "History", "Log"]

        for name in self.tabNames:
            self.add(name)

        self.tab('AbuseIPDB').grid_columnconfigure(0,weight=1)
        self.tab('AbuseIPDB').grid_rowconfigure(0,weight=1)
        
        self.textBox = widget.CTkTextbox(self.tab('AbuseIPDB'))
        self.textBox.insert("0.0", "Sorry I have nothing to show!\n"*100)
        self.textBox.grid(row=0, column=0, padx=5, pady=5, columnspan=1, rowspan=1, sticky="SWEN")

        self.tab('Log').grid_columnconfigure(0,weight=1)
        self.tab('Log').grid_rowconfigure(0,weight=1)
        
        self.textBox = widget.CTkTextbox(self.tab('Log'))
        self.textBox.insert("0.0", "Sorry I have nothing to show!\n"*100)
        self.textBox.grid(row=0, column=0, padx=5, pady=5, columnspan=1, rowspan=1, sticky="SWEN")

    def update_analyzer(self, analyzer: Analyzer):
        self.set('Auto')
        l = widget.CTkLabel(master=self.tab('Auto'), 
                        text=f'{analyzer.text} is: {analyzer.dataClass}')
        l.grid(row=0, column=0, padx=20, pady=10, columnspan=1, rowspan=1, sticky="SWEN")

    def update_worker(self, worker):
        pass

class DTSToolBox(widget.CTk):
    def __init__(self):
        super().__init__()
        self.grid_columnconfigure(0,weight=1)
        self.grid_rowconfigure(0,weight=0)
        self.grid_rowconfigure(1,weight=10)

        self.iconbitmap(resource_path('.\lib\icon.ico'))
        self.title("Toolbox")

        # add widgets to app
        self.topFrame = widget.CTkFrame(self, border_width=2)
        self.searchBar = widget.CTkEntry(self.topFrame, height=40, width=408)
        self.button = widget.CTkButton(self.topFrame, text="Lookup")
        self.searchBar.grid(row=0, column=0, padx=5, pady=5, sticky="NEW")
        self.button.grid(row=0, column=1, padx=20, pady=10, sticky="ENS")

        self.tabView = DTSTabView(master=self)
        self.topFrame.grid(row=0,column=0, padx=6, pady=6, columnspan=1, rowspan=1, sticky="NEW")
        self.tabView.grid(row=1, column=0, padx=10, pady=8, columnspan=1, rowspan=1, sticky="SWEN")
        self.drag_id = ''

        # config
        self.config = Config()
        # analyzer
        self.analyzer = Analyzer()
        self.worker = AbuseIPDB(self.config.get('api', 'abuseipdb'))

        # threads
        self.threads = {}

    def clear_search_bar(self):
        self.searchBar.delete(0, len(self.searchBar.get()))

    def setup_geometry(self):
        self.minsize(640, 320)

        if self.config.get('ui', 'dimension') != None:
            self.geometry(self.config.get('ui', 'dimension'))
        (dx, dy) = self.config.get_dimension()
        ws = self.winfo_screenwidth()
        hs = self.winfo_screenheight()

        x = (ws) - (int(dx))
        y = (hs) - (int(dy))
        self.geometry(f'{dx}x{dy}+{x}+{y}')

    def bind_events(self):
        self.bind('<FocusIn>', self.cb_on_focus)
        self.bind('<Configure>', self.cb_on_drag)
        self.button.bind('<Button-1>', self.cb_on_entry_update)

    # add methods to app
        
    def cb_on_drag(self, event):
        if event.widget is self:  # do nothing if the event is triggered by one of root's children
            if self.drag_id == '':
                # action on drag start
                pass
            else:
                # cancel scheduled call to stop_drag
                self.after_cancel(drag_id)
            # schedule stop_drag
            drag_id = self.after(100, self.__stop_drag)

    def __stop_drag(self):
        self.config.set('ui', 'dimension', self.geometry())
        # reset drag_id to be able to detect the start of next dragging
        self.drag_id = '' 

    def cb_on_focus(self, event):
        print('[i] focused on main window')
        self.analyzer.reset()
        self.searchBar.focus()
        clipboard = self.clipboard_get().strip()
        if clipboard == self.searchBar.get():
            return
        self.analyzer.process(clipboard)
        if self.analyzer.insertable:
            self.clear_search_bar()
            self.searchBar.insert(0, clipboard)
            self.cb_on_entry_update(event, clipboard)
        
    def cb_on_entry_update(self, event, text=''):
        if text == '':
            text = self.searchBar.get()
            self.analyzer.process(text)

        if self.analyzer.dataClass == 'ipv4' or self.analyzer.dataClass == 'ipv6':
            self.tabView.update_analyzer(self.analyzer)
            p = Thread(target=self.worker.query, args=[text])
            p.start()

    def quit(self):
        # save configs
        self.config.persist()
    
    def run(self):
        self.setup_geometry()
        self.bind_events()
        self.mainloop()

app = DTSToolBox()

import signal, sys
def sigint_handler(sig, frame):
    print("[i] exiting ...")
    app.quit()
    sys.exit(-1)
signal.signal(signal.SIGINT, sigint_handler)

app.run()