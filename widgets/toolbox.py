import uuid
import customtkinter as widget
from tkinter import font
import sys
from PIL import ImageGrab
import secrets

from widgets.tabview import DTSTabView

from lib.config import DTSConfig
from lib.analyzer import DTSAnalyzer
from lib.worker import DTSWorker

from lib.util import resource_path
from lib.structure import (
    DTSInputSource,
)


class DTSToolBox(widget.CTk):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=10)

        self.roboto_bold = font.Font(
            family="Roboto", name="DTSLabelFont", size=11, weight="bold"
        )
        self.roboto_normal = font.Font(
            family="Roboto", name="DTSContentFont", size=11, weight="normal"
        )
        if sys.platform == "win32":
            self.iconbitmap(resource_path("lib/icons/icon.ico"))
        self.title("Toolbox")
        self.welcomeTexts = [
            "How are you doing today?",
            "Feeling good?",
            "Search anything!",
            "Paste me something!",
            "I'm here to help",
            "Hi there!",
            "I'm ready!",
        ]

        # add widgets to app
        self.topFrame = widget.CTkFrame(self, border_width=2)
        # self.topFrame.grid_columnconfigure(3, weight=1)
        self.topFrame.grid_columnconfigure(2, weight=1)
        self.topFrame.grid_rowconfigure(0, weight=1)
        self.navLeft = widget.CTkButton(self.topFrame, text="⮜", width=40)
        self.navRight = widget.CTkButton(self.topFrame, text="⮞", width=40)
        self.searchBar = widget.CTkEntry(
            self.topFrame,
            height=40,
            width=416,
            font=widget.CTkFont(size=16),
            placeholder_text=secrets.choice(self.welcomeTexts),
        )
        self.searchBtn = widget.CTkButton(self.topFrame, text="Lookup", width=90)

        self.navLeft.grid(row=0, column=0, padx=8, pady=10, sticky="W")
        self.navRight.grid(row=0, column=1, padx=8, pady=10, sticky="W")
        self.searchBar.grid(row=0, column=2, padx=2, pady=5, columnspan=1, sticky="WE")
        self.searchBtn.grid(row=0, column=3, padx=8, pady=10, columnspan=1, sticky="E")

        # config
        self.config = DTSConfig()

        self.tabView = DTSTabView(master=self, config=self.config)
        self.topFrame.grid(
            row=0, column=0, padx=6, pady=6, columnspan=1, rowspan=1, sticky="NEW"
        )
        self.tabView.grid(
            row=1, column=0, padx=8, pady=8, columnspan=1, rowspan=1, sticky="SWEN"
        )
        self.drag_id = ""

        # analyzer
        self.analyzer = DTSAnalyzer(self.config)
        self.worker = DTSWorker(self.config, self)
        ## internal states
        self.expectingDataId: str = ""
        self.lastImageSize = None
        self.showingNotification = False

    def clear_search_bar(self):
        self.searchBar.delete(0, "end")

    def update_search_bar(self):
        self.tabView.update_history(self.analyzer.content)
        if self.searchBar.get() == self.analyzer.text:
            return
        self.clear_search_bar()
        self.searchBar.insert(0, self.analyzer.content)

    def notify(self, message, last=2000):
        self.showingNotification = True

        def restore():
            self.title("Toolbox")
            self.showingNotification = False

        self.title(f"Toolbox ({message})")
        self.after(last, restore)

    def update_top_bar(self):
        self.update_nav()
        self.update_search_bar()

    def setup_geometry(self):
        self.minsize(640, 800)

        if self.config.get("ui", "dimension") is not None:
            self.geometry(self.config.get("ui", "dimension"))
            return

        ws = self.winfo_screenwidth()
        hs = self.winfo_screenheight()

        x = (ws / 2) - 320
        y = (hs / 2) - 400
        self.geometry(f"640x800+{int(x)}+{int(y)}")

    def bind_events(self):
        self.bind("<FocusIn>", self.cb_on_focus)
        self.bind("<Escape>", self.cb_on_escape)
        self.protocol("WM_DELETE_WINDOW", self.cb_on_close)
        self.bind("<Configure>", self.cb_on_drag)
        self.searchBtn.bind("<Button-1>", self.cb_on_entry_update)
        self.searchBar.bind("<Return>", self.cb_on_entry_update)
        # self.searchDropdown.bind('<FocusIn>', self.cb_on_dropdown_focus)

        # navigation buttons
        self.navLeft.bind("<Button-1>", self.cb_on_nav_left)
        self.navRight.bind("<Button-1>", self.cb_on_nav_right)

        # redirect stdout and stderr to log
        sys.stdout = self.tabView.textBoxLog
        sys.stderr = self.tabView.textBoxLog

    # this function should only be called from workers to deliver data to the ui
    def render(self, source, box):
        print(f"[ui] data received from {source}")
        self.tabView.stop_loading()
        (id, originalText, data) = box

        if id != self.expectingDataId:
            print("[ui] data dropped due to expiration")
        else:
            # dataId expires
            self.expectingDataId = ""
            if data is not None:
                self.tabView.history.append((source, originalText, data))
            self.tabView.render_from_worker(source, originalText, data)

    # add events to app
    def cb_on_close(self):
        self.exit_gracefully()

    def cb_on_escape(self, event):
        print(self.config.get_iconify_on_escape())
        if self.config.get_iconify_on_escape() is True:
            self.iconify()

    def cb_on_nav_left(self, event):
        previousData = self.tabView.history.nav_backward()
        if previousData is None:
            print("[ui] nothing to go backward to")
            return
        else:
            (source, originalText, data) = previousData
            self.tabView.render_from_worker(source, originalText, data)

    def cb_on_nav_right(self, event):
        previousData = self.tabView.history.nav_forward()
        if previousData is None:
            print("[ui] nothing to go forward to")
            return
        else:
            (source, originalText, data) = previousData
            self.tabView.render_from_worker(source, originalText, data)

    def cb_on_drag(self, event):
        if (
            event.widget is self
        ):  # do nothing if the event is triggered by one of root's children
            # if self.searchDropdown.winfo_viewable():
            #    self.searchDropdown.withdraw()
            if self.drag_id == "":
                # action on drag start
                pass
            else:
                # cancel scheduled call to stop_drag
                self.after_cancel(self.drag_id)
            # schedule stop_drag
            self.drag_id = self.after(100, self.__stop_drag)

    def __stop_drag(self):
        self.config.set("ui", "dimension", self.geometry())
        # reset drag_id to be able to detect the start of next dragging
        self.drag_id = ""

    def cb_on_focus(self, event):
        if event.widget != self or self.config.get_analyze_on_focus() is False:
            return

        # xclip on linux doesnt support image/png
        if sys.platform != "linux":
            clipboardImg = ImageGrab.grabclipboard()
            if (
                clipboardImg is not None
                and not isinstance(clipboardImg, list)
                and (
                    self.lastImageSize is None
                    or clipboardImg.size != self.lastImageSize
                )
            ):
                self.lastImageSize = clipboardImg.size
                self.expectingDataId = uuid.uuid4().hex

                self.tabView.start_loading()
                self.worker.run(self.expectingDataId, ["ocr"], img=clipboardImg)
                return

        try:
            clipboard = self.clipboard_get().strip()
        except Exception:
            clipboard = ""

        if clipboard == self.searchBar.get() or clipboard == "":
            print("[ui] nothing or nothing new to analyze")
            return

        self.cb_on_input_update(source=DTSInputSource.CLIPBOARD, text=clipboard)

    def cb_on_entry_update(self, event=None):
        text = self.searchBar.get().strip()
        self.cb_on_input_update(source=DTSInputSource.USER, text=text)

    def cb_on_input_update(self, source, text):
        if self.showingNotification is True:
            return

        self.analyzer.process(source, text)
        if self.analyzer.skipped:
            self.notify(self.analyzer.message)
            return

        if not self.analyzer.has_complex_data():
            self.dispatch_work()
        else:
            self.expectingDataId = uuid.uuid4().hex
            self.render(
                source="analyzer",
                box=(self.expectingDataId, self.analyzer.text, self.analyzer.dataClass),
            )

    def dispatch_work(self):
        # dispatch the work to worker
        if self.analyzer.is_internal_ip():
            self.tabView.update_from_analyzer(self.analyzer)
            self.expectingDataId = uuid.uuid4().hex
            self.worker.run(self.expectingDataId, ["rdns"], self.analyzer.content)

        elif self.analyzer.is_ip():
            self.tabView.update_from_analyzer(self.analyzer)
            self.expectingDataId = uuid.uuid4().hex
            self.worker.run(self.expectingDataId, ["abuseipdb"], self.analyzer.content)

        elif self.analyzer.is_hash() or self.analyzer.is_url():
            self.tabView.update_from_analyzer(self.analyzer)
            self.expectingDataId = uuid.uuid4().hex
            self.worker.run(self.expectingDataId, ["virustotal"], self.analyzer.content)

        elif self.analyzer.is_cve():
            self.tabView.update_from_analyzer(self.analyzer)
            self.expectingDataId = uuid.uuid4().hex
            self.worker.run(self.expectingDataId, ["cve"], self.analyzer.content)

        elif self.analyzer.is_base64():
            self.tabView.update_from_analyzer(self.analyzer)
            self.expectingDataId = uuid.uuid4().hex
            self.worker.run(self.expectingDataId, ["base64"], self.analyzer.content)

        elif self.analyzer.is_user():
            self.tabView.update_from_analyzer(self.analyzer)
            self.expectingDataId = uuid.uuid4().hex
            self.worker.run(self.expectingDataId, ["netuser"], self.analyzer.content)

        elif self.analyzer.is_pcomputer():
            self.tabView.update_from_analyzer(self.analyzer)
            self.expectingDataId = uuid.uuid4().hex
            self.worker.run(self.expectingDataId, ["dns"], self.analyzer.content)

        elif self.analyzer.is_mac():
            self.tabView.update_from_analyzer(self.analyzer)
            self.expectingDataId = uuid.uuid4().hex
            self.worker.run(self.expectingDataId, ["mac"], self.analyzer.content)

        else:
            self.notify("I could not find anything")
            self.tabView.stop_loading()

    def exit_gracefully(self):
        # save configs
        self.config.persist()
        self.tabView.textBoxLog.persist()
        print("[ui] exiting gracefully ...")
        self.destroy()

    def run(self):
        self.setup_geometry()
        self.bind_events()
        self.mainloop()
