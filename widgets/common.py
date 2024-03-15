from tkinter import ttk
import customtkinter as widget
from PIL import Image
from collections import deque
import secrets

from lib.CTkListbox import CTkListbox
from lib.util import resource_path, hash_str
from lib.structure import DTSInputSource


class DTSLabelWithBtn(widget.CTkFrame):
    def __init__(
        self,
        master,
        web_btn=False,
        copy_btn=True,
        analyze_btn=False,
        direct_btn=False,
        max_width=400,
        **kwargs,
    ):
        super().__init__(master, **kwargs)
        self.label = ttk.Label(
            self,
            border=2,
            font="DTSLabelFont",
            background="#292929",
            foreground="gray95",
        )
        self.content = ttk.Label(
            self,
            wraplength=max_width,
            font="DTSContentFont",
            background="#292929",
            foreground="gray95",
        )
        self.cbtn = None
        self.wbtn = None
        self.abtn = None
        self.dbtn = None

        if copy_btn:
            icpy = Image.open(resource_path("lib/icons/copy.png"))
            self.cbtn = widget.CTkButton(
                self,
                text="",
                width=30,
                height=20,
                image=widget.CTkImage(dark_image=icpy, light_image=icpy, size=(15, 15)),
            )
        if web_btn:
            iweb = Image.open(resource_path("lib/icons/web.png"))
            self.wbtn = widget.CTkButton(
                self,
                text="",
                width=30,
                height=20,
                image=widget.CTkImage(dark_image=iweb, light_image=iweb, size=(15, 15)),
            )
        if analyze_btn:
            ianalyze = Image.open(resource_path("lib/icons/analyze.png"))
            self.abtn = widget.CTkButton(
                self,
                text="",
                width=30,
                height=20,
                image=widget.CTkImage(
                    dark_image=ianalyze, light_image=ianalyze, size=(15, 15)
                ),
            )
        if direct_btn:
            idirect = Image.open(resource_path("lib/icons/direct.png"))
            self.dbtn = widget.CTkButton(
                self,
                text="",
                width=30,
                height=20,
                image=widget.CTkImage(
                    dark_image=idirect, light_image=idirect, size=(15, 15)
                ),
            )

        self.label.grid(column=0, row=0, padx=2, pady=4)
        self.content.grid(column=1, row=0, padx=2, pady=4)
        self.currentCol = 2

        if copy_btn:
            self.cbtn.bind("<Button-1>", self.cb_on_copy_btn_click)
        if web_btn:
            self.wbtn.bind("<Button-1>", self.cb_on_web_btn_click)
        if analyze_btn:
            self.abtn.bind("<Button-1>", self.cb_on_analyze_btn_click)
        if direct_btn:
            self.directLink = ""
            self.dbtn.bind("<Button-1>", self.cb_on_direct_btn_click)

    def cb_on_copy_btn_click(self, event):
        self.clipboard_clear()
        self.clipboard_append(self.content.cget("text"))

    def cb_on_web_btn_click(self, event):
        import webbrowser

        # todo: fix this
        webbrowser.open_new_tab(
            f"https://www.google.com/search?q={self.content.cget('text')}"
        )

    def cb_on_analyze_btn_click(self, event):
        # bad code, but since tkinter doesnt allow event from child to parent
        self.master.master.master.master.cb_on_input_update(
            source=DTSInputSource.GENERIC_REPORT, text=self.content.cget("text")
        )

    def cb_on_direct_btn_click(self, event):
        import webbrowser

        webbrowser.open_new_tab(self.directLink)

    def set(self, label, content, directLink=""):
        self.label.configure(text=f"{label}:")
        self.content.configure(text=content)
        if self.cbtn:
            if label != "Error":
                self.cbtn.grid(column=self.currentCol, row=0, padx=4, pady=4)
                self.currentCol += 1
            else:
                self.cbtn.grid_remove()
        if self.wbtn:
            self.wbtn.grid(column=self.currentCol, row=0, padx=4, pady=4)
            self.currentCol += 1
        if self.abtn:
            self.abtn.grid(column=self.currentCol, row=0, padx=4, pady=4)
            self.currentCol += 1
        if self.dbtn:
            if directLink != "":
                self.dbtn.grid(column=self.currentCol, row=0, padx=4, pady=4)
                self.currentCol += 1
                self.directLink = directLink
            else:
                self.dbtn.grid_remove()

    def clear(self):
        self.label.configure(text="")
        self.content.configure(text="")
        if self.cbtn:
            self.cbtn.grid_remove()
        if self.wbtn:
            self.wbtn.grid_remove()
        if self.abtn:
            self.abtn.grid_remove()
        if self.dbtn:
            self.dbtn.grid_remove()
            self.directLink = ""


class DTSButton(widget.CTkButton):
    def __init__(self, master, **kwargs):
        super().__init__(master, self.cb_on_click, **kwargs)

    def cb_on_click(self):
        pass


class DTSHistory(CTkListbox):
    def __init__(self, master, mainUI, **kwargs):
        super().__init__(master, command=self.cb_on_click, **kwargs)
        self.grid(
            row=0, column=0, padx=4, pady=4, columnspan=1, rowspan=1, sticky="SWEN"
        )
        self.items = {}
        self.index = 0
        self.mainUI = mainUI
        self.historyClick = False  # workaround

        self.navigationMax = 100
        self.navigation = deque([None] * self.navigationMax, maxlen=self.navigationMax)
        self.navigationIndex = 0

    def cb_on_click(self, item):
        self.historyClick = True
        itemHash = hash_str(item)
        # find if it exists in navigation cache
        for nv in self.navigation:
            (_, nvHash) = self.make_hash(nv)
            if itemHash == nvHash:
                print(f"[history] {item} exists in navigation cache")
                self.historyClick = False
                (source, originalText, data) = nv
                self.mainUI.tabView.render_from_worker(source, originalText, data)
                return

        originalText = self.items[hash_str(item)]
        self.mainUI.cb_on_input_update(source="history", text=originalText)
        self.historyClick = False

    def make_hash(self, data):
        if data is None:
            return ("-", "-")
        type = data[0] if data[0] != "analyzer" else "ocr"
        hashStr = f"{type}: {data[1][:50]}"
        return (hashStr, hash_str(hashStr))

    def append(self, data):
        # don't save generic report to history, but save to navigation
        if not self.historyClick and data[0] != "analyzer":
            (hashStr, hashStrDigest) = self.make_hash(data)

            self.insert(self.index, hashStr)
            self.items[hashStrDigest] = data[1]
            self.index += 1

        # check if the lastest item in navigation is equal to new data
        if self.navigation[self.navigationIndex] == data:
            return

        if self.navigationIndex == 0 and self.navigation[self.navigationIndex] is None:
            self.navigation[0] = data
        elif self.navigationIndex == self.navigationMax - 1:
            self.navigation.append(data)
        else:
            self.navigationIndex += 1
            self.navigation[self.navigationIndex] = data

            for i in range(self.navigationIndex + 1, self.navigationMax):
                self.navigation[i] = None

    # called before switching to next view
    def nav_forward(self):
        if (
            self.navigationIndex < self.navigationMax - 1
            and self.navigation[self.navigationIndex + 1] is not None
        ):
            self.navigationIndex += 1
            return self.navigation[self.navigationIndex]
        else:
            return None

    def nav_backward(self):
        if self.navigationIndex > 0:
            self.navigationIndex -= 1
            return self.navigation[self.navigationIndex]
        else:
            return None


class DTSLoading(widget.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.grid_columnconfigure(0, weight=1)
        # self.grid_rowconfigure(0, weight=1)

        self.loadingText = (
            "Loading",
            "Fetching",
            "Thinking",
            "Hang in there",
            "Establishing network connection",
            "Let's see",
        )

        self.loading = widget.CTkLabel(
            self,
            text=f"{secrets.choice(self.loadingText)} ...",
            font=widget.CTkFont(size=18),
        )

        self.loading.grid(
            row=0, column=0, padx=5, pady=20, columnspan=1, rowspan=1, sticky="SWEN"
        )

    def hide(self):
        self.grid_forget()

    def show(self):
        self.loading.configure(text=f"{secrets.choice(self.loadingText)} ...")
        self.grid(
            row=0, column=0, padx=5, pady=10, columnspan=1, rowspan=1, sticky="SWEN"
        )


class DTSLog(widget.CTkTextbox):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)

    def write(self, text):
        self.insert("end", text)

    def flush(self):
        pass

    def persist(self, fname="log.txt"):
        with open(fname, "wt+") as f:
            f.write(self.get("0.0", "end"))
            print(f"[log] wrote to disk as {fname}")
