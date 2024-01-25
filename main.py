import uuid
import customtkinter as widget
from tkinter import ttk, font
from lib.config import DTSConfig
from lib.analyzer import DTSAnalyzer
from lib.worker import DTSWorker
from lib.tkdial import Meter
from lib.CTkListbox import CTkListbox
from iso3166 import countries
from lib.util import resource_path
from lib.structure import AbuseObject, VirusTotalObject, VTAttributes
import signal
import sys

VERSION_MAJOR = 0
VERSION_MINOR = 1
VERSION_PATCH = 3

widget.set_default_color_theme(resource_path("lib\\theme.json"))
widget.set_appearance_mode("dark")


def sigint_handler(sig, frame):
    app.exit_gracefully()
    sys.exit(-1)


signal.signal(signal.SIGINT, sigint_handler)


class DTSLabelWithBtn(widget.CTkFrame):
    def __init__(self, master, web_btn=False, copy_btn=True, max_width=400, **kwargs):
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
        from PIL import Image

        if copy_btn:
            icpy = Image.open(resource_path("lib\\copy.png"))
            self.cbtn = widget.CTkButton(
                self,
                text="",
                width=30,
                height=20,
                image=widget.CTkImage(dark_image=icpy, light_image=icpy, size=(15, 15)),
            )
        if web_btn:
            iweb = Image.open(resource_path("lib\\web.png"))
            self.wbtn = widget.CTkButton(
                self,
                text="",
                width=30,
                height=20,
                image=widget.CTkImage(dark_image=iweb, light_image=iweb, size=(15, 15)),
            )

        self.label.grid(column=0, row=0, padx=2, pady=4)
        self.content.grid(column=1, row=0, padx=2, pady=4)
        self.currentCol = 2

        if copy_btn:
            self.cbtn.bind("<Button-1>", self.cb_on_copy_btn_click)
        if web_btn:
            self.wbtn.bind("<Button-1>", self.cb_on_web_btn_click)

    def cb_on_copy_btn_click(self, event):
        self.clipboard_clear()
        self.clipboard_append(self.content.cget("text"))

    def cb_on_web_btn_click(self, event):
        import webbrowser
        import urllib.parse

        webbrowser.open_new_tab(
            urllib.parse.quote(f"https://www.google.com/search?q={self.content}")
        )

    def set(self, label, content):
        self.label.configure(text=f"{label}:")
        self.content.configure(text=content)
        if self.cbtn:
            self.cbtn.grid(column=self.currentCol, row=0, padx=4, pady=4)
            self.currentCol += 1
        if self.wbtn:
            self.wbtn.grid(column=self.currentCol, row=0, padx=4, pady=4)
            self.currentCol += 1

    def clear(self):
        self.label.configure(text="")
        self.content.configure(text="")
        if self.cbtn:
            self.cbtn.grid_remove()
        if self.wbtn:
            self.wbtn.grid_remove()


class DTSHistory(CTkListbox):
    def __init__(self, master, mainUI, **kwargs):
        super().__init__(master, command=self.cb_on_click, **kwargs)
        self.grid(
            row=0, column=0, padx=4, pady=4, columnspan=1, rowspan=1, sticky="SWEN"
        )
        self.currentPos = 0
        self.mainUI: DTSToolBox = mainUI
        self.historyClick = False  # workaround

    def cb_on_click(self, item):
        self.historyClick = True
        self.mainUI.cb_on_entry_update(text=item)
        self.historyClick = False

    def append(self, target):
        if self.historyClick:
            return
        self.insert(self.currentPos, target)
        self.currentPos += 1


class DTSGenericReport(widget.CTkFrame):
    pass


class DTSVirusTotalReport(widget.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.label = widget.CTkLabel(
            self, justify="center", font=widget.CTkFont(size=18, weight="bold")
        )
        self.result = widget.CTkLabel(self, justify="center")
        self.rateMeter = Meter(
            self,
            radius=200,
            start=0,
            end=100,
            border_width=5,
            bg="#212121",
            fg="gray35",
            text_color="white",
            start_angle=180,
            end_angle=-270,
            scale_color="black",
            axis_color="white",
            needle_color="white",
            state="static",
            scroll=False,
        )
        self.rateMeter.set_mark(0, 24, "green")
        self.rateMeter.set_mark(25, 50, "yellow")
        self.rateMeter.set_mark(51, 75, "orange")
        self.rateMeter.set_mark(76, 100, "red")

        self.knownNames = DTSLabelWithBtn(self, web_btn=False, copy_btn=False)
        self.magicInfo = DTSLabelWithBtn(self, web_btn=False, copy_btn=False)

    def render_exception(self, message):
        self.rateMeter.set(0)
        self.result.configure(text=message)
        self.knownNames.grid_remove()
        self.magicInfo.grid_remove()

    def populate(self, data: VirusTotalObject):
        self.label.grid(row=0, column=0, padx=4, pady=2)
        self.rateMeter.grid(row=1, column=0, padx=10, pady=20)
        self.result.grid(row=2, column=0, padx=4, pady=2)
        self.knownNames.grid(row=3, column=0, padx=4, pady=2)
        self.magicInfo.grid(row=4, column=0, padx=4, pady=2)

        self.label.configure(text="VirusTotal Report")
        try:
            firstResult = data.data[0].attributes
            firstResultType = data.data[0].type
            assert isinstance(firstResult, VTAttributes)
        except IndexError:
            self.render_exception("Resource not found on VirusTotal!")
            return
        except Exception:
            self.render_exception("An unknown error happened!")
            return

        lastAnalysis = firstResult.last_analysis_stats
        if firstResultType == "file":
            magic = firstResult.magic
            names = firstResult.names
            totalVendors = (
                lastAnalysis.malicious
                + lastAnalysis.undetected
                + lastAnalysis.harmless
                + lastAnalysis.suspicious
            )
            self.rateMeter.set(lastAnalysis.malicious * 100 / totalVendors)
            self.result.configure(
                text=f"The {firstResultType} was marked by {lastAnalysis.malicious}/{totalVendors} vendors as malicious"
            )

            self.knownNames.set("Known names", ", ".join(names[:3]) if names is not None else "_")
            self.magicInfo.set("Magic", magic)

        elif firstResultType in ("domain", "url"):
            totalVendors = (
                lastAnalysis.malicious
                + lastAnalysis.undetected
                + lastAnalysis.harmless
                + lastAnalysis.suspicious
            )
            self.rateMeter.set(lastAnalysis.malicious * 100 / totalVendors)
            self.result.configure(
                text=f"The {firstResultType} was marked by {lastAnalysis.malicious}/{totalVendors} vendors as malicious"
            )
            self.knownNames.set(
                "Reputation",
                f"{firstResult.reputation if firstResult.reputation is not None else ''}",
            )
            self.magicInfo.grid_remove()
        else:
            self.render_exception(
                f"Unknown VirusTotal result type of `{firstResultType}`"
            )


class DTSAbuseIPDBReport(widget.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.label = widget.CTkLabel(
            self, justify="center", font=widget.CTkFont(size=18, weight="bold")
        )
        self.result = widget.CTkLabel(self, justify="center")
        self.rateMeter = Meter(
            self,
            radius=200,
            start=0,
            end=100,
            border_width=5,
            bg="#212121",
            fg="gray35",
            text_color="white",
            start_angle=180,
            end_angle=-270,
            scale_color="black",
            axis_color="white",
            needle_color="white",
            state="static",
            scroll=False,
        )
        self.rateMeter.set_mark(0, 24, "green")
        self.rateMeter.set_mark(25, 50, "yellow")
        self.rateMeter.set_mark(51, 75, "orange")
        self.rateMeter.set_mark(76, 100, "red")

        self.isp = DTSLabelWithBtn(self)
        self.usageType = DTSLabelWithBtn(self)
        self.country = DTSLabelWithBtn(self)
        self.domain = DTSLabelWithBtn(self, web_btn=True)
        # self.hostnames = CTkTable(self, column=2)

    def populate(self, data: AbuseObject):
        self.label.grid(row=0, column=0, padx=4, pady=2)
        self.rateMeter.grid(row=1, column=0, padx=10, pady=20)
        self.result.grid(row=2, column=0, padx=4, pady=2)
        self.isp.grid(row=3, column=0)
        self.usageType.grid(row=4, column=0)
        self.domain.grid(row=5, column=0)
        self.country.grid(row=6, column=0)

        self.label.configure(text=f"Result for {data.data.ipAddress}")
        if not data.data.isPublic:
            self.result.configure(text="This IP is a private IP")
            self.rateMeter.set(data.data.abuseConfidenceScore)
            self.domain.grid_remove()
            self.isp.grid_remove()
            self.usageType.grid_remove()
            self.country.grid_remove()
            # self.hostnames.grid_remove()
            return

        self.result.configure(
            text=f'This IP was reported {data.data.totalReports} time{"" if data.data.totalReports in [0,1] else "s"}, confidence of abuse is {data.data.abuseConfidenceScore}%'
        )
        self.rateMeter.set(data.data.abuseConfidenceScore)
        self.isp.set("ISP", data.data.isp)
        self.usageType.set("Usage type", data.data.usageType)
        self.domain.set("Domain", data.data.domain)
        if data.data.countryCode != "null":
            country = countries.get(data.data.countryCode)
            self.country.set("Country", f"{country.name}")


##
class DTSIPReport(widget.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.abuseIPDB = DTSAbuseIPDBReport(self)


class DTSTextReport(widget.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        from PIL import Image

        i = Image.open(resource_path("lib\\copy.png"))
        self.copyBtn = widget.CTkButton(
            self,
            text="Copy",
            width=30,
            height=20,
            image=widget.CTkImage(dark_image=i, light_image=i, size=(15, 15)),
        )
        self.textContent = widget.CTkTextbox(
            self, font=widget.CTkFont(family="Consolas", size=14)
        )

        self.copyBtn.bind("<Button-1>", command=self.cb_on_copy)

    def cb_on_copy(self, event):
        self.clipboard_clear()
        self.clipboard_append(self.textContent.get("0.0", "end"))
        print("[base64report] decoded content copied")

    def populate(self, result: str):
        self.copyBtn.grid(row=0, column=0, padx=20, pady=10)
        self.textContent.grid(
            row=1, column=0, padx=5, pady=10, columnspan=1, rowspan=1, sticky="SWEN"
        )
        self.clear()
        self.textContent.insert("0.0", result)

    def clear(self):
        self.textContent.delete("0.0", "end")


class DTSLoading(widget.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.loading = widget.CTkLabel(
            self, text="Loading ...", font=widget.CTkFont(size=18)
        )

        self.loading.grid(
            row=0, column=0, padx=5, pady=20, columnspan=1, rowspan=1, sticky="SWEN"
        )

    def hide(self):
        self.grid_forget()

    def show(self):
        self.grid(
            row=0, column=0, padx=5, pady=10, columnspan=1, rowspan=1, sticky="SWEN"
        )


class DTSTabView(widget.CTkTabview):
    def __init__(self, master, config=None, **kwargs):
        super().__init__(master, **kwargs)
        self.tabNames = ["Auto", "Data", "History", "Log", "Preferences"]
        self.reports = {}
        self.reportShowing = ""
        self.config = config

        for name in self.tabNames:
            self.add(name)

        self.loading = DTSLoading(self.tab("Auto"))
        self.tab("Data").grid_columnconfigure(0, weight=1)
        self.tab("Data").grid_rowconfigure(0, weight=1)

        self.tab("Auto").grid_columnconfigure(0, weight=1)

        self.textBoxData = widget.CTkTextbox(
            self.tab("Data"), font=widget.CTkFont(family="Consolas", size=14)
        )
        self.textBoxData.insert("0.0", "Waiting for your requests!\n" * 10)
        self.textBoxData.grid(
            row=0, column=0, padx=5, pady=5, columnspan=1, rowspan=1, sticky="SWEN"
        )

        self.tab("Log").grid_columnconfigure(0, weight=1)
        self.tab("Log").grid_rowconfigure(0, weight=1)

        self.tab("Preferences").grid_columnconfigure(0, weight=1)
        self.tab("Preferences").grid_rowconfigure(0, weight=1)
        self.preferences = DTSPreferences(self.tab("Preferences"), config=self.config)
        self.preferences.grid(
            row=0, column=0, padx=5, pady=5, columnspan=1, rowspan=1, sticky="SWEN"
        )

        self.tab("History").grid_columnconfigure(0, weight=1)
        self.tab("History").grid_rowconfigure(0, weight=1)
        self.history = DTSHistory(self.tab("History"), self.master)
        self.history.grid(
            row=0, column=0, padx=5, pady=5, columnspan=1, rowspan=1, sticky="SWEN"
        )

        self.textBoxLog = widget.CTkTextbox(
            self.tab("Log"), font=widget.CTkFont(family="Consolas", size=14)
        )
        self.textBoxLog.insert("0.0", "I have nothing to show right now ¯\_(ツ)_/¯")
        self.textBoxLog.grid(
            row=0, column=0, padx=5, pady=5, columnspan=1, rowspan=1, sticky="SWEN"
        )

    def get_root_geometry(self):
        pass

    def update_history(self, target):
        self.history.append(target)

    def stop_loading(self):
        self.loading.hide()

    def start_loading(self):
        # hide other widgets
        self.hide_other_reports(except_for=None)  # this will hide all reports
        self.loading.show()

    def hide_other_reports(self, except_for: str):
        for r in self.reports:
            if r != except_for:
                self.reports[r].grid_remove()

        if except_for is None:
            return
        self.reports[except_for].grid(
            row=0, column=0, columnspan=1, rowspan=1, sticky="SWEN"
        )

    def update_from_analyzer(self, analyzer: DTSAnalyzer):
        self.set("Auto")
        self.start_loading()

    def render_from_worker(self, source, data):
        self.stop_loading()
        # todo: factoring out common code patterns
        if source == "abuseipdb":
            if source not in self.reports:
                self.reports[source] = DTSAbuseIPDBReport(self.tab("Auto"))
                self.reports[source].grid(
                    row=0, column=0, columnspan=1, rowspan=1, sticky="SWEN"
                )

            self.textBoxData.delete("0.0", "end")
            self.textBoxData.insert("0.0", data.model_dump_json(indent=2))

            self.hide_other_reports(except_for=source)
            self.reports[source].populate(data)
            self.reportShowing = source

        elif source == "virustotal":
            if source not in self.reports:
                self.reports[source] = DTSVirusTotalReport(self.tab("Auto"))
                self.reports[source].grid(
                    row=0, column=0, columnspan=1, rowspan=1, sticky="SWEN"
                )

            self.textBoxData.delete("0.0", "end")
            self.textBoxData.insert("0.0", data.model_dump_json(indent=2))

            self.hide_other_reports(except_for=source)
            self.reports[source].populate(data)
            self.reportShowing = source

        elif source in ("base64", "dns", "rdns", "pcomputer", "mac", "localip"):
            if source not in self.reports:
                self.reports[source] = DTSTextReport(self.tab("Auto"))
                self.reports[source].grid(
                    row=0, column=0, columnspan=1, rowspan=1, sticky="SWEN"
                )

            self.textBoxData.delete("0.0", "end")
            self.textBoxData.insert("0.0", "Nothing to show here ¯\_(ツ)_/¯")

            self.hide_other_reports(except_for=source)
            self.reports[source].populate(data)
            self.reportShowing = source

        else:
            print(f"[ui] can't render from `{source}` with data = `{data}`")


"""     
        DATA = {
            "Data": [
                {"Name": "Tom", "Rollno": 1, "Marks": 50},
                {"Name": "Tim", "Rollno": 2, "Marks": 40},
                {"Name": "Jim", "Rollno": 3, "Marks": 60}
            ]
        }

        treeview = ttk.Treeview(self.tab('History'), show="headings", columns=("Name", "Rollno", "Marks"))
        treeview.heading("#1", text="Name")
        treeview.heading("#2", text="Rollno")
        treeview.heading("#3", text="Marks")
        treeview.grid()

        for row in DATA["Data"]:
            treeview.insert("", "end", values=(row["Name"], row["Rollno"], row["Marks"]))
"""


class DTSPreferencesGeneral(widget.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)


class DTSAboutDialog(widget.CTkToplevel):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        sh = self.winfo_screenheight()
        sw = self.winfo_screenwidth()
        self.geometry(f"400x300+{int(sw/2-200)}+{int(sh/2-150)}")
        self.title("About")
        self.grid_columnconfigure(0, weight=1)

        from PIL import Image

        i = Image.open(resource_path("lib\\icon.png"))
        image = widget.CTkImage(light_image=i, dark_image=i, size=(150, 150))
        self.logo = widget.CTkLabel(self, image=image, text="")
        self.line1 = widget.CTkLabel(
            self,
            font=widget.CTkFont(size=18),
            text=f"DTS Toolbox - version {VERSION_MAJOR}.{VERSION_MINOR}.{VERSION_PATCH}",
        )
        self.line2 = widget.CTkLabel(
            self, font=widget.CTkFont(size=14), text="Original author: Duc Lam Nguyen"
        )
        self.line3 = widget.CTkLabel(
            self,
            font=widget.CTkFont(size=12),
            text="Unlicensed, but free to use and modify",
        )

        self.logo.grid(
            row=0, column=0, padx=10, pady=10, columnspan=1, rowspan=1, sticky="SWEN"
        )
        self.line1.grid(
            row=1, column=0, padx=10, pady=8, columnspan=1, rowspan=1, sticky="SWEN"
        )
        self.line2.grid(
            row=2, column=0, padx=10, pady=4, columnspan=1, rowspan=1, sticky="SWEN"
        )
        self.line3.grid(
            row=3, column=0, padx=10, pady=2, columnspan=1, rowspan=1, sticky="SWEN"
        )

        self.focus()
        self.bind("<FocusOut>", self.cb_on_focus_out)

    def cb_on_focus_out(self, event):
        print("[about] focused out")
        # self.destroy()


class DTSPreferences(widget.CTkFrame):
    def __init__(self, master, config, **kwargs):
        super().__init__(master, **kwargs)
        self.config = config
        self.aboutDialog = None

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.about = widget.CTkButton(self, text="About this program")
        self.about.grid(row=0, column=0, padx=5, pady=5)
        self.about.bind("<Button-1>", self.cb_on_btn_click)

    def cb_on_btn_click(self, event):
        if self.aboutDialog is None or not self.aboutDialog.winfo_exists():
            self.aboutDialog = DTSAboutDialog(self)
        self.aboutDialog.focus()

    def load(self):
        pass

    def get_root_geometry(self):
        return self.master.get_root_geometry()


class DTSToolBox(widget.CTk):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=10)

        self.roboto_bold = font.Font(
            family="Roboto", name="DTSLabelFont", size=10, weight="bold"
        )
        self.roboto_normal = font.Font(
            family="Roboto", name="DTSContentFount", size=10, weight="normal"
        )
        self.iconbitmap(resource_path(".\\lib\\icon.ico"))
        self.title("Toolbox")

        # add widgets to app
        self.topFrame = widget.CTkFrame(self, border_width=2)
        self.searchBar = widget.CTkEntry(
            self.topFrame, height=40, width=458, font=widget.CTkFont(size=16)
        )
        # self.searchDropdown = CTkScrollableDropdown(self.searchBar, values=['1.1.1.1', '170.238.160.191', '192.168.1.1', '2607:f8b0:4009:80a::200e'],
        #                                            command=self.cb_on_search_dropdown_click, autocomplete=False, button_height=30, double_click=True, )
        self.button = widget.CTkButton(self.topFrame, text="Lookup")
        self.searchBar.grid(row=0, column=0, padx=5, pady=5, sticky="NEW")
        self.button.grid(row=0, column=1, padx=10, pady=10, sticky="ENS")

        self.tabView = DTSTabView(master=self)
        self.topFrame.grid(
            row=0, column=0, padx=6, pady=6, columnspan=1, rowspan=1, sticky="NEW"
        )
        self.tabView.grid(
            row=1, column=0, padx=8, pady=8, columnspan=1, rowspan=1, sticky="SWEN"
        )
        self.drag_id = ""

        # config
        self.config = DTSConfig()
        # analyzer
        self.analyzer = DTSAnalyzer(self.config)
        self.worker = DTSWorker(self.config, self)
        ## internal states
        self.expectingDataId: str = ""

    def clear_search_bar(self):
        self.searchBar.delete(0, len(self.searchBar.get()))

    def set_search_bar(self):
        self.tabView.update_history(self.analyzer.text)
        if self.searchBar.get() == self.analyzer.text:
            return
        self.clear_search_bar()
        self.searchBar.insert(0, self.analyzer.text)

    def setup_geometry(self):
        self.minsize(640, 320)

        if self.config.get("ui", "dimension") is not None:
            self.geometry(self.config.get("ui", "dimension"))
            return

        ws = self.winfo_screenwidth()
        hs = self.winfo_screenheight()

        x = (ws / 2) - 320
        y = (hs / 2) - 160
        self.geometry(f"640x320+{int(x)}+{int(y)}")

    def bind_events(self):
        self.bind("<FocusIn>", self.cb_on_focus)
        if self.config.get_iconify_on_escape() is True:
            self.bind("<Escape>", lambda e: self.iconify())
        self.protocol("WM_DELETE_WINDOW", self.cb_on_close)
        self.bind("<Configure>", self.cb_on_drag)
        self.button.bind("<Button-1>", self.cb_on_entry_update)
        self.searchBar.bind("<Return>", self.cb_on_entry_update)
        # self.searchDropdown.bind('<FocusIn>', self.cb_on_dropdown_focus)

    # this function should only be called from workers to deliver data to the ui
    def render(self, source, box):
        print(f"[ui] data received from {source}")
        (id, data) = box
        if id == self.expectingDataId:
            if self.analyzer.insertable:
                self.set_search_bar()
            self.tabView.render_from_worker(source, data)
        else:
            print("[ui] data dropped due to expiration")

    # add events to app
    def cb_on_close(self):
        self.exit_gracefully()

    # unused since dropdown focus bug
    def cb_on_search_dropdown_click(self, text):
        self.clear_search_bar()
        self.searchBar.insert(0, text)
        self.dropdownFocus = False
        self.cb_on_entry_update()

    def cb_on_dropdown_focus(self, event):
        if event.widget == self.searchDropdown:
            print("[+] focused on dropdown")
            self.dropdownFocus = True

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
        if event.widget != self or self.config.get("ui", "analyze_on_focus") == "0":
            return

        try:
            clipboard = self.clipboard_get().strip()
        except Exception:
            clipboard = ""

        if clipboard == self.searchBar.get() or clipboard == "":
            print("[ui] nothing or nothing new to analyze")
            return

        self.cb_on_entry_update(event, text=clipboard)

    def cb_on_entry_update(self, event=None, text=""):
        if text == "":
            text = self.searchBar.get().strip()
        self.analyzer.process(text)

        # dispatch the work to worker
        if self.analyzer.is_internal_ip():
            self.tabView.update_from_analyzer(self.analyzer)
            self.expectingDataId = uuid.uuid4().hex
            self.worker.run(self.expectingDataId, ["localip"], self.analyzer.text)

        elif self.analyzer.is_ip():
            self.tabView.update_from_analyzer(self.analyzer)
            self.expectingDataId = uuid.uuid4().hex
            self.worker.run(self.expectingDataId, ["abuseipdb"], self.analyzer.text)

        elif self.analyzer.is_hash() or self.analyzer.is_url():
            self.tabView.update_from_analyzer(self.analyzer)
            self.expectingDataId = uuid.uuid4().hex
            self.worker.run(self.expectingDataId, ["virustotal"], self.analyzer.text)

        elif self.analyzer.is_base64():
            self.tabView.update_from_analyzer(self.analyzer)
            self.expectingDataId = uuid.uuid4().hex
            self.worker.run(self.expectingDataId, ["base64"], self.analyzer.text)

        elif self.analyzer.is_user():
            self.tabView.update_from_analyzer(self.analyzer)
            self.expectingDataId = uuid.uuid4().hex
            self.worker.run(self.expectingDataId, ["netuser"], self.analyzer.text)

        elif self.analyzer.is_pcomputer():
            self.tabView.update_from_analyzer(self.analyzer)
            self.expectingDataId = uuid.uuid4().hex
            self.worker.run(self.expectingDataId, ["pcomputer"], self.analyzer.text)

        elif self.analyzer.is_mac():
            self.tabView.update_from_analyzer(self.analyzer)
            self.expectingDataId = uuid.uuid4().hex
            self.worker.run(self.expectingDataId, ["mac"], self.analyzer.text)

        else:
            self.tabView.stop_loading()

    def exit_gracefully(self):
        # save configs
        self.config.persist()
        print("[ui] exiting gracefully ...")
        self.destroy()

    def run(self):
        self.setup_geometry()
        self.bind_events()
        self.mainloop()


app = DTSToolBox()
app.run()
