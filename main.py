import uuid
import customtkinter as widget
from tkinter import ttk, font
from lib.config import Config
from lib.analyzer import Analyzer
from lib.worker import DTSWorker
from lib.tkdial import Meter
from lib.CTkListbox import CTkListbox

# from lib.CTkTable import CTkTable
from iso3166 import countries
from lib.util import resource_path
from lib.structure import AbuseObject, VirusTotalObject, VTAttributes
import signal
import sys

widget.set_default_color_theme(resource_path("lib\\theme.json"))


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
            self.cbtn = widget.CTkButton(
                self,
                text="",
                width=30,
                height=20,
                image=widget.CTkImage(
                    dark_image=Image.open(resource_path("lib\\copy.png")), size=(15, 15)
                ),
            )
        if web_btn:
            self.wbtn = widget.CTkButton(
                self,
                text="",
                width=30,
                height=20,
                image=widget.CTkImage(
                    dark_image=Image.open(resource_path("lib\\web.png")), size=(15, 15)
                ),
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


class DTSHistory(widget.CTkScrollableFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.list = CTkListbox(self)
        self.list.grid(
            row=0, column=0, padx=4, pady=4, columnspan=1, rowspan=1, sticky="SWEN"
        )

    def append(self, target):
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
        self.label.configure(text="VirusTotal Report")
        self.rateMeter.set(0)
        self.result.configure(message)
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
            assert isinstance(firstResult, VTAttributes)
        except IndexError:
            self.render_exception("File not found!")
            return
        except Exception:
            self.render_exception("An unknown error happened!")
            return

        magic = firstResult.magic
        names = firstResult.names
        lastAnalysis = firstResult.last_analysis_stats
        self.rateMeter.set(
            lastAnalysis.malicious
            * 100
            / (lastAnalysis.malicious + lastAnalysis.undetected)
        )
        self.result.configure(
            text=f"The file was marked by {lastAnalysis.malicious}/{lastAnalysis.malicious + lastAnalysis.undetected} vendors as malicious"
        )
        self.knownNames.set("Known names", ", ".join(names[:3]))
        self.magicInfo.set("Magic", magic)


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


"""
        hostnames = data['hostnames']
        values = [['#', 'Hostname']]
        if hostnames != []:
            for index, h in enumerate(hostnames):
                values.append([index, h])
            print(values)
            self.hostnames.configure(values=values, rows=len(values))
            self.hostnames.grid(padx=30, pady=4)
"""


class DTSTabView(widget.CTkTabview):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.tabNames = ["Auto", "Data", "History", "Log", "Preferences"]
        self.report = None

        for name in self.tabNames:
            self.add(name)

        self.tab("Data").grid_columnconfigure(0, weight=1)
        self.tab("Data").grid_rowconfigure(0, weight=1)

        self.tab("Auto").grid_columnconfigure(0, weight=1)

        self.textBoxData = widget.CTkTextbox(
            self.tab("Data"), font=widget.CTkFont(family="Consolas", size=14)
        )
        self.textBoxData.insert("0.0", "Sorry I have nothing to show!\n" * 100)
        self.textBoxData.grid(
            row=0, column=0, padx=5, pady=5, columnspan=1, rowspan=1, sticky="SWEN"
        )

        self.tab("Log").grid_columnconfigure(0, weight=1)
        self.tab("Log").grid_rowconfigure(0, weight=1)

        self.textBoxLog = widget.CTkTextbox(self.tab("Log"))
        self.textBoxLog.insert("0.0", "Sorry I have nothing to show!\n" * 100)
        self.textBoxLog.grid(
            row=0, column=0, padx=5, pady=5, columnspan=1, rowspan=1, sticky="SWEN"
        )

    def update_history(self, target):
        pass

    def update_analyzer(self, analyzer: Analyzer):
        self.set("Auto")

    def render_from_worker(self, source, data):
        if source == "abuseipdb":
            if self.report is not None:
                self.report.destroy()
            self.textBoxData.delete("0.0", "end")
            self.textBoxData.insert("0.0", data.model_dump_json(indent=2))

            self.report = DTSAbuseIPDBReport(self.tab("Auto"))
            self.report.populate(data)
            self.report.grid(row=0, column=0, columnspan=1, rowspan=1, sticky="SWEN")

        if source == "virustotal":
            if self.report is not None:
                self.report.destroy()
            self.textBoxData.delete("0.0", "end")
            self.textBoxData.insert("0.0", data.model_dump_json(indent=2))

            self.report = DTSVirusTotalReport(self.tab("Auto"))
            self.report.populate(data)
            self.report.grid(row=0, column=0, columnspan=1, rowspan=1, sticky="SWEN")


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


class DTSPreferences(widget.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, kwargs)


class DTSToolBox(widget.CTk):
    def __init__(self):
        super().__init__()
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
            row=1, column=0, padx=10, pady=8, columnspan=1, rowspan=1, sticky="SWEN"
        )
        self.drag_id = ""

        # config
        self.config = Config()
        # analyzer
        self.analyzer = Analyzer()
        self.worker = DTSWorker(self.config, self)
        ## internal states
        self.expectingDataId: str = ""

    def clear_search_bar(self):
        self.searchBar.delete(0, len(self.searchBar.get()))

    def setup_geometry(self):
        self.minsize(640, 320)

        if self.config.get("ui", "dimension") is not None:
            self.geometry(self.config.get("ui", "dimension"))
            return
        (dx, dy) = self.config.get_dimension()
        ws = self.winfo_screenwidth()
        hs = self.winfo_screenheight()

        x = (ws) - (int(dx))
        y = (hs) - (int(dy))
        self.geometry(f"{dx}x{dy}+{x}+{y}")

    def bind_events(self):
        self.bind("<FocusIn>", self.cb_on_focus)
        self.bind("<Escape>", lambda e: self.iconify())
        self.protocol("WM_DELETE_WINDOW", self.cb_on_close)
        self.bind("<Configure>", self.cb_on_drag)
        self.button.bind("<Button-1>", self.cb_on_entry_update)
        # self.searchDropdown.bind('<FocusIn>', self.cb_on_dropdown_focus)

    def render(self, source, box):
        print(f"[+] UI has received data from {source}")
        (id, data) = box
        if id == self.expectingDataId:
            if self.analyzer.insertable:
                self.searchBar.insert(0, self.analyzer.text)
            self.tabView.render_from_worker(source, data)
        else:
            print("[+] UI has dropped the data")

    # add events to app
    def cb_on_close(self):
        self.exit_gracefully()

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
        print("[i] focused on main window")
        self.analyzer.reset()
        self.searchBar.focus()
        try:
            clipboard = self.clipboard_get().strip()
        except Exception:
            clipboard = ""
        if clipboard == self.searchBar.get() or clipboard == "":
            print("[i] nothing or nothing new to analyze")
            return
        self.analyzer.process(clipboard)
        if self.analyzer.insertable:
            self.clear_search_bar()
            # self.searchBar.insert(0, clipboard)
            self.cb_on_entry_update(event, clipboard)

    def cb_on_entry_update(self, event=None, text=""):
        if text == "":
            text = self.searchBar.get()
            self.analyzer.process(text)

        if self.analyzer.is_ip():
            self.expectingDataId = uuid.uuid4().hex
            self.tabView.update_analyzer(self.analyzer)
            self.worker.run(self.expectingDataId, ["abuseipdb"], self.analyzer.text)

        if self.analyzer.is_hash():
            self.expectingDataId = uuid.uuid4()
            self.tabView.update_analyzer(self.analyzer)
            self.worker.run(self.expectingDataId, ["virustotal"], self.analyzer.text)

    def exit_gracefully(self):
        # save configs
        self.config.persist()
        print("[i] exiting gracefully ...")
        self.destroy()
        print("hel;lo")

    def run(self):
        self.setup_geometry()
        self.bind_events()
        self.mainloop()


app = DTSToolBox()

app.run()
