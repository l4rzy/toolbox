import uuid
import customtkinter as widget
from tkinter import ttk, font
from lib.config import DTSConfig
from lib.analyzer import DTSAnalyzer
from lib.worker import DTSWorker
from lib.tkdial import Meter
from lib.CTkListbox import CTkListbox
from iso3166 import countries
from lib.util import resource_path, hash_str, unique
from lib.structure import (
    AbuseObject,
    VirusTotalObject,
    VTAttributes,
    NISTObject,
    DTSInputSource,
)
import signal
import sys
from PIL import Image, ImageGrab
import secrets

# for navigation
from collections import deque

VERSION_MAJOR = 0
VERSION_MINOR = 4
VERSION_PATCH = 0
VERSION_DATE = "2024 Feb 14"

widget.set_default_color_theme(resource_path("lib\\theme.json"))
widget.set_appearance_mode("dark")


def sigint_handler(sig, frame):
    app.exit_gracefully()
    sys.exit(-1)


signal.signal(signal.SIGINT, sigint_handler)


class DTSLabelWithBtn(widget.CTkFrame):
    def __init__(
        self,
        master,
        web_btn=False,
        copy_btn=True,
        analyze_btn=False,
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
        if analyze_btn:
            ianalyze = Image.open(resource_path("lib\\analyze.png"))
            self.abtn = widget.CTkButton(
                self,
                text="",
                width=30,
                height=20,
                image=widget.CTkImage(
                    dark_image=ianalyze, light_image=ianalyze, size=(15, 15)
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

    def set(self, label, content):
        self.label.configure(text=f"{label}:")
        self.content.configure(text=content)
        if self.cbtn:
            self.cbtn.grid(column=self.currentCol, row=0, padx=4, pady=4)
            self.currentCol += 1
        if self.wbtn:
            self.wbtn.grid(column=self.currentCol, row=0, padx=4, pady=4)
            self.currentCol += 1
        if self.abtn:
            self.abtn.grid(column=self.currentCol, row=0, padx=4, pady=4)
            self.currentCol += 1

    def clear(self):
        self.label.configure(text="")
        self.content.configure(text="")
        if self.cbtn:
            self.cbtn.grid_remove()
        if self.wbtn:
            self.wbtn.grid_remove()
        if self.abtn:
            self.abtn.grid_remove()


class DTSHistory(CTkListbox):
    def __init__(self, master, mainUI, **kwargs):
        super().__init__(master, command=self.cb_on_click, **kwargs)
        self.grid(
            row=0, column=0, padx=4, pady=4, columnspan=1, rowspan=1, sticky="SWEN"
        )
        self.items = {}
        self.index = 0
        self.mainUI: DTSToolBox = mainUI
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


class DTSGenericReport(widget.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)

        self.grid_columnconfigure(0, weight=1)
        # self.grid_rowconfigure(0, weight=1)
        self.title = widget.CTkLabel(
            self, text="Report", font=widget.CTkFont(size=18, weight="bold")
        )
        self.label = widget.CTkLabel(self, text="Which one should I analyze?")
        self.title.grid(row=0, column=0, padx=4, pady=4)
        self.label.grid(row=1, column=0, padx=4, pady=5)
        self.entries = []
        self.row = 2
        self.maxRow = 12
        self.reset()

    def reset(self):
        self.row = 2
        for e in self.entries:
            e.destroy()

        self.entries = []

    def populate(self, data, correction=False):
        if correction is True:
            self.label.configure(text="Did you mean?")
        for type in data:
            uniqueData = unique(data[type])
            for entry in uniqueData:
                if self.row == self.maxRow:
                    print("[greport] max row reached, aborting ...")
                    return
                e = DTSLabelWithBtn(self, copy_btn=True, analyze_btn=True)
                e.set(label=type, content=entry)
                e.grid(row=self.row, column=0, padx=4, pady=10)
                self.entries.append(e)
                self.row += 1


class DTSVirusTotalReport(widget.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)

        self.grid_columnconfigure(0, weight=1)
        # self.grid_rowconfigure(0, weight=1)

        self.title = widget.CTkLabel(
            self, justify="center", font=widget.CTkFont(size=18, weight="bold")
        )
        self.label = widget.CTkLabel(
            self, justify="center", font=widget.CTkFont(size=14)
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
        self.signature = DTSLabelWithBtn(self, web_btn=False, copy_btn=False)

    def render_exception(self, message):
        self.rateMeter.set(0)
        self.result.configure(text=message)
        self.label.configure(text="Error happened!")
        self.knownNames.grid_remove()
        self.magicInfo.grid_remove()
        self.signature.grid_remove()

    def populate(self, data: VirusTotalObject):
        self.title.grid(row=0, column=0, padx=4, pady=4)
        self.label.grid(row=1, column=0, padx=4, pady=2)
        self.rateMeter.grid(row=2, column=0, padx=10, pady=20)
        self.result.grid(row=3, column=0, padx=4, pady=2)
        self.knownNames.grid(row=4, column=0, padx=4, pady=2)
        self.magicInfo.grid(row=5, column=0, padx=4, pady=2)
        self.signature.grid(row=6, column=0, padx=4, pady=2)

        self.title.configure(text="VirusTotal Report")
        try:
            firstResult = data.data[0].attributes
            firstResultType = data.data[0].type
            self.label.configure(text=f"for {data.data[0].type}: {data.data[0].id}")
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
            signature = firstResult.signature_info

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
                "Known names", ", ".join(names[:3]) if names is not None else "_"
            )
            self.magicInfo.set("Magic", magic)
            self.signature.set(
                "Signed binary",
                content=f"Signed by {signature.signers} on {signature.signing_date if signature.signing_date is not None else 'date unknown'}"
                if (signature is not None and signature.verified is not None)
                else "No",
            )

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
            self.signature.grid_remove()
        else:
            self.render_exception(
                f"Unknown VirusTotal result type of `{firstResultType}`"
            )


class DTSAbuseIPDBReport(widget.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)

        self.grid_columnconfigure(0, weight=1)
        # self.grid_rowconfigure(0, weight=1)

        self.title = widget.CTkLabel(
            self, justify="center", font=widget.CTkFont(size=18, weight="bold")
        )
        self.label = widget.CTkLabel(
            self, justify="center", font=widget.CTkFont(size=14)
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
        self.title.grid(row=0, column=0, padx=4, pady=4)
        self.label.grid(row=1, column=0, padx=4, pady=2)
        self.rateMeter.grid(row=2, column=0, padx=10, pady=20)
        self.result.grid(row=3, column=0, padx=4, pady=2)
        self.isp.grid(row=4, column=0)
        self.usageType.grid(row=5, column=0)
        self.domain.grid(row=6, column=0)
        self.country.grid(row=7, column=0)

        self.title.configure(text="AbuseIPDB Report")
        self.label.configure(text=f"for {data.data.ipAddress}")
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


class DTSNISTCVEReport(widget.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(5, weight=1)

        self.title = widget.CTkLabel(
            self, justify="center", font=widget.CTkFont(size=18, weight="bold")
        )
        self.label = widget.CTkLabel(
            self, justify="center", font=widget.CTkFont(size=14)
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

        self.desc = DTSLabelWithBtn(self, copy_btn=False, max_width=500)
        self.metrics = widget.CTkTextbox(
            self, font=widget.CTkFont(family="Consolas", size=14)
        )

    def clear(self):
        self.metrics.delete("0.0", "end")

    def render_exception(self, message="---"):
        self.rateMeter.set(0)
        self.label.configure(text="An error happened")
        self.result.configure(text=message)
        self.desc.grid_remove()
        self.metrics.grid_remove()

    def populate(self, data: NISTObject):
        self.clear()
        self.title.grid(row=0, column=0, padx=4, pady=4)
        self.label.grid(row=1, column=0, padx=4, pady=2)
        self.rateMeter.grid(row=2, column=0, padx=10, pady=20)
        self.result.grid(row=3, column=0, padx=4, pady=2)
        self.desc.grid(row=4, column=0, padx=30, pady=10, sticky="NSEW")
        self.metrics.grid(
            row=5, column=0, padx=6, pady=10, columnspan=1, rowspan=1, sticky="NSEW"
        )

        self.title.configure(text="NIST's CVE Report")

        if data.vulnerabilities == [] or data.vulnerabilities is None:
            self.render_exception("CVE not found!")
            return

        try:
            firstCve = data.vulnerabilities[0].cve
            self.label.configure(text=f"for {firstCve.id}")
            self.result.configure(text=f"Published on {firstCve.published}")

            desc = firstCve.descriptions[0].value
            if len(desc) > 450:
                shortDesc = desc[:450]
                if ". " in shortDesc:
                    shortDesc = shortDesc[: shortDesc.rfind(". ")]
                else:
                    shortDesc += " ..."
            else:
                shortDesc = desc

            self.desc.set("Desc", shortDesc)
            if firstCve.metrics.cvssMetricV31 is not None:
                cvss = firstCve.metrics.cvssMetricV31[0].cvssData
            elif firstCve.metrics.cvssMetricV2 is not None:
                cvss = firstCve.metrics.cvssMetricV2[0].cvssData
            else:
                self.rateMeter.set(0)
                self.metrics.insert("0.0", "Metrics not found!")
                return

            self.rateMeter.set(int(cvss.baseScore * 10))
            self.metrics.insert("0.0", cvss.model_dump_json(indent=2))

        except Exception as e:
            print(e)
            self.render_exception()


class DTSTextReport(widget.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        self.title = widget.CTkLabel(
            self, justify="center", font=widget.CTkFont(size=18, weight="bold")
        )
        self.btnFrame = widget.CTkFrame(self)
        self.btnFrame.grid_rowconfigure(0, weight=1)

        i = Image.open(resource_path("lib\\copy.png"))
        self.copyBtn = widget.CTkButton(
            self.btnFrame,
            text="Copy",
            width=30,
            height=20,
            image=widget.CTkImage(dark_image=i, light_image=i, size=(15, 15)),
        )
        ia = Image.open(resource_path("lib\\analyze.png"))
        self.analyzeBtn = widget.CTkButton(
            self.btnFrame,
            text="Analyze",
            width=30,
            height=20,
            image=widget.CTkImage(dark_image=ia, light_image=ia, size=(15, 15)),
        )
        self.textContent = widget.CTkTextbox(
            self, font=widget.CTkFont(family="Consolas", size=14)
        )

        self.title.grid(row=0, column=0, padx=4, pady=4, sticky="N")
        self.copyBtn.grid(row=0, column=0, padx=20, pady=5)
        self.analyzeBtn.grid(row=0, column=1, padx=20, pady=5)
        self.btnFrame.grid(row=1, column=0, padx=20, pady=10, sticky="N")
        self.textContent.grid(row=2, column=0, padx=5, pady=5, rowspan=2, sticky="EWNS")

        self.copyBtn.bind("<Button-1>", command=self.cb_on_copy)
        self.analyzeBtn.bind("<Button-1>", command=self.cb_on_analyze)

    def cb_on_copy(self, event):
        self.clipboard_clear()
        self.clipboard_append(self.textContent.get("0.0", "end"))
        self.master.master.master.notify("Text copied")
        print("[textreport] content copied")

    def cb_on_analyze(self, event):
        self.master.master.master.cb_on_input_update(
            source=DTSInputSource.TEXT_REPORT, text=self.textContent.get("0.0", "end")
        )

    def populate(self, result: str, title="Text Report"):
        self.title.configure(text=title)
        self.clear()
        self.textContent.insert("0.0", result)

    def clear(self):
        self.textContent.delete("0.0", "end")


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


class DTSTabView(widget.CTkTabview):
    def __init__(self, master, config=None, **kwargs):
        super().__init__(master, **kwargs)
        self.tabNames = ("Report", "Data", "History", "Log", "Preferences")
        self.reports = {}
        self.lastData = 0
        self.currentReport = ""
        self.config = config

        for name in self.tabNames:
            self.add(name)

        self.loading = DTSLoading(self.tab("Report"))
        self.tab("Data").grid_columnconfigure(0, weight=1)
        self.tab("Data").grid_rowconfigure(0, weight=1)

        self.tab("Report").grid_columnconfigure(0, weight=1)
        self.tab("Report").grid_rowconfigure(0, weight=1)

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
        self.preferences.load()

        self.tab("History").grid_columnconfigure(0, weight=1)
        self.tab("History").grid_rowconfigure(0, weight=1)
        self.history = DTSHistory(self.tab("History"), self.master)
        self.history.grid(
            row=0, column=0, padx=5, pady=5, columnspan=1, rowspan=1, sticky="SWEN"
        )

        self.textBoxLog = DTSLog(
            self.tab("Log"), font=widget.CTkFont(family="Consolas", size=14)
        )
        self.textBoxLog.insert("0.0", "This is the beginning of your log\n---\n")
        self.textBoxLog.grid(
            row=0, column=0, padx=5, pady=5, columnspan=1, rowspan=1, sticky="SWEN"
        )

    def get_root_geometry(self):
        pass

    def update_history(self, target):
        self.history.append(target)

    def stop_loading(self):
        self.loading.hide()

    def show_previous_report(self):
        if self.currentReport != "":
            self.hide_other_reports(except_for=self.currentReport)

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
        self.set("Report")
        self.start_loading()

    def render_from_worker(self, source, originalText, data):
        if f"{source}-{originalText}" == self.lastData:
            print("[tabview] duplicated data, will not render again")
            self.show_previous_report()
            self.set("Report")
            return

        self.set("Report")
        # todo: factoring out common code patterns
        if source == "abuseipdb":
            if source not in self.reports:
                self.reports[source] = DTSAbuseIPDBReport(self.tab("Report"))
                self.reports[source].grid(
                    row=0, column=0, columnspan=1, rowspan=1, sticky="SWEN"
                )

            self.textBoxData.delete("0.0", "end")
            self.textBoxData.insert("0.0", data.model_dump_json(indent=2))

            self.hide_other_reports(except_for=source)
            self.reports[source].populate(data)
            self.currentReport = source

        elif source == "virustotal":
            if source not in self.reports:
                self.reports[source] = DTSVirusTotalReport(self.tab("Report"))
                self.reports[source].grid(
                    row=0, column=0, columnspan=1, rowspan=1, sticky="SWEN"
                )

            self.textBoxData.delete("0.0", "end")
            self.textBoxData.insert("0.0", data.model_dump_json(indent=2))

            self.hide_other_reports(except_for=source)
            self.reports[source].populate(data)
            self.currentReport = source

        elif source == "cve":
            if source not in self.reports:
                self.reports[source] = DTSNISTCVEReport(self.tab("Report"))
                self.reports[source].grid(
                    row=0, column=0, columnspan=1, rowspan=1, sticky="SWEN"
                )

            self.textBoxData.delete("0.0", "end")
            self.textBoxData.insert("0.0", data.model_dump_json(indent=2))

            self.hide_other_reports(except_for=source)
            self.reports[source].populate(data)
            self.currentReport = source

        elif source in ("base64", "dns", "rdns", "pcomputer", "mac", "ocr"):
            if "text" not in self.reports:
                self.reports["text"] = DTSTextReport(self.tab("Report"))
                self.reports["text"].grid(
                    row=0, column=0, columnspan=1, rowspan=1, sticky="SWEN"
                )

            title = f"Report for {source.upper()}"

            self.textBoxData.delete("0.0", "end")
            self.textBoxData.insert("0.0", "Nothing to show here ¯\_(ツ)_/¯")

            self.hide_other_reports(except_for="text")
            self.reports["text"].populate(data, title=title)
            self.currentReport = "text"

        # generic report if analyzer is not sure which item to proceed
        elif source == "analyzer":
            if source not in self.reports:
                self.reports[source] = DTSGenericReport(self.tab("Report"))
                self.reports[source].grid(
                    row=0, column=0, columnspan=1, rowspan=1, sticky="SWEN"
                )

            self.textBoxData.delete("0.0", "end")
            self.textBoxData.insert("0.0", originalText)

            self.hide_other_reports(except_for=source)
            self.reports[source].reset()
            self.reports[source].populate(data)
            self.currentReport = source

        else:
            print(f"[ui] can't render from `{source}` with data = `{data}`")

        self.lastData = f"{source}-{originalText}"


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
            text=f"DTS Toolbox - v{VERSION_MAJOR}.{VERSION_MINOR}.{VERSION_PATCH} ({VERSION_DATE})",
        )
        self.line2 = widget.CTkLabel(
            self, font=widget.CTkFont(size=14), text="Original author: Duc Lam Nguyen"
        )
        self.line3 = widget.CTkLabel(
            self,
            font=widget.CTkFont(size=12),
            text=f"Running on Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
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

        self.bind("<FocusOut>", self.cb_on_focus_out)

    def cb_on_focus_out(self, event):
        print("[about] focused out")
        # self.destroy()


class DTSPreferences(widget.CTkFrame):
    def __init__(self, master, config: DTSConfig, **kwargs):
        super().__init__(master, **kwargs)
        self.config = config
        self.aboutDialog = None

        self.grid_columnconfigure(0, weight=1)
        # self.grid_rowconfigure(0, weight=1)
        self.analyzeOnFocus = widget.CTkSwitch(
            self,
            text="Analyze clipboard on window focus",
            onvalue="true",
            offvalue="false",
            command=self.cb_on_setting_analyze_on_focus_click,
        )
        self.about = widget.CTkButton(self, text="About this program")
        self.about.grid(row=0, column=0, padx=5, pady=5)
        self.about.bind("<Button-1>", self.cb_on_btn_click)
        self.analyzeOnFocus.grid(row=1, column=0, pady=5)
        self.iconifyOnEscape = widget.CTkSwitch(
            self,
            text="Minimize window when <Esc> hit",
            onvalue="true",
            offvalue="false",
            command=self.cb_on_setting_iconify_on_escape_click,
        )
        self.iconifyOnEscape.grid(row=2, column=0, pady=5)
        self.curlDebug = widget.CTkSwitch(
            self,
            text="Show network debugging logs (program restart required)",
            onvalue="true",
            offvalue="false",
            command=self.cb_on_setting_curl_debug_click,
        )
        self.curlDebug.grid(row=3, column=0, pady=5)

    def cb_on_btn_click(self, event):
        if self.aboutDialog is None or not self.aboutDialog.winfo_exists():
            self.aboutDialog = DTSAboutDialog(self)
        self.aboutDialog.focus()

    def cb_on_setting_analyze_on_focus_click(self):
        value = self.analyzeOnFocus.get()
        self.config.set("ui", "analyze_on_focus", value)
        self.config.persist()

    def cb_on_setting_iconify_on_escape_click(self):
        value = self.iconifyOnEscape.get()
        self.config.set("ui", "iconify_on_escape", value)
        self.config.persist()

    def cb_on_setting_curl_debug_click(self):
        value = self.curlDebug.get()
        self.config.set("general", "network_debug", value)
        self.config.persist()

    def load(self):
        configAnalyzeOnFocus = self.config.get_analyze_on_focus()
        if configAnalyzeOnFocus:
            self.analyzeOnFocus.select()
        configIconifyOnEscape = self.config.get_iconify_on_escape()
        if configIconifyOnEscape:
            self.iconifyOnEscape.select()
        configCurlDebug = self.config.get_network_debug()
        if configCurlDebug:
            self.curlDebug.select()


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
        self.iconbitmap(resource_path(".\\lib\\icon.ico"))
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

    def notify(self, message, last=800):
        if self.showingNotification is True:
            return
        self.showingNotification = True
        lastSearchBar = self.searchBar.get()
        self.clear_search_bar()

        def restore():
            self.clear_search_bar()
            self.searchBar.insert(0, lastSearchBar)
            self.showingNotification = False

        self.searchBar.insert(0, message)
        self.searchBar.after(last, restore)

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
        if data is None:
            print("[ui] data is None")
            self.tabView.show_previous_report()
        elif id != self.expectingDataId:
            print("[ui] data dropped due to expiration")
        else:
            # dataId expires
            self.expectingDataId = ""
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

        clipboardImg = ImageGrab.grabclipboard()
        if (
            clipboardImg is not None
            and not isinstance(clipboardImg, list)
            and (self.lastImageSize is None or clipboardImg.size != self.lastImageSize)
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
            self.notify("I didn't find anything")
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


app = DTSToolBox()
app.run()
