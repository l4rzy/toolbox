import customtkinter as widget
from lib.tkdial import Meter
from iso3166 import countries
from lib.util import resource_path, unique
from lib.structure import (
    AbuseObject,
    VirusTotalObject,
    VTAttributes,
    NISTObject,
    CirclCVEObject,
    DTSInputSource,
)

from .custom import DTSLabelWithBtn
from PIL import Image


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
        if data is None:
            return
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
        self.label.configure(text="---")
        self.knownNames.grid_remove()
        self.magicInfo.grid_remove()
        self.signature.grid_remove()

    def populate(self, data: VirusTotalObject | None):
        self.title.grid(row=0, column=0, padx=4, pady=4)
        self.label.grid(row=1, column=0, padx=4, pady=2)
        self.rateMeter.grid(row=2, column=0, padx=10, pady=20)
        self.result.grid(row=3, column=0, padx=4, pady=2)
        self.knownNames.grid(row=4, column=0, padx=4, pady=2)
        self.magicInfo.grid(row=5, column=0, padx=4, pady=2)
        self.signature.grid(row=6, column=0, padx=4, pady=2)

        self.title.configure(text="VirusTotal Report")
        if data is None:
            self.render_exception(
                "A network error happened! Check your internet settings."
            )
            return

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
        self.error = False
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

    def render_exception(self, message):
        self.title.grid(row=0, column=0, padx=4, pady=4)
        self.label.grid(row=1, column=0, padx=4, pady=2)
        self.rateMeter.grid(row=2, column=0, padx=10, pady=20)
        self.result.grid(row=3, column=0, padx=4, pady=2)

        self.title.configure(text="AbuseIPDB Report")
        self.label.configure(text="---")
        self.result.configure(text=message)
        self.error = True

    def populate(self, data: AbuseObject | None):
        if data is None:
            self.render_exception(
                "A network error happened! Check your internet settings."
            )
            self.error = True
            return
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
        self.error = False


class DTSNISTCVEReport(widget.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.error = False
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
        self.error = True

    def populate(self, data: NISTObject | None):
        self.clear()

        if data is None:
            self.render_exception(
                message="A network error happened! Check your internet settings."
            )
            self.error = True
            return

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

            self.desc.set("Desc", shortDesc.strip())
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
            self.error = False
        except Exception as e:
            print(f"[nistcve] error: {e}")
            self.render_exception()


class DTSCirclCVEReport(widget.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.error = False
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
        self.error = True

    def populate(self, data: CirclCVEObject | None):
        self.clear()

        if data is None:
            self.render_exception(
                message="A network error happened! Check your internet settings."
            )
            self.error = True
            return

        self.title.grid(row=0, column=0, padx=4, pady=4)
        self.label.grid(row=1, column=0, padx=4, pady=2)
        self.rateMeter.grid(row=2, column=0, padx=10, pady=20)
        self.result.grid(row=3, column=0, padx=4, pady=2)
        self.desc.grid(row=4, column=0, padx=30, pady=10, sticky="NSEW")
        self.metrics.grid(
            row=5, column=0, padx=6, pady=10, columnspan=1, rowspan=1, sticky="NSEW"
        )

        self.title.configure(text="CIRCL's CVE Report")

        if data.id is None:
            self.render_exception("CVE not found!")
            return

        try:
            self.label.configure(text=f"for {data.id}")
            self.result.configure(text=f"Published on {data.Published}")
            desc = data.summary
            if len(desc) > 450:
                shortDesc = desc[:450]
                if ". " in shortDesc:
                    shortDesc = shortDesc[: shortDesc.rfind(". ")]
                else:
                    shortDesc += " ..."
            else:
                shortDesc = desc

            self.desc.set("Desc", shortDesc.strip())
            if data.cvss is None:
                self.rateMeter.set(0)
                self.metrics.insert("0.0", "Metrics not found!")
                return

            self.rateMeter.set(int(data.cvss * 10))
            self.metrics.insert(
                "0.0",
                "Access: "
                + data.access.model_dump_json(indent=2)
                + "\n\nImpact: "
                + data.impact.model_dump_json(indent=2),
            )
            self.error = False

        except Exception as e:
            print(e)
            self.render_exception()


class DTSTextReport(widget.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.error = False
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        self.title = widget.CTkLabel(
            self, justify="center", font=widget.CTkFont(size=18, weight="bold")
        )
        self.btnFrame = widget.CTkFrame(self)
        self.btnFrame.grid_rowconfigure(0, weight=1)

        i = Image.open(resource_path("lib/copy.png"))
        self.copyBtn = widget.CTkButton(
            self.btnFrame,
            text="Copy",
            width=30,
            height=20,
            image=widget.CTkImage(dark_image=i, light_image=i, size=(15, 15)),
        )
        ia = Image.open(resource_path("lib/analyze.png"))
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
