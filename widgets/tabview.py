import customtkinter as widget

from .report import (
    DTSAbuseIPDBReport,
    DTSCirclCVEReport,
    DTSVirusTotalReport,
    DTSGenericReport,
    DTSTextReport,
    DTSNISTCVEReport,
)

from widgets.custom import DTSLoading, DTSHistory, DTSLog
from widgets.preferences import DTSPreferences

from lib.analyzer import DTSAnalyzer


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
        # if last render had error, render again
        if f"{source}-{originalText}" == self.lastData and (
            source in self.reports and not self.reports[source].error
        ):
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
            if data is not None:
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
            if data is not None:
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
            if data is not None:
                self.textBoxData.insert("0.0", data.model_dump_json(indent=2))

            self.hide_other_reports(except_for=source)
            self.reports[source].populate(data)
            self.currentReport = source

        elif source == "circlcve":
            if source not in self.reports:
                self.reports[source] = DTSCirclCVEReport(self.tab("Report"))
                self.reports[source].grid(
                    row=0, column=0, columnspan=1, rowspan=1, sticky="SWEN"
                )

            self.textBoxData.delete("0.0", "end")
            if data is not None:
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
            if data is not None:
                self.textBoxData.insert("0.0", originalText)

            self.hide_other_reports(except_for=source)
            self.reports[source].reset()
            self.reports[source].populate(data)
            self.currentReport = source

        else:
            print(f"[ui] can't render from `{source}` with data = `{data}`")

        self.lastData = f"{source}-{originalText}"
