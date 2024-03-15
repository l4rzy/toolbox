import customtkinter as widget
import sys

from lib.config import DTSConfig
from lib.util import resource_path
from lib import VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH, VERSION_DATE


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

        i = Image.open(resource_path("lib/icons/icon.png"))
        image = widget.CTkImage(light_image=i, dark_image=i, size=(150, 150))
        self.logo = widget.CTkLabel(self, image=image, text="")
        self.line1 = widget.CTkLabel(
            self,
            font=widget.CTkFont(size=18),
            text=f"DTS Toolbox - v{VERSION_MAJOR}.{VERSION_MINOR}.{VERSION_PATCH} ({VERSION_DATE})",
        )
        self.line2 = widget.CTkLabel(
            self,
            font=widget.CTkFont(size=14),
            text="Original author: l4rzy | License: GPLv3",
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
