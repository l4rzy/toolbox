import customtkinter as widget
import signal
import sys

from lib.util import resource_path
from widgets.toolbox import DTSToolBox

widget.set_default_color_theme(resource_path("lib/theme.json"))
widget.set_appearance_mode("dark")


app = DTSToolBox()


def sigint_handler(sig, frame):
    app.exit_gracefully()
    sys.exit(-1)


signal.signal(signal.SIGINT, sigint_handler)

app.run()
