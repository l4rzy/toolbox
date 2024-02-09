import customtkinter

app = customtkinter.CTk()

def segmented_button_callback(value):
    print("segmented button clicked:", value)

segemented_button = customtkinter.CTkSegmentedButton(app, values=["Value 1", "Value 2", "Value 3"],
                                                     command=segmented_button_callback)
segemented_button.set("Value 1")

segemented_button.pack()

def combobox_callback(choice):
    print("combobox dropdown clicked:", choice)

combobox = customtkinter.CTkComboBox(app, values=["option 1", "option 2"],
                                     command=combobox_callback)
combobox.set("option 2")

combobox.pack()

def optionmenu_callback(choice):
    print("optionmenu dropdown clicked:", choice)

optionmenu = customtkinter.CTkOptionMenu(app, values=["option 1", "option 2"],
                                         command=optionmenu_callback)
optionmenu.set("option 2")

optionmenu.pack()

def slider_event(value):
    print(value)

slider = customtkinter.CTkSlider(app, from_=0, to=100, command=slider_event)

slider.pack()

app.mainloop()