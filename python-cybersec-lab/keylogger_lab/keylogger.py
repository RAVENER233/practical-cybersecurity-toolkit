
import tkinter as tk
from datetime import datetime
from pathlib import Path

LOG_FILE = Path(__file__).parent / "keyboard_test.log"


def record_input(event):
    """Record input typed inside our own test application."""

    if event.char and event.char.isprintable():
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with open(LOG_FILE, "a", encoding="utf-8") as log:
            log.write(f"[{timestamp}] {event.char}\n")


def clear_log():
    LOG_FILE.write_text("", encoding="utf-8")
    status.config(text="Test log cleared.")


def close_app():
    root.destroy()


root = tk.Tk()
root.title("Keyboard Monitoring Research Lab")
root.geometry("600x350")

heading = tk.Label(
    root,
    text="Python Keyboard Monitoring Lab",
    font=("Arial", 16, "bold")
)
heading.pack(pady=15)

instructions = tk.Label(
    root,
    text="Type test text below. Only this application's input is recorded."
)
instructions.pack(pady=5)

text_area = tk.Text(root, height=8, width=60)
text_area.pack(padx=15, pady=10)

text_area.bind("<KeyPress>", record_input)

status = tk.Label(root, text="Waiting for test input...")
status.pack(pady=5)

buttons = tk.Frame(root)
buttons.pack(pady=10)

tk.Button(
    buttons,
    text="Clear Log",
    command=clear_log
).pack(side=tk.LEFT, padx=5)

tk.Button(
    buttons,
    text="Exit",
    command=close_app
).pack(side=tk.LEFT, padx=5)

root.mainloop()
