#!/usr/bin/env python3
"""GUI for HTG-940 console monitoring and automatic USB recovery."""

from __future__ import annotations

import queue
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, scrolledtext, ttk


RECOVERY_MARKER = "[MCU] [mcu-rom] Waiting for MCU firmware to be ready"


def console_target(line: str) -> str:
    if line.startswith("[CALIPTRA") or "[LOG_OVERFLOW] CALIPTRA" in line:
        return "caliptra"
    return "mcu"


class RecoveryGui:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.script_directory = Path(__file__).resolve().parent
        self.console_script = self.script_directory / "htg940_console_updated.py"
        self.events: queue.Queue[tuple[str, str, object]] = queue.Queue()
        self.console_process: subprocess.Popen[str] | None = None
        self.recovery_process: subprocess.Popen[str] | None = None
        self.recovery_started = False
        self.stopping = False

        self.root.title("HTG-940 USB OCP Recovery")
        self.root.geometry("1280x820")
        self.root.minsize(900, 600)
        self.root.protocol("WM_DELETE_WINDOW", self.close)

        self.port = tk.StringVar(value="COM8")
        self.status = tk.StringVar(value="Ready")
        self._build_ui()
        self.root.after(50, self._drain_events)

    def _build_ui(self) -> None:
        toolbar = ttk.Frame(self.root, padding=(10, 8))
        toolbar.pack(fill=tk.X)

        ttk.Label(toolbar, text="Serial port:").pack(side=tk.LEFT)
        self.port_entry = ttk.Entry(toolbar, textvariable=self.port, width=10)
        self.port_entry.pack(side=tk.LEFT, padx=(6, 12))

        self.start_button = ttk.Button(toolbar, text="Start", command=self.start)
        self.start_button.pack(side=tk.LEFT)
        self.stop_button = ttk.Button(
            toolbar,
            text="Stop",
            command=self.stop,
            state=tk.DISABLED,
        )
        self.stop_button.pack(side=tk.LEFT, padx=(8, 0))
        ttk.Label(toolbar, textvariable=self.status).pack(side=tk.LEFT, padx=(16, 0))

        outer = ttk.Panedwindow(self.root, orient=tk.VERTICAL)
        outer.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        top = ttk.Panedwindow(outer, orient=tk.HORIZONTAL)
        mcu_frame, self.mcu_log = self._make_log_panel(top, "MCU logs")
        caliptra_frame, self.caliptra_log = self._make_log_panel(top, "Caliptra logs")
        top.add(mcu_frame, weight=1)
        top.add(caliptra_frame, weight=1)

        recovery_frame, self.recovery_log = self._make_log_panel(
            outer,
            "USB recovery logs",
        )
        outer.add(top, weight=2)
        outer.add(recovery_frame, weight=1)

    @staticmethod
    def _make_log_panel(parent: tk.Widget, title: str) -> tuple[ttk.Frame, scrolledtext.ScrolledText]:
        frame = ttk.Frame(parent, padding=4)
        ttk.Label(frame, text=title).pack(anchor=tk.W, pady=(0, 4))
        log = scrolledtext.ScrolledText(
            frame,
            wrap=tk.NONE,
            font=("Consolas", 10),
            state=tk.DISABLED,
            undo=False,
        )
        log.pack(fill=tk.BOTH, expand=True)
        return frame, log

    def start(self) -> None:
        if self.console_process and self.console_process.poll() is None:
            return

        required_files = [
            self.console_script,
            self.script_directory / "usb_recovery.py",
            self.script_directory / "caliptra_fw.bin",
            self.script_directory / "soc_manifest.bin",
            self.script_directory / "mcu_runtime.bin",
        ]
        missing = [str(path) for path in required_files if not path.is_file()]
        if missing:
            messagebox.showerror("Missing files", "Required files are missing:\n" + "\n".join(missing))
            return

        port = self.port.get().strip()
        if not port:
            messagebox.showerror("Serial port", "Enter a serial port such as COM8.")
            return

        for log in (self.mcu_log, self.caliptra_log, self.recovery_log):
            self._clear_log(log)

        self.recovery_started = False
        self.stopping = False
        self.start_button.configure(state=tk.DISABLED)
        self.stop_button.configure(state=tk.NORMAL)
        self.port_entry.configure(state=tk.DISABLED)
        self.status.set(f"Starting console on {port}")

        command = [
            sys.executable,
            "-u",
            str(self.console_script),
            "--port",
            port,
            "--restart-local",
            "monitor",
        ]
        try:
            self.console_process = self._start_process(
                "console",
                command,
                self.console_script.parent,
            )
        except OSError as error:
            self._finish_run(f"Could not start console: {error}")

    def _start_recovery(self) -> None:
        if self.recovery_started or self.stopping:
            return
        self.recovery_started = True
        self.status.set("MCU is ready; starting USB recovery")
        self._append(self.recovery_log, f"[GUI] Detected: {RECOVERY_MARKER}\n")

        command = [
            sys.executable,
            "-u",
            str(self.script_directory / "usb_recovery.py"),
            "--caliptra-fmc-rt",
            str(self.script_directory / "caliptra_fw.bin"),
            "--soc-manifest",
            str(self.script_directory / "soc_manifest.bin"),
            "--mcu-runtime",
            str(self.script_directory / "mcu_runtime.bin"),
        ]
        try:
            self.recovery_process = self._start_process(
                "recovery",
                command,
                self.script_directory,
            )
        except OSError as error:
            self._append(self.recovery_log, f"[GUI] Could not start recovery: {error}\n")
            self.status.set("USB recovery failed to start")

    def _start_process(
        self,
        source: str,
        command: list[str],
        working_directory: Path,
    ) -> subprocess.Popen[str]:
        process = subprocess.Popen(
            command,
            cwd=working_directory,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        threading.Thread(
            target=self._read_process,
            args=(source, process),
            daemon=True,
        ).start()
        return process

    def _read_process(self, source: str, process: subprocess.Popen[str]) -> None:
        try:
            if process.stdout is not None:
                for line in process.stdout:
                    self.events.put(("line", source, line.rstrip("\r\n")))
            return_code = process.wait()
            self.events.put(("exit", source, return_code))
        except Exception as error:
            self.events.put(("error", source, str(error)))

    def _drain_events(self) -> None:
        try:
            while True:
                event, source, value = self.events.get_nowait()
                if event == "line":
                    line = str(value)
                    if source == "console":
                        target = self.caliptra_log if console_target(line) == "caliptra" else self.mcu_log
                        self._append(target, line + "\n")
                        if RECOVERY_MARKER in line:
                            self._start_recovery()
                    else:
                        self._append(self.recovery_log, line + "\n")
                elif event == "exit":
                    self._process_exited(source, int(value))
                else:
                    target = self.recovery_log if source == "recovery" else self.mcu_log
                    self._append(target, f"[GUI] Reader error: {value}\n")
        except queue.Empty:
            pass
        self.root.after(50, self._drain_events)

    def _process_exited(self, source: str, return_code: int) -> None:
        if source == "recovery":
            self._append(self.recovery_log, f"[GUI] USB recovery exited with code {return_code}.\n")
            if not self.stopping:
                self.status.set(
                    "USB recovery completed; monitoring console"
                    if return_code == 0
                    else f"USB recovery failed with code {return_code}"
                )
            return

        self._append(self.mcu_log, f"[GUI] Console exited with code {return_code}.\n")
        if not self.stopping:
            self._finish_run(f"Console exited with code {return_code}")

    def stop(self) -> None:
        self.stopping = True
        self.status.set("Stopping")
        for process in (self.recovery_process, self.console_process):
            if process and process.poll() is None:
                process.terminate()
        self._finish_run("Stopped")

    def _finish_run(self, status: str) -> None:
        self.status.set(status)
        self.start_button.configure(state=tk.NORMAL)
        self.stop_button.configure(state=tk.DISABLED)
        self.port_entry.configure(state=tk.NORMAL)

    @staticmethod
    def _append(log: scrolledtext.ScrolledText, text: str) -> None:
        at_bottom = log.yview()[1] >= 0.999
        log.configure(state=tk.NORMAL)
        log.insert(tk.END, text)
        log.configure(state=tk.DISABLED)
        if at_bottom:
            log.see(tk.END)

    @staticmethod
    def _clear_log(log: scrolledtext.ScrolledText) -> None:
        log.configure(state=tk.NORMAL)
        log.delete("1.0", tk.END)
        log.configure(state=tk.DISABLED)

    def close(self) -> None:
        self.stopping = True
        for process in (self.recovery_process, self.console_process):
            if process and process.poll() is None:
                process.terminate()
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    RecoveryGui(root)
    root.mainloop()


if __name__ == "__main__":
    main()