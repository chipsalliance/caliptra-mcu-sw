#!/usr/bin/env python3
"""Single-owner J1 console: CPU log polling and optional development entropy feed."""
import argparse
import os
import time
from entropy_host import Link, describe


class Logs:
    def __init__(self, link):
        self.link = link
        self.lines = ['', '']
        self.last = [time.monotonic()] * 2
        self.dropped = [0, 0]
        self.quiet = False

    def emit(self, ch, partial=False):
        if self.lines[ch]:
            if not self.quiet:
                print(
                    f'[{("MCU", "CALIPTRA")[ch]}{":partial" if partial else ""}] {self.lines[ch]}',
                    flush=True,
                )
            self.lines[ch] = ''
        self.last[ch] = time.monotonic()

    def drain(self, budget=8):
        any_data = False
        for _ in range(budget):
            active = False
            for ch in range(2):
                value = self.link.call(0x10 + ch)
                count = value >> 24
                if count > 3:
                    raise RuntimeError(
                        'Invalid log byte count; wrong bitstream/protocol?'
                    )
                active |= bool(count)
                any_data |= bool(count)
                for i in range(count):
                    b = (value >> (i * 8)) & 255
                    if b == 10:
                        self.emit(ch)
                    elif b != 13:
                        self.lines[ch] += (
                            chr(b) if 32 <= b <= 126 or b == 9
                            else f'\\x{b:02x}'
                        )
                        if len(self.lines[ch]) >= 512:
                            self.emit(ch, True)
            if not active:
                break

        for ch in range(2):
            if self.lines[ch] and time.monotonic() - self.last[ch] > 1:
                self.emit(ch, True)
        return any_data

    def drops(self):
        for ch in range(2):
            count = self.link.call(0x12 + ch)
            if count != self.dropped[ch]:
                print(
                    f'[LOG_OVERFLOW] {("MCU", "CALIPTRA")[ch]} '
                    f'cumulative dropped bytes={count}',
                    flush=True,
                )
                self.dropped[ch] = count


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        '--port',
        required=True,
        help='Actual J1 serial port, e.g. COM5 or /dev/ttyUSB0',
    )
    p.add_argument('--baud', type=int, default=115200)
    p.add_argument(
        '--restart-local',
        action='store_true',
        help='Restart subsystem with deterministic DEVELOPMENT source',
    )
    p.add_argument('action', choices=['monitor', 'feed', 'status'])
    a = p.parse_args()

    if a.restart_local and a.action != 'monitor':
        p.error('--restart-local requires monitor')

    link = Link(a.port, a.baud)
    logs = Logs(link)
    feeding = False

    try:
        if a.action == 'status':
            print(describe(link.call(1)))
            logs.drops()
            return

        if a.restart_local or a.action == 'feed':
            link.call(2, int(a.action == 'feed'))
            time.sleep(0.01)

            logs.quiet = True
            print(
                '[HOST] Subsystem held; discarding previous boot logs.',
                flush=True,
            )
            for _ in range(180):
                if not logs.drain(8):
                    break
            else:
                raise RuntimeError(
                    'Logs continue while subsystem held; reset wiring needs inspection.'
                )

            for ch in range(2):
                logs.emit(ch, True)
            logs.quiet = False

            if a.action == 'feed':
                for _ in range(256):
                    link.call(3, int.from_bytes(os.urandom(4), 'little'))

            feeding = a.action == 'feed'
            print(
                '[HOST] Releasing subsystem reset; DEVELOPMENT entropy only.',
                flush=True,
            )
            link.call(4)

        print(
            '[HOST] Monitoring MCU/Caliptra logs. '
            'Close other programs using this UART.',
            flush=True,
        )
        last = 0

        while True:
            if feeding:
                status = link.call(1)
                for _ in range(min(status >> 16, 64)):
                    link.call(3, int.from_bytes(os.urandom(4), 'little'))

            active = logs.drain(8 if feeding else 32)
            if time.monotonic() - last >= 2:
                logs.drops()
                if feeding:
                    print('[ENTROPY]', describe(link.call(1)), flush=True)
                last = time.monotonic()

            if not active:
                time.sleep(0.005)

    except KeyboardInterrupt:
        print('\n[HOST] Console stopped.', flush=True)
    finally:
        if feeding:
            try:
                link.call(2, 1)
                print('[HOST] Subsystem held in HOST reset.')
            except Exception as e:
                print(f'[HOST] Could not confirm reset: {e}')

        for ch in range(2):
            logs.emit(ch, True)
        link.close()


if __name__ == '__main__':
    main()