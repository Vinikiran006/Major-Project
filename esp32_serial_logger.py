
import serial
from datetime import datetime

PORT = "COM3"
BAUD_RATE = 115200

filename = f"esp32_serial_{datetime.now():%Y%m%d_%H%M%S}.log"

print(f"Logging ESP32 output to {filename}")
print("Press Ctrl+C to stop.\n")

try:
    with serial.Serial(PORT, BAUD_RATE, timeout=1) as esp, \
            open(filename, "w", encoding="utf-8") as log:

        while True:
            line = esp.readline().decode("utf-8", errors="replace")
            if line:
                print(line, end="")
                log.write(line)
                log.flush()

except KeyboardInterrupt:
    print(f"\nLogging stopped. Saved to {filename}")
except serial.SerialException as exc:
    print(f"Serial error: {exc}")
    print("Close Arduino Serial Monitor and check the COM port.")
