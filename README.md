
# ESP32 WiFi Striker

**ESP32-based Arduino project** designed as an **educational tool for learning Wi-Fi security testing techniques**.  
> ⚠️ Use responsibly: Only test on networks and devices you own or have explicit permission to test. Unauthorized use is illegal.

---

## ⚠️ Warning

This project contains firmware capable of interacting with Wi-Fi networks in ways that can be illegal if used without consent.  
Test **only** in controlled environments on devices you own.

---

## Tools you need:

- ESP32
- LCD1602 Display
- Potentiometer
- Joystick Arduino Module
- Wires and free time.

## Wiring

### LCD1602 to ESP32

| LCD Pin | ESP32 Pin | Notes |
|---------|-----------|-------|
| VSS     | GND       |       |
| VDD     | 5V        | VN    |
| VO      | Pot middle| Contrast control |
| RS      | D14       |       |
| RW      | GND       |       |
| E       | D27       |       |
| D4      | D26       |       |
| D5      | D25       |       |
| D6      | D33       |       |
| D7      | D32       |       |
| A       | 5V        | VN    |
| K       | GND       |       |

### Joystick Module to ESP32

| Joystick Pin | ESP32 Pin | Notes |
|--------------|-----------|-------|
| X            | D35       |       |
| Y            | D34       |       |
| VCC          | 5V        | VN    |
| GND          | GND       |       |

### Potentiometer

| Leg | Connection |
|-----|------------|
| Left | GND       |
| Middle | LCD1602 VO |
| Right | Not used |

---

## Notes

- Ensure your power connections are correct to avoid damaging the ESP32 or peripherals.  
- Adjust the potentiometer to control LCD contrast.  
- This setup is strictly for **educational and ethical hacking purposes**.
