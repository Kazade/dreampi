# DreamPi  
DreamPi is software that lets a Sega Dreamcast use its built-in dial-up modem to access modern internet connections. It runs on a Raspberry Pi and bridges the Pi’s Ethernet or Wi-Fi connection to the Dreamcast through a compatible USB dial-up voice modem and phone cable.

This approach makes it possible to use compatible Dreamcast games and web browsers online without a traditional dial-up ISP. DreamPi is especially useful because the Dreamcast Broadband Adapter supports only a limited selection of games, while DreamPi works through the console’s standard modem.

# How to install

DreamPi runs on all Raspberry Pi models except the Raspberry Pi 5. Download the prebuilt image from the repository’s [Releases page](https://github.com/Kazade/dreampi/releases); each release includes an image asset, such as [`dreampi-2.1.zip`](https://github.com/Kazade/dreampi/releases/download/v2.1/dreampi-2.1.zip) for version 2.1.

## What you need

- A supported Raspberry Pi and compatible power supply
- A microSD card
- A microSD-card reader
- A computer running Windows, macOS, or Linux
- A flashing utility, such as [Raspberry Pi Imager](https://www.raspberrypi.com/software/) or [balenaEtcher](https://etcher.balena.io/)

>  **Warning:** Flashing overwrites the entire selected microSD card. Copy off anything important before continuing.

## Flash microSD card

1. Open the [Releases page](https://github.com/Kazade/dreampi/releases) and select the release you want to install.
2. Under **Assets**, download the `dreampi-<version>.zip` file. For example, DreamPi 2.1 provides `dreampi-2.1.zip`.
3. Extract the ZIP archive. It contains the DreamPi `.img` disk image.
4. Insert the microSD card into your computer.
5. Open **Raspberry Pi Imager** or **balenaEtcher**.
6. Select the extracted DreamPi `.img` file as the image source.
7. Select the correct microSD card as the target device.
8. Start the flash process and wait for it to complete. If the tool offers validation, allow it to verify the written image.
9. Eject the microSD card safely and insert it into the Raspberry Pi.