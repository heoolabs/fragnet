# fragnet
*Made just for fun.*

**fragnet** is a lightweight, cross-platform SOCKS5 proxy designed to bypass DPI strictly in `userspace` without root privileges.

## Features
* **Userspace only:** Works without kernel drivers. You can use any third-party app to create a TUN interface.
* **Automatic strategy selection:** Finds the best bypass method automatically (though it takes a little time on startup).
* **Built-in DoH:** Uses DNS-over-HTTPS out of the box.

## How to build and run
```bash
git clone https://github.com/heoolabs/fragnet.git
cd fragnet
go build -o fragnet .
./fragnet
```
