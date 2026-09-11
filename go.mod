module github.com/instacryptio/ic-cli

go 1.26.6

require (
	github.com/charmbracelet/bubbles v1.0.0
	github.com/charmbracelet/lipgloss v1.1.0
	github.com/instacryptio/icfx v0.1.6
	github.com/spf13/cobra v1.10.2
	golang.org/x/term v0.42.0
)

require (
	al.essio.dev/pkg/shellescape v1.5.1 // indirect
	filippo.io/age v1.3.1 // indirect
	filippo.io/hpke v0.4.0 // indirect
	github.com/BurntSushi/toml v1.6.0 // indirect
	github.com/awnumar/memcall v0.4.0 // indirect
	github.com/awnumar/memguard v0.23.0 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/charmbracelet/bubbletea v1.3.10 // indirect
	github.com/charmbracelet/colorprofile v0.4.1 // indirect
	github.com/charmbracelet/harmonica v0.2.0 // indirect
	github.com/charmbracelet/x/ansi v0.11.6 // indirect
	github.com/charmbracelet/x/cellbuf v0.0.15 // indirect
	github.com/charmbracelet/x/term v0.2.2 // indirect
	github.com/clipperhouse/displaywidth v0.9.0 // indirect
	github.com/clipperhouse/stringish v0.1.1 // indirect
	github.com/clipperhouse/uax29/v2 v2.5.0 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/danieljoos/wincred v1.2.2 // indirect
	github.com/ebfe/scard v0.0.0-20241214075232-7af069cabc25 // indirect
	github.com/erikgeiser/coninput v0.0.0-20211004153227-1c3628e74d0f // indirect
	github.com/fxamacker/cbor/v2 v2.9.2 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/keybase/go-keychain v0.0.1 // indirect
	github.com/keys-pub/go-libfido2 v1.5.4-0.20251021061633-bf2d0535e75c // indirect
	github.com/lucasb-eyer/go-colorful v1.3.0 // indirect
	github.com/makiuchi-d/gozxing v0.1.1 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-localereader v0.0.1 // indirect
	github.com/mattn/go-runewidth v0.0.19 // indirect
	github.com/muesli/ansi v0.0.0-20230316100256-276c6243b2f6 // indirect
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/muesli/termenv v0.16.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	github.com/sstallion/go-hid v0.15.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	github.com/zalando/go-keyring v0.2.6 // indirect
	golang.org/x/crypto v0.50.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
	golang.org/x/text v0.36.0 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
)

replace github.com/keys-pub/go-libfido2 => github.com/instacryptio/go-libfido2 v1.5.4-instacrypt.2

// go-hid fork (instacryptio/go-hid @ instacrypt): adds OpenBSD support to the libusb
// backend (upstream has no openbsd cgo/build-tag). Tag .1 ONLY — it leaves hid_darwin.*
// untouched, so macOS stays on upstream IOHIDManager, which is what the chalresp macOS
// fixes in icfx rely on (SetOpenExclusive(false) + LockOSThread). The later .2/.3/.4 tags
// forced darwin→libusb and are ABANDONED (libusb can't open a kernel-held HID interface on
// macOS). Linux stays hidraw, Windows stays hid.dll.
replace github.com/sstallion/go-hid => github.com/instacryptio/go-hid v0.15.0-instacrypt.1
