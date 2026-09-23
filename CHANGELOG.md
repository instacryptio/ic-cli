# CHANGELOG

**v0.1.3 - 09-23-2026**

- Bumped icfx to v0.1.7 (hardening) 
- `icc decrypt` / `icc cloud share get`: a failed signature asks before writing (refuses in scripts); new `--allow-unverified` and `--require-verified`
- Output is decrypted to a temp file and promoted only once released, so unverified plaintext never lands at the destination
- `icc verify` works on the containers the clients actually write (was rejecting every streaming container) and on armored input
- Sender fingerprints are sanitized before reaching the terminal
- When stdout is not a terminal it carries exactly the command's data: the banner, trailing spacing and the decrypt `---` marker no longer corrupt piped armored/plaintext output
- `icc verify` exit status: 0 verified, 1 failed, 2 unsigned, 3 unknown sender
- Fixed `--conf-path`


**v0.1.2 - 09-10-2026**

- Bumped icfx to v0.1.6
- Added static knob to build
- Added Windows static build in GA
- Added macOS static build in GA
- Droped Windows arm64 build in GA
- Added Gatekeeper detect+prompt in install.sh
- Changed to build FreeBSD builds with FreeBSD 14.3
- Added proper openBSD builds (7.8 and 7.9)
- Added instacryptio/go-hid .1


**v0.1.1 - 09-07-2026**

- ChalResp setup flow fix
- Fix show first & last name logic
- Bumped icfx to v0.1.2


**v0.1.0 - 09-06-2026**

- Initial commit
- git-sign refinements
