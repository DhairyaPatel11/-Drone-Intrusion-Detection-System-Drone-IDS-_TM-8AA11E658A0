# Firmware Attacks — Threat Model (Phase 0)

| # | Attack | Vector | Observable from | Detectable by this module | Notes / Required trust |
|---|--------|--------|-----------------|---------------------------|------------------------|
| F-001 | Reboot-to-bootloader abuse (REBOOT_AUTOPILOT/BOOTLOADER) | MAVLink CMD | MAVLink stream (COMMAND_LONG/INT) | **yes** | Gate by arm state & authorized sysid; MAVLink 2.0 signing helps |
| F-002 | Unauthorized firmware/param/script upload via FTP | MAVLink FILE_TRANSFER_PROTOCOL | MAVLink stream (FILE_TRANSFER_PROTOCOL) | **yes** | Monitor sessions, paths, sizes; deny writes to protected dirs |
| F-003 | Firmware version / git-hash change (downgrade or unexpected) | MAVLink AUTOPILOT_VERSION / HEARTBEAT | MAVLink stream | **yes** | Track identity per sysid; alert on unexpected change/downgrade |
| F-004 | Rollback to old version (git hash < known-good) | MAVLink AUTOPILOT_VERSION | MAVLink stream | **yes** | Requires approved version list in policy |
| F-005 | Tampered companion-side firmware images / update files | Filesystem on companion | Companion (local hash/signature check) | **yes** | Hash + sig verification against trusted manifest; off hot path |
| F-006 | Unexpected boot / uptime / boot-count resets | MAVLink SYS_STATUS / SYSTEM_TIME / STATUSTEXT | MAVLink stream | **yes** | Detect discontinuous uptime / boot_count jumps |
| F-007 | Safety-parameter tampering (PID, EKF, geofence, battery FS) | MAVLink PARAM_SET / PARAM_VALUE | MAVLink stream | **yes** | Value-range & safety-critical lists from policy; cross-ref state |
| F-008 | ArduPilot Lua script injection (upload + load) | MAVLink FTP + SCRIPTING | MAVLink stream + companion FS | **partial** | Upload via FTP detected (F-002); script load needs FC-side hook |
| F-009 | Update-channel hijack (malicious update URL / manifest) | Companion network / FS | Companion (manifest sig) | **yes** | Verify update manifest signature & hash before apply |
| F-010 | Post-tamper behavioral drift (PID response, motor vs command) | Telemetry (IMU, motor, attitude) | MAVLink stream (physical) | **partial** | Cyber-physical baseline drift flag; **indicates**, not proves |
| F-011 | Bootloader-level firmware replacement (JTAG/SWD/chip-off) | Physical / bootloader | **needs FC-side trust** | **no** | Requires Secure Boot / TPM / hardware-rooted attestation |
| F-012 | In-memory FC code modification (runtime corruption) | Physical / DMA / exploit | **needs FC-side trust** | **no** | Requires FC-side integrity measurement (TPM/IMR) |

**Key principle (from mentor research):** This module runs on the **companion computer**. It observes the MAVLink stream and the companion filesystem. Anything that requires **flight-controller-internal** visibility (F-011, F-012) is marked **"requires secure boot/attestation"** — we do **not** claim detection without hardware-rooted trust.