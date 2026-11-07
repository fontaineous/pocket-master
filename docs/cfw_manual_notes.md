# Notes from the Pocket Master CFW user manual

Source: the manual of the community CFW project (pocketmaster-cfw.guitar-training-generator.com), pasted into the session by the
repo owner. The site itself is not reachable from the analysis environment, so this file only records facts relevant to the
reverse engineering. Treat them as the CFW author's statements, not as verified results.

- The device is the **Sonicake** Pocket Master (not Hotone). The "Smart Box" is a sibling Sonicake product with the same model
  ids (amps, delays, modulations); the CFW author ports its models over. A Smart Box CFW also exists.
- Current CFW is **0.9.7** (beta). The repo has 0.5 and 0.9.4. 0.9.6 added 16 Smart Box amps and the Bass 4x10 cab
  (amp library stored compressed and unpacked per amp), 0.9.7 added the Smart Box delays and modulations.
- The manual describes **no looper length change**; the CFW only made the looper lighter, made loud overdubs saturate and added a DSP meter.
- Hardware backup advice: "dump the pedal's flash memory with a CH341A programmer and a SOP-8 clip. The bootloader is not part of
  the update file". So the NDS32 chip's flash is an external SPI-NOR in SOP-8, and the update file (HTFW) does not contain the boot loader.
- The manual calls the second processor the **"DSP co-processor"** and says the amp library is decompressed per amp load.
- Bluetooth: the pedal advertises as "Pocket Master MIDI" (BLE MIDI). M-Vave Chocolate and similar controllers connect to it. The
  CFW remembers one **Sonicake Pocket Control** (BLE) paired from Settings -> BT and reconnects it automatically, so the pedal does act as a
  BLE central for that controller. The manual states that Bluetooth audio, the web app over Bluetooth and these controllers "work as before";
  it does not say that all of them can be connected at once.
- Settings written by the web app/pedal include a MIDI map table (Custom map), EXP A-D assignments per preset, scenes (BASE/SC1/SC2) and STOMP groups.
