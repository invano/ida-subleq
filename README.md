# IDA Pro processor module for SUBLEQ

Proof of concept implementation of an IDA Processor module for *SUbtract and
Branch if Less than or EQual to zero* (SUBLEQ) machines.
Written for IDA Pro 7 and tested on IDA Pro 7.1.

This module was written to solve *Suspicious Floppy Disk*---the last challenge---of [Flare-On 2018](http://flare-on.com/) reverse engineering competition.
The aim of this IDA processor is to translate `subleq` instructions to an higher
level interpretation. You can find a quick explanation of the implemented macro
at [this blog post](https://emanuelecozzi.net/posts/ctf/flareon-2018-challenge-12-subleq-rssb-writeup).

Please, take it as it is and bear in mind this processor is strongly built on
top of the SUBLEQ macros created by the challenge author.

Content:

- **subleq-ida.py**, IDA processor module. Move it to `/<IDA installation
path>/procs/`
- **subleq-emu.py**, a Subleq emulator written in Python
- **flareon2018-ch12.sl**, the Subleq payload extracted from last challenge of
Flare-On 2018
