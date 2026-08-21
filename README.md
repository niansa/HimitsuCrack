# HimitsuCrack

Dynamic HimitsuShell deobfuscator

## Usage

1. Compile: `gcc HimitsuCrack.c -o HimitsuCrack`
2. Run the target script: `./HimitsuCrack ./safeLauncher`

The target script will be terminated the moment extraction is complete. However, I'd still recommend to proceed with great care when handling potentially malicious scripts.

## Notes

Ironically, despite the *HimitsuShell* developers boasting about how secure their solution is, this deobfuscator is way simpler (less than 200 LOC!) than [UnSHc](https://github.com/yanncam/UnSHc) or [unshell](https://github.com/Rem01Gaming/unshell). With this repo I'd like to prove them otherwise :-)

I put this together in about 5 minutes with basically no research into how HimitsuShell works. It's not perfect, but seems to work almost all of the time. The one case where I found it to not be working is with very very short running scripts, though this isn't a big problem since all practical shell scripts will run for longer than that.

I encourage anyone to fork and improve this project.
