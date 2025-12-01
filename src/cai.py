import subprocess

pfx_path = r"C:\Users\mahfu\neo_certs\neo_codesign_Dexcorp_Softwares_Limited_3504cec2.pfx"
password = "gg"

# Directly import into Trusted Publishers store
proc = subprocess.run([
    "certutil",
    "-f",
    "-p", password,
    "-importpfx",
    "TrustedPublisher",
    pfx_path
], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

print("Return code:", proc.returncode)
print("STDOUT:", proc.stdout)
print("STDERR:", proc.stderr)
