import subprocess
import pathlib

def windows_path_to_wsl(path: pathlib.Path) -> str:
    """
    Convert Windows path to WSL path.
    C:\\finalyear_project\\pcaps\\file.pcap
    -> /mnt/c/finalyear_project/pcaps/file.pcap
    """
    path = path.resolve()
    drive = path.drive.lower().replace(":", "")
    rest = str(path).replace(path.drive, "").replace("\\", "/")
    return f"/mnt/{drive}{rest}"

def run_zeek_on_pcap(pcap_path: str) -> pathlib.Path:
    """
    Runs Zeek via WSL on a PCAP file.
    Returns path to generated conn.log.
    """

    pcap_path = pathlib.Path(pcap_path).resolve()
    workdir = pcap_path.parent

    # Clean old Zeek logs (avoid stale data)
    for f in workdir.glob("*.log"):
        f.unlink()

    wsl_pcap = windows_path_to_wsl(pcap_path)

    cmd = [
    "wsl",
    "/opt/zeek/bin/zeek",
    "-r",
    wsl_pcap
]

    subprocess.run(
        cmd,
        cwd=str(workdir),
        check=True
    )

    conn_log = workdir / "conn.log"
    if not conn_log.exists():
        raise RuntimeError("Zeek ran but conn.log was not created")

    return conn_log
