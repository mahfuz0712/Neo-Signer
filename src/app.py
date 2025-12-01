import sys
import os
import shutil
import uuid
import subprocess
from datetime import datetime, timedelta
import ctypes
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from PyQt6.QtWidgets import (
    QApplication, QWidget, QPushButton, QLabel, QVBoxLayout, QHBoxLayout,
    QTextEdit, QFileDialog, QProgressBar, QMessageBox, QLineEdit, QGroupBox, QInputDialog, QTabWidget
)
from PyQt6.QtGui import QIcon
from PyQt6.QtCore import  QThread, pyqtSignal
# import ends here




# ----------------------------- Metadata ----------------------------------------------
APP_TITLE = "Neo Signer"
VERSION = "1.0.0"
COMPANY = "Dexcorp Softwares Limited"


# ---------------------------- Directories / Dependencies -----------------------------
BIN_DIR = os.path.join(os.path.dirname(__file__), "bin")


# ---------------------------- Privilege / Install Helpers ----------------------------
def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# --- NEW PATH RESOLUTION FUNCTION ---
def resource_path(relative_path):
    """Get the absolute path to resource, works for dev and for PyInstaller."""
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        # This is the path to the bundled files inside the executable
        base_path = sys._MEIPASS # type: ignore
    except Exception:
        # If running in development (outside of a PyInstaller bundle)
        # Use the current directory as the base path
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)
# ------------------------------------


def elevate_and_run_install(pfx_path: str, password: str) -> None:
    params = f'--elev-install "{pfx_path}" "{password}"'
    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    except Exception:
        raise


def install_pfx_direct(pfx_path: str, password: str) -> dict:
    if not os.path.isfile(pfx_path):
        return {"ok": False, "error": "PFX file not found."}

    proc = subprocess.run([
        "certutil",
        "-f",
        "-p", password,
        "-importpfx",
        "TrustedPublisher",
        pfx_path
    ], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if proc.returncode != 0:
        return {"ok": False, "error": proc.stderr.strip() or proc.stdout.strip()}

    return {"ok": True}



# ---------------------------- Certificate & Signing Worker ----------------------------
class RealWorker(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal(dict)

    def __init__(self, action: str, payload: dict, log_fn):
        super().__init__()
        self.action = action
        self.payload = payload
        self.log = log_fn
    def run(self):
        try:
            self.progress.emit(5)
            if self.action == "generate_cert":
                res = self._generate_certificate(
                    self.payload.get("publisher", ""),
                    self.payload.get("password", ""),
                    self.payload.get("organization", "")
                )
            elif self.action == "install_cert":
                res = self._install_certificate(self.payload["pfx_path"], self.payload.get("password", ""))
            elif self.action == "sign_file":
                res = self._sign_file(
                    self.payload["exe_path"],
                    self.payload["pfx_path"],
                    self.payload.get("pfx_password", ""),
                    self.payload.get("publisher", ""),
                    self.payload.get("timestamp_url", "")
                )
            else:
                res = {"ok": False, "error": "Unknown action"}
        except Exception as e:
            res = {"ok": False, "error": str(e)}
        self.progress.emit(100)
        self.finished.emit(res)

    def _generate_certificate(self, publisher_name: str, pfx_password: str, organization_name: str) -> dict:
        # Save generated certificates next to this module if no EXE path is available
        out_dir = os.path.join(os.path.dirname(__file__), "neo_signed")
        os.makedirs(out_dir, exist_ok=True)

        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        now = datetime.utcnow()
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
            x509.NameAttribute(NameOID.COMMON_NAME, publisher_name),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=365*2))
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(private_key=key, algorithm=hashes.SHA256())
        )

        uid = uuid.uuid4().hex[:8]
        basename = f"neo_codesign_{publisher_name.replace(' ', '_')}_{uid}"
        pfx_path = os.path.join(out_dir, basename + ".pfx")

        pfx_bytes = pkcs12.serialize_key_and_certificates(
            name=publisher_name.encode(),
            key=key,
            cert=cert,
            cas=None,
            encryption_algorithm=serialization.BestAvailableEncryption(pfx_password.encode())
            if pfx_password else serialization.NoEncryption()
        )
        with open(pfx_path, "wb") as f:
            f.write(pfx_bytes)

        return {"ok": True, "pfx_path": pfx_path}

    def _install_certificate(self, pfx_path: str, password: str) -> dict:
        if not os.path.isfile(pfx_path):
            return {"ok": False, "error": "PFX file not found."}

        # Directly import PFX into Trusted Publishers store
        proc = subprocess.run([
            "certutil",
            "-f",
            "-p", password,
            "-importpfx",
            "TrustedPublisher",
            pfx_path
        ], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if proc.returncode != 0:
            return {"ok": False, "error": "Failed to install certificate: " + proc.stderr.strip()}

        return {"ok": True}

    def _sign_file(self, exe_path: str, pfx_path: str, pfx_password: str, publisher_name: str, timestamp_url: str) -> dict:
        if not os.path.isfile(exe_path):
            return {"ok": False, "error": "Executable not found."}
        if not os.path.isfile(pfx_path):
            return {"ok": False, "error": "PFX file not found."}

        out_dir = os.path.join(os.path.dirname(exe_path), "neo_signed")
        os.makedirs(out_dir, exist_ok=True)
        base, ext = os.path.splitext(os.path.basename(exe_path))
        signed_path = os.path.join(out_dir, f"{base}_signed{ext}")

        ossl = os.path.join(BIN_DIR, "osslsigncode.exe")
        if not os.path.isfile(ossl):
            ossl = shutil.which("osslsigncode")
        if not ossl:
            return {"ok": False, "error": "osslsigncode not found in bin/ or PATH."}

        cmd = [ossl, "sign", "-pkcs12", pfx_path, "-in", exe_path, "-out", signed_path, "-h", "sha256"]
        if pfx_password:
            cmd += ["-pass", pfx_password]
        if publisher_name:
            cmd += ["-n", publisher_name]
        if timestamp_url:
            cmd += ["-t", timestamp_url]

        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if proc.returncode != 0:
            return {"ok": False, "error": f"osslsigncode failed: {proc.stderr.strip()}"}
        return {"ok": True, "signed_path": signed_path}


# ---------------------------- GUI ----------------------------
class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_TITLE} — {VERSION}")


        # set window icon if available
        icon_path = resource_path(os.path.join("assets", "logo.ico"))
        if os.path.isfile(icon_path):
            try:
                self.setWindowIcon(QIcon(icon_path))
            except Exception:
                pass


        self.setMinimumSize(820, 520)
        self._exe_path = None
        self._pfx_path = None
        self._pfx_password = ""
        self.workers = []
        self._last_exe_dir = os.path.expanduser("")
        self._last_pfx_dir = os.path.expanduser("")
        self.build_ui()
        # Check admin state immediately after UI is built
        try:
            self.check_admin_status()
        except Exception:
            # If anything goes wrong, just log it
            self.append_log("Failed to determine administrative status")

    def build_ui(self):
        main_layout = QVBoxLayout()
        # Header with admin status
        header_h = QHBoxLayout()
        header_label = QLabel(f"<h2>{APP_TITLE}</h2><small>Sign EXE with a self-signed Certificate</small>")
        self.admin_label = QLabel("")
        header_h.addWidget(header_label)
        header_h.addStretch()
        header_h.addWidget(self.admin_label)
        main_layout.addLayout(header_h)

        # Create tabs
        tabs = QTabWidget()
        tabs.addTab(self.build_home_tab(), "Home")
        tabs.addTab(self.build_cert_manager_tab(), "Certificate Manager")
        main_layout.addWidget(tabs)

        # Log
        self.log = QTextEdit(); self.log.setReadOnly(True); main_layout.addWidget(self.log)

        # Footer
        f = QHBoxLayout()
        btn_open = QPushButton("Open Output Folder"); btn_open.clicked.connect(self.open_output_folder)
        f.addWidget(btn_open); f.addStretch()
        main_layout.addLayout(f)
        self.setLayout(main_layout)

    def build_home_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()

        # --- Select EXE
        group_file = QGroupBox("1) Select Setup Executable (.exe)")
        g = QHBoxLayout()
        self.exe_line = QLineEdit(); self.exe_line.setReadOnly(True)
        btn_browse = QPushButton("Browse..."); btn_browse.clicked.connect(self.browse_exe)
        g.addWidget(self.exe_line); g.addWidget(btn_browse)
        group_file.setLayout(g); layout.addWidget(group_file)
        
        # --- Signing Publisher (separate from Certificate Manager)
        gp_sign_pub = QGroupBox("Application Metadata")
        gs = QHBoxLayout()
        self.signing_publisher_input = QLineEdit("")
        gs.addWidget(QLabel("App Name:")); gs.addWidget(self.signing_publisher_input)
        gp_sign_pub.setLayout(gs); layout.addWidget(gp_sign_pub)

        # --- Select existing PFX
        group_cert_select = QGroupBox("2) Select Certificate")
        g_select = QHBoxLayout()
        self.select_pfx_line = QLineEdit(); self.select_pfx_line.setReadOnly(True)
        btn_select_pfx = QPushButton("Select..."); btn_select_pfx.clicked.connect(self.select_pfx)
        g_select.addWidget(self.select_pfx_line); g_select.addWidget(btn_select_pfx)
        group_cert_select.setLayout(g_select); layout.addWidget(group_cert_select)

        # --- Sign EXE
        group_sign = QGroupBox("3) Sign Executable")
        g3 = QHBoxLayout()
        btn_sign = QPushButton("Sign"); btn_sign.clicked.connect(self.sign_exe)
        self.timestamp_input = QLineEdit(); self.timestamp_input.setPlaceholderText("Optional timestamp URL")
        self.progress = QProgressBar()
        g3.addWidget(btn_sign); g3.addWidget(self.timestamp_input); g3.addWidget(self.progress)
        group_sign.setLayout(g3); layout.addWidget(group_sign)

        layout.addStretch()
        widget.setLayout(layout)
        return widget

    def build_cert_manager_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()

        # --- Generate PFX
        group_cert = QGroupBox("Generate Certificate")
        g2 = QHBoxLayout()
        self.organization_input = QLineEdit("")
        self.publisher_input = QLineEdit("")
        self.pfx_pass_input = QLineEdit(); self.pfx_pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.pfx_pass_input.setPlaceholderText("Password")
        self.pfx_line = QLineEdit(); self.pfx_line.setReadOnly(True)
        btn_gen = QPushButton("Generate Certificate"); btn_gen.clicked.connect(self.generate_cert)
        g2.addWidget(QLabel("Organization:")); g2.addWidget(self.organization_input)
        g2.addWidget(QLabel("Publisher:")); g2.addWidget(self.publisher_input)
        g2.addWidget(QLabel("Password:")); g2.addWidget(self.pfx_pass_input)
        g2.addWidget(self.pfx_line); g2.addWidget(btn_gen)
        group_cert.setLayout(g2); layout.addWidget(group_cert)

        # --- Install Certificate
        group_install = QGroupBox("Install Certificate to Trusted Publishers")
        g_install = QHBoxLayout()
        self.cert_pfx_input = QLineEdit(); self.cert_pfx_input.setReadOnly(True)
        btn_browse_cert = QPushButton("Select..."); btn_browse_cert.clicked.connect(self.browse_cert_pfx)
        self.cert_pwd_input = QLineEdit(); self.cert_pwd_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.cert_pwd_input.setPlaceholderText("Password")
        btn_install = QPushButton("Install"); btn_install.clicked.connect(self.install_cert_only)
        self.install_progress = QProgressBar()
        g_install.addWidget(QLabel("Certificate:")); g_install.addWidget(self.cert_pfx_input); g_install.addWidget(btn_browse_cert)
        g_install.addWidget(QLabel("Password:")); g_install.addWidget(self.cert_pwd_input)
        g_install.addWidget(btn_install); g_install.addWidget(self.install_progress)
        group_install.setLayout(g_install); layout.addWidget(group_install)

        layout.addStretch()
        widget.setLayout(layout)
        return widget

    # --- Handlers ---
    def append_log(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log.append(f"[{ts}] {msg}")

    def browse_exe(self):
        start_dir = self._last_exe_dir if os.path.isdir(self._last_exe_dir) else ""
        path, _ = QFileDialog.getOpenFileName(self, "Select EXE", start_dir, "PE Executables (*.exe)")
        if path:
            self._last_exe_dir = os.path.dirname(path)  
            self._exe_path = path
            self.exe_line.setText(path)
            self.append_log(f"Selected {path}")

    def check_admin_status(self):
        """Check if the app is running with admin rights and update UI/log."""
        try:
            admin = is_admin()
            self._is_admin = admin
            if admin:
                self.admin_label.setText("Administrator: Yes")
                self.admin_label.setStyleSheet("color: green; font-weight: bold;")
                self.append_log("Running with administrator privileges.")
            else:
                self.admin_label.setText("Administrator: No")
                self.admin_label.setStyleSheet("color: orange; font-weight: bold;")
                self.append_log("Not running as administrator.")
        except Exception as e:
            self.admin_label.setText("Administrator: Unknown")
            self.append_log("Admin check failed: " + str(e))

    def generate_cert(self):
        org = self.organization_input.text().strip() or COMPANY
        pub = self.publisher_input.text().strip()
        pwd = self.pfx_pass_input.text() or ""
        self.append_log(f"Generating Certificate for {pub} (Organization: {org})...")
        w = RealWorker("generate_cert", {"publisher": pub, "password": pwd, "organization": org}, self.append_log)
        self.register_worker(w); w.finished.connect(self.on_cert_generated); w.start()

    def on_cert_generated(self, res):
        if not res.get("ok"):
            self.append_log("Certificate generation failed: " + res.get("error", "unknown"))
            return
        self._pfx_path = res["pfx_path"]; self._pfx_password = self.pfx_pass_input.text() or ""
        self.pfx_line.setText(self._pfx_path)
        self.append_log(f"Certificate created: {self._pfx_path}")

    def select_pfx(self):
        start_dir = self._last_pfx_dir if os.path.isdir(self._last_pfx_dir) else ""
        path, _ = QFileDialog.getOpenFileName(self, "Select PFX", start_dir, "PFX Files (*.pfx)")
        if path:
            self._last_pfx_dir = os.path.dirname(path)
            pwd, ok = QInputDialog.getText(self, "Password", "Enter password (or leave empty):", QLineEdit.EchoMode.Password)
            if ok:
                self._pfx_path = path
                self._pfx_password = pwd
                self.select_pfx_line.setText(path)
                self.append_log(f"Selected PFX: {path}")

    def sign_exe(self):
        if not self._exe_path:
            QMessageBox.warning(self, "Missing", "Select executable first."); return
        if not self._pfx_path:
            QMessageBox.warning(self, "Missing", "Generate or select a PFX first."); return

        # Use the signing-specific publisher input if present, otherwise fall back
        pub = getattr(self, 'signing_publisher_input', None)
        if pub:
            pub = pub.text().strip() or "Neo"
        else:
            pub = self.publisher_input.text().strip() or "Neo"
        ts = self.timestamp_input.text().strip() or None

        self.append_log("Signing EXE...")
        w_sign = RealWorker(
            "sign_file",
            {"exe_path": self._exe_path, "pfx_path": self._pfx_path, "pfx_password": self._pfx_password,
             "publisher": pub, "timestamp_url": ts},
            self.append_log
        )
        self.register_worker(w_sign)
        w_sign.progress.connect(self.progress.setValue)
        w_sign.finished.connect(self.on_signed)
        w_sign.start()

    def browse_cert_pfx(self):
        start_dir = self._last_pfx_dir if os.path.isdir(self._last_pfx_dir) else ""
        path, _ = QFileDialog.getOpenFileName(self, "Select Certificate", start_dir, "PFX Files (*.pfx)")
        if path:
            self._last_pfx_dir = os.path.dirname(path)
            self.cert_pfx_input.setText(path)
            self.append_log(f"Selected Certificate: {path}")

    def install_cert_only(self):
        pfx_path = self.cert_pfx_input.text().strip()
        if not pfx_path:
            QMessageBox.warning(self, "Missing", "Select a certificate file first."); return
        
        password = self.cert_pwd_input.text()
        # If not running as admin, prompt to relaunch elevated
        if not is_admin():
            answer = QMessageBox.question(self, "Administrator rights required",
                                          "Installing a certificate requires administrator rights. Relaunch as administrator?",
                                          QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if answer == QMessageBox.StandardButton.Yes:
                try:
                    self.append_log("Requesting elevation to install certificate...")
                    elevate_and_run_install(pfx_path, password)
                    self.append_log("Elevation requested; please accept the UAC prompt.")
                except Exception as e:
                    self.append_log("Failed to request elevation: " + str(e))
                    QMessageBox.critical(self, "Elevation failed", str(e))
                return
            else:
                self.append_log("User cancelled elevation. Installation aborted.")
                return

        # Already admin -- proceed with threaded install
        self.append_log("Installing certificate into Trusted Publishers...")
        w_install = RealWorker("install_cert", {"pfx_path": pfx_path, "password": password}, self.append_log)
        self.register_worker(w_install)
        w_install.progress.connect(self.install_progress.setValue)
        w_install.finished.connect(self.on_cert_installed)
        w_install.start()

    def on_cert_installed(self, res):
        if not res.get("ok"):
            self.append_log("Certificate installation failed: " + res.get("error", "unknown"))
            QMessageBox.critical(self, "Installation failed", res.get("error", "unknown")); return
        self.append_log("Certificate installed successfully.")
        QMessageBox.information(self, "Done", "Certificate installed to Trusted Publishers.")

    def _after_install(self, install_res, pub, ts):
        if not install_res.get("ok"):
            self.append_log("Certificate installation failed: " + install_res.get("error", "unknown"))
            QMessageBox.warning(self, "Warning", "Certificate installation failed. UAC may still show Unknown Publisher.")
        else:
            self.append_log("Certificate installed successfully.")
        # Continue signing
        w_sign = RealWorker(
            "sign_file",
            {"exe_path": self._exe_path, "pfx_path": self._pfx_path, "pfx_password": self._pfx_password,
             "publisher": pub, "timestamp_url": ts},
            self.append_log
        )
        self.register_worker(w_sign)
        w_sign.finished.connect(self.on_signed)
        w_sign.start()

    def on_signed(self, res):
        if not res.get("ok"):
            self.append_log("Signing failed: " + res.get("error", "unknown"))
            QMessageBox.critical(self, "Signing failed", res.get("error", "unknown")); return
        self.append_log(f"Signed: {res['signed_path']}")
        QMessageBox.information(self, "Done", "Signing complete.")

    def register_worker(self, w):
        self.workers.append(w)
        w.progress.connect(self.progress.setValue)
        w.finished.connect(lambda _: self.workers.remove(w))

    def open_output_folder(self):
        if not self._exe_path: return
        out_dir = os.path.join(os.path.dirname(self._exe_path), "neo_signed")
        os.makedirs(out_dir, exist_ok=True)
        if sys.platform.startswith("win"):
            os.startfile(out_dir)

# ---------------------------- Run ----------------------------
def main():
    # Headless elevated install path: when relached with --elev-install <pfx> <password>
    if "--elev-install" in sys.argv:
        try:
            idx = sys.argv.index("--elev-install")
            pfx_path = sys.argv[idx + 1]
            password = sys.argv[idx + 2] if len(sys.argv) > idx + 2 else ""
        except Exception as e:
            print("Invalid arguments for --elev-install", e)
            sys.exit(2)
        res = install_pfx_direct(pfx_path, password)
        # Show a simple message box via Win32 API (works even without a Qt event loop)
        try:
            if res.get("ok"):
                ctypes.windll.user32.MessageBoxW(None, "Certificate installed successfully.", "Neo Signer", 0x40)
                sys.exit(0)
            else:
                ctypes.windll.user32.MessageBoxW(None, f"Installation failed: {res.get('error')}", "Neo Signer", 0x10)
                sys.exit(1)
        except Exception:
            # Fall back to printing if MessageBox fails
            print(res)
            sys.exit(0 if res.get("ok") else 1)

    app = QApplication(sys.argv)
    # set application icon if available
    icon_path = resource_path(os.path.join("assets", "logo.ico"))
    if os.path.isfile(icon_path):
        try:
            app.setWindowIcon(QIcon(icon_path))
        except Exception:
            pass
    win = MainWindow()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()