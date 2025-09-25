import sys
import platform
import subprocess
import socket
import re
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QFormLayout, QLabel,
    QLineEdit, QPushButton, QTableWidget, QTableWidgetItem,
    QCheckBox, QMessageBox, QSpinBox, QGroupBox, QSplitter, QSizePolicy,
    QProgressBar, QMenu, QTabWidget
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor, QFont

# ---------------- 工具函数 ----------------
def run_cmd_silent(cmd, timeout=None):
    """在 Windows 下隐藏黑框执行命令"""
    system = platform.system().lower()
    si = None
    creationflags = 0
    if system == "windows":
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        creationflags = subprocess.CREATE_NO_WINDOW
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        startupinfo=si,
        creationflags=creationflags
    )

def run_cmd_output(cmd, timeout=None):
    """在 Windows 下隐藏黑框并返回输出"""
    system = platform.system().lower()
    si = None
    creationflags = 0
    if system == "windows":
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        creationflags = subprocess.CREATE_NO_WINDOW
    return subprocess.check_output(
        cmd,
        timeout=timeout,
        startupinfo=si,
        creationflags=creationflags
    )

def ping_host(ip, timeout=1.0):
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(timeout)), ip]
    try:
        proc = run_cmd_silent(cmd, timeout=timeout + 0.8)
        return proc.returncode == 0
    except Exception:
        return False

def is_port_open(ip, port=3389, timeout=1.5):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((ip, port)) == 0
    except Exception:
        return False

def get_hostname(ip):
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return None

def get_mac(ip):
    system = platform.system().lower()
    if system == "windows":
        cmd = ["arp", "-a", ip]
    else:
        cmd = ["arp", "-n", ip]
    try:
        out = run_cmd_output(cmd).decode(errors="ignore")
        mac = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", out)
        return mac.group(0) if mac else None
    except Exception:
        return None

def scan_one(ip, do_ping=True, do_port=True, ping_timeout=1.0, rdp_timeout=1.5):
    res = {"ip": ip, "ping": False, "rdp_open": False, "hostname": None, "mac": None}
    if do_ping:
        if ping_host(ip, ping_timeout):
            res["ping"] = True
            res["hostname"] = get_hostname(ip)
            res["mac"] = get_mac(ip)
            if do_port:
                res["rdp_open"] = is_port_open(ip, 3389, rdp_timeout)
    else:
        if do_port:
            res["rdp_open"] = is_port_open(ip, 3389, rdp_timeout)
    return res

# ---------------- 扫描线程 ----------------
class ScannerThread(QThread):
    progress = pyqtSignal(dict)
    finished = pyqtSignal(list)

    def __init__(self, prefix, ip_start, ip_end, workers, do_ping, do_port, ping_timeout=1, rdp_timeout=1.5, parent=None):
        super().__init__(parent)
        self.prefix = prefix
        self.ip_start = ip_start
        self.ip_end = ip_end
        self.workers = workers
        self.do_ping = do_ping
        self.do_port = do_port
        self.ping_timeout = ping_timeout
        self.rdp_timeout = rdp_timeout
        self._stop_flag = False

    def run(self):
        ips = [f"{self.prefix}.{i}" for i in range(self.ip_start, self.ip_end+1)]
        results = []
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            futures = {ex.submit(scan_one, ip, self.do_ping, self.do_port, self.ping_timeout, self.rdp_timeout): ip for ip in ips}

            while futures and not self._stop_flag:
                done, _ = wait(futures.keys(), timeout=0.1, return_when=FIRST_COMPLETED)
                for fut in done:
                    ip = futures.pop(fut)
                    try:
                        r = fut.result()
                    except Exception:
                        r = {"ip": ip, "ping": False, "rdp_open": False, "hostname": None, "mac": None}
                    self.progress.emit(r)
                    results.append(r)

        if not self._stop_flag:
            self.finished.emit(results)

    def stop(self):
        self._stop_flag = True

# ---------------- 主窗口 ----------------
class RDPScanner(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("RDP 扫描器")
        self.resize(1200, 850)
        self.setFont(QFont("Segoe UI", 10))

        self.results = []
        self.scanner = None
        self.ip_list = []

        self.init_ui()
        self.set_styles()
        self.connect_signals()

    def init_ui(self):
        form_layout = QFormLayout()
        self.prefix_edit = QLineEdit("172.16.4")
        self.start_spin = QSpinBox(); self.start_spin.setRange(1,254); self.start_spin.setValue(1)
        self.end_spin = QSpinBox(); self.end_spin.setRange(1,254); self.end_spin.setValue(255)
        self.workers_spin = QSpinBox(); self.workers_spin.setRange(1,100); self.workers_spin.setValue(6)
        self.ping_timeout_spin = QSpinBox(); self.ping_timeout_spin.setRange(1,10); self.ping_timeout_spin.setValue(1)
        self.rdp_timeout_spin = QSpinBox(); self.rdp_timeout_spin.setRange(1,10); self.rdp_timeout_spin.setValue(2)
        self.cb_no_ping = QCheckBox("跳过 Ping")
        self.cb_no_port = QCheckBox("不检测端口")

        form_layout.addRow("IP 前缀:", self.prefix_edit)
        form_layout.addRow("起始 IP:", self.start_spin)
        form_layout.addRow("结束 IP:", self.end_spin)
        form_layout.addRow("线程数:", self.workers_spin)

        timeout_layout = QHBoxLayout()
        timeout_layout.addWidget(QLabel("Ping超时:")); timeout_layout.addWidget(self.ping_timeout_spin)
        timeout_layout.addSpacing(10)
        timeout_layout.addWidget(QLabel("RDP超时:")); timeout_layout.addWidget(self.rdp_timeout_spin)
        form_layout.addRow(timeout_layout)

        checkbox_layout = QHBoxLayout()
        checkbox_layout.addWidget(self.cb_no_ping)
        checkbox_layout.addWidget(self.cb_no_port)
        checkbox_layout.addStretch()
        form_layout.addRow(checkbox_layout)

        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("开始扫描")
        self.start_btn.setFixedWidth(120)
        self.cancel_btn = QPushButton("取消扫描")
        self.cancel_btn.setFixedWidth(120)
        self.cancel_btn.setEnabled(False)
        btn_layout.addStretch()
        btn_layout.addWidget(self.start_btn)
        btn_layout.addSpacing(15)
        btn_layout.addWidget(self.cancel_btn)
        btn_layout.addStretch()
        form_layout.addRow(btn_layout)

        param_group = QGroupBox("扫描参数")
        param_group.setLayout(form_layout)

        self.table = QTableWidget(0,5)
        self.table.setHorizontalHeaderLabels(["IP","Ping","RDP(3389)","主机名","MAC"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setColumnWidth(3, 250)  # 主机名列宽
        self.table.setColumnWidth(4, 160)  # MAC列宽
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setDefaultSectionSize(28)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("扫描进度: %p% (0/0)")

        top_splitter = QSplitter(Qt.Horizontal)
        left_widget = QWidget(); left_layout = QVBoxLayout()
        left_layout.addWidget(param_group)
        left_layout.addWidget(self.progress_bar)
        left_layout.addStretch()
        left_widget.setLayout(left_layout)
        left_widget.setMinimumWidth(320)
        top_splitter.addWidget(left_widget)
        top_splitter.addWidget(self.table)
        top_splitter.setSizes([320, 880])

        self.category_tab = QTabWidget()
        self.group_ping = self.create_group_table("仅 Ping 通")
        self.group_rdp = self.create_group_table("仅 RDP 通")
        self.group_both = self.create_group_table("Ping + RDP 都通")
        self.group_neither = self.create_group_table("都不通")
        self.category_tab.addTab(self.group_ping, "仅 Ping 通")
        self.category_tab.addTab(self.group_rdp, "仅 RDP 通")
        self.category_tab.addTab(self.group_both, "Ping + RDP 都通")
        self.category_tab.addTab(self.group_neither, "都不通")

        main_splitter = QSplitter(Qt.Vertical)
        main_splitter.addWidget(top_splitter)
        main_splitter.addWidget(self.category_tab)
        main_splitter.setSizes([500, 350])
        main_layout = QVBoxLayout()
        main_layout.addWidget(main_splitter)
        self.setLayout(main_layout)

    def set_styles(self):
        self.setStyleSheet("""
        QWidget { background-color: #f0f2f5; font-size: 11pt; }
        QPushButton { background-color: #4CAF50; color: white; border-radius: 4px; padding: 5px 10px; }
        QPushButton:hover { background-color: #45a049; }
        QPushButton#cancel { background-color: #f44336; }
        QPushButton#cancel:hover { background-color: #da190b; }
        QTableWidget { background-color: #ffffff; alternate-background-color: #f9f9f9; gridline-color: #d0d0d0; }
        QHeaderView::section { background-color: #e0e0e0; font-weight: bold; }
        QTableWidget::item:selected { background-color: #a0d7ff; }
        QProgressBar { border: 1px solid #c0c0c0; border-radius: 5px; text-align: center; height: 22px; }
        QProgressBar::chunk { background-color: #4CAF50; }
        """)

    def connect_signals(self):
        self.start_btn.clicked.connect(self.start_scan)
        self.cancel_btn.clicked.connect(self.cancel_scan)

    def create_group_table(self, title):
        group = QGroupBox(title)
        table = QTableWidget(0,2)
        table.setHorizontalHeaderLabels(["IP", "主机名"])
        table.horizontalHeader().setStretchLastSection(True)
        table.setAlternatingRowColors(True)
        table.setSizePolicy(QSizePolicy.Expanding,QSizePolicy.Expanding)
        table.setContextMenuPolicy(Qt.CustomContextMenu)
        table.customContextMenuRequested.connect(lambda pos, t=table: self.right_click_table(t,pos))
        layout = QVBoxLayout()
        layout.addWidget(table)
        group.setLayout(layout)
        group.table = table
        return group

    def right_click_table(self, table, pos):
        menu = QMenu()
        menu.addAction("复制选中 IP", lambda: self.copy_selected_rows(table))
        menu.exec_(table.mapToGlobal(pos))

    def copy_selected_rows(self, table):
        rows = set(idx.row() for idx in table.selectedIndexes())
        text = "\n".join(table.item(r,0).text() for r in rows)
        QApplication.clipboard().setText(text)
        QMessageBox.information(self,"已复制",f"已复制 {len(rows)} 个 IP 到剪贴板")

    def start_scan(self):
        prefix = self.prefix_edit.text().strip()
        ip_start = self.start_spin.value()
        ip_end = self.end_spin.value()
        workers = self.workers_spin.value()
        do_ping = not self.cb_no_ping.isChecked()
        do_port = not self.cb_no_port.isChecked()
        ping_timeout = self.ping_timeout_spin.value()
        rdp_timeout = self.rdp_timeout_spin.value()

        self.ip_list = [f"{prefix}.{i}" for i in range(ip_start, ip_end+1)]
        self.table.setRowCount(len(self.ip_list))
        for idx, ip in enumerate(self.ip_list):
            self.table.setItem(idx, 0, QTableWidgetItem(ip))
            self.table.setItem(idx, 1, QTableWidgetItem(""))
            self.table.setItem(idx, 2, QTableWidgetItem(""))
            self.table.setItem(idx, 3, QTableWidgetItem(""))
            self.table.setItem(idx, 4, QTableWidgetItem(""))

        self.results = []
        self.progress_bar.setValue(0)
        self.progress_bar.setMaximum(len(self.ip_list))
        self.disable_params(True)
        self.start_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)

        for g in [self.group_ping,self.group_rdp,self.group_both,self.group_neither]:
            g.table.setRowCount(0)

        self.scanner = ScannerThread(prefix, ip_start, ip_end, workers, do_ping, do_port, ping_timeout, rdp_timeout)
        self.scanner.progress.connect(self.add_result)
        self.scanner.finished.connect(self.scan_done)
        self.scanner.start()

    def cancel_scan(self):
        if self.scanner:
            self.scanner.stop()
            QMessageBox.information(self,"取消","扫描已取消")
            self.disable_params(False)
            self.start_btn.setEnabled(True)
            self.cancel_btn.setEnabled(False)

    def disable_params(self, disable):
        for w in [self.prefix_edit, self.start_spin, self.end_spin, self.workers_spin,
                  self.cb_no_ping, self.cb_no_port, self.ping_timeout_spin, self.rdp_timeout_spin]:
            w.setDisabled(disable)

    def add_result(self, r):
        try:
            row_index = self.ip_list.index(r["ip"])
        except ValueError:
            return

        ping_item = QTableWidgetItem(str(r["ping"]))
        rdp_item = QTableWidgetItem(str(r["rdp_open"]))
        ping_item.setBackground(QColor(144,238,144) if r["ping"] else QColor(220,220,220))
        rdp_item.setBackground(QColor(173,216,230) if r["rdp_open"] else QColor(220,220,220))
        self.table.setItem(row_index,1,ping_item)
        self.table.setItem(row_index,2,rdp_item)
        self.table.setItem(row_index,3,QTableWidgetItem(r.get("hostname") or ""))
        self.table.setItem(row_index,4,QTableWidgetItem(r.get("mac") or ""))
        self.results.append(r)

        self.progress_bar.setValue(len(self.results))
        self.progress_bar.setFormat(f"{len(self.results)}/{len(self.ip_list)} 扫描中: {r['ip']}")

    def scan_done(self, results):
        self.disable_params(False)
        self.start_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.progress_bar.setValue(self.progress_bar.maximum())

        ping_only = [(r["ip"], r["hostname"]) for r in results if r["ping"] and not r["rdp_open"]]
        rdp_only  = [(r["ip"], r["hostname"]) for r in results if r["rdp_open"] and not r["ping"]]
        both      = [(r["ip"], r["hostname"]) for r in results if r["ping"] and r["rdp_open"]]
        neither   = [(r["ip"], r["hostname"]) for r in results if not r["ping"] and not r["rdp_open"]]

        self.fill_table(self.group_ping.table, ping_only)
        self.fill_table(self.group_rdp.table, rdp_only)
        self.fill_table(self.group_both.table, both)
        self.fill_table(self.group_neither.table, neither)

        self.category_tab.setTabText(0,f"仅 Ping 通 ({len(ping_only)})")
        self.category_tab.setTabText(1,f"仅 RDP 通 ({len(rdp_only)})")
        self.category_tab.setTabText(2,f"Ping + RDP 都通 ({len(both)})")
        self.category_tab.setTabText(3,f"都不通 ({len(neither)})")

        QMessageBox.information(self,"完成",f"扫描完成，共 {len(results)} 条结果。")

    def fill_table(self, table, data):
        table.setRowCount(0)
        for ip, hostname in data:
            row = table.rowCount()
            table.insertRow(row)
            table.setItem(row,0,QTableWidgetItem(ip))
            table.setItem(row,1,QTableWidgetItem(hostname or ""))

    def closeEvent(self, event):
        if self.scanner and self.scanner.isRunning():
            reply = QMessageBox.question(self, '退出', '扫描仍在进行，确定退出吗？',
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.scanner.stop()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()

# ---------------- 入口 ----------------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = RDPScanner()
    w.show()
    sys.exit(app.exec_())

