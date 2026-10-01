import sys

from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QTableWidget, QTableWidgetItem, QGroupBox, QGridLayout,
)

from packet_sniffer import start_sniffing, get_snapshot, hostname_of


def num_item(n):
    item = QTableWidgetItem(f"{n:,}")
    item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
    return item


class Monitor(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Packet Monitor")
        self.resize(900, 520)

        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)

        kpi_box = QGroupBox("Summary")
        kpi = QGridLayout(kpi_box)
        self.lbl_total  = QLabel("0")
        self.lbl_bytes  = QLabel("0")
        self.lbl_uptime = QLabel("0 s")
        self.lbl_tcp    = QLabel("0")
        self.lbl_udp    = QLabel("0")
        self.lbl_icmp   = QLabel("0")
        self.lbl_other  = QLabel("0")

        for lbl in [self.lbl_total, self.lbl_bytes, self.lbl_uptime,
                    self.lbl_tcp, self.lbl_udp, self.lbl_icmp, self.lbl_other]:
            lbl.setStyleSheet("font-size: 18px; font-weight: 600;")

        kpi.addWidget(QLabel("Total packets"), 0, 0)
        kpi.addWidget(self.lbl_total,          1, 0)
        kpi.addWidget(QLabel("Total bytes"),   0, 1)
        kpi.addWidget(self.lbl_bytes,          1, 1)
        kpi.addWidget(QLabel("Uptime"),        0, 2)
        kpi.addWidget(self.lbl_uptime,         1, 2)

        kpi.addWidget(QLabel("TCP"),   2, 0); kpi.addWidget(self.lbl_tcp,  3, 0)
        kpi.addWidget(QLabel("UDP"),   2, 1); kpi.addWidget(self.lbl_udp,  3, 1)
        kpi.addWidget(QLabel("ICMP"),  2, 2); kpi.addWidget(self.lbl_icmp, 3, 2)
        kpi.addWidget(QLabel("Other"), 2, 3); kpi.addWidget(self.lbl_other,3, 3)

        layout.addWidget(kpi_box)

        row = QHBoxLayout()

        self.src_table = QTableWidget(0, 4)
        self.src_table.setHorizontalHeaderLabels(["Source IP", "Hostname", "Protocol", "Packets"])
        self.src_table.horizontalHeader().setStretchLastSection(True)
        self.src_table.verticalHeader().setVisible(False)
        self.src_table.setColumnWidth(1, 220)

        self.port_table = QTableWidget(0, 3)
        self.port_table.setHorizontalHeaderLabels(["Dest port", "Protocol", "Packets"])
        self.port_table.horizontalHeader().setStretchLastSection(True)
        self.port_table.verticalHeader().setVisible(False)

        src_box  = QGroupBox("Top source IPs")
        QVBoxLayout(src_box).addWidget(self.src_table)

        port_box = QGroupBox("Top destination ports")
        QVBoxLayout(port_box).addWidget(self.port_table)

        row.addWidget(src_box, 2)
        row.addWidget(port_box, 1)
        layout.addLayout(row)

        start_sniffing()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(1000)

    def refresh(self):
        s = get_snapshot()

        self.lbl_total.setText(f"{s['total']:,}")
        self.lbl_bytes.setText(f"{s['bytes']:,}")
        self.lbl_uptime.setText(f"{s['uptime']} s")
        self.lbl_tcp.setText(f"{s['tcp']:,}")
        self.lbl_udp.setText(f"{s['udp']:,}")
        self.lbl_icmp.setText(f"{s['icmp']:,}")
        self.lbl_other.setText(f"{s['other']:,}")

        self.src_table.setRowCount(len(s["src"]))
        for i, ((ip, proto), count) in enumerate(s["src"]):
            host = hostname_of(ip)
            host = "..." if host is None else (host or "—")
            self.src_table.setItem(i, 0, QTableWidgetItem(ip))
            self.src_table.setItem(i, 1, QTableWidgetItem(host))
            self.src_table.setItem(i, 2, QTableWidgetItem(proto.upper()))
            self.src_table.setItem(i, 3, num_item(count))

        self.port_table.setRowCount(len(s["ports"]))
        for i, ((proto, port), count) in enumerate(s["ports"]):
            self.port_table.setItem(i, 0, QTableWidgetItem(str(port)))
            self.port_table.setItem(i, 1, QTableWidgetItem(proto.upper()))
            self.port_table.setItem(i, 2, num_item(count))


def main():
    app = QApplication(sys.argv)
    win = Monitor()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
