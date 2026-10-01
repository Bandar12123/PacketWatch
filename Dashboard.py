import sys

from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QTableWidget, QTableWidgetItem, QGroupBox, QGridLayout,
)

from sniffer import start_sniffing, get_snapshot, hostname_of

def num_item(n):
    def num_item(n):
    item = QTableWidgetItem(f"{n:,}")
    item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
    return item 