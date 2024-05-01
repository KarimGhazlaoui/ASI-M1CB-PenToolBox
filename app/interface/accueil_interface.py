from PyQt5.QtCore import Qt, QRectF
from PyQt5.QtGui import QPixmap, QPainter, QColor, QBrush, QPainterPath, QLinearGradient
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel

from qfluentwidgets import FluentIcon

from ..components.link_card import LinkCardView
from ..common.config import HELP_URL, REPO_URL, EXAMPLE_URL

class AccueilInterface(QWidget):

    def __init__(self, parent=None):
        super().__init__(parent=parent)

        self.setFixedHeight(336)

        self.vBoxLayout = QVBoxLayout(self)
        self.galleryLabel = QLabel('Accès rapide', self)
        self.banner = QPixmap(':/gallery/images/header1.png')
        self.linkCardView = LinkCardView(self)

        self.galleryLabel.setObjectName('galleryLabel')

        self.vBoxLayout.setSpacing(0)
        self.vBoxLayout.setContentsMargins(0, 20, 0, 0)
        self.vBoxLayout.addWidget(self.galleryLabel)
        self.vBoxLayout.addWidget(self.linkCardView, 1, Qt.AlignBottom)
        self.vBoxLayout.setAlignment(Qt.AlignLeft | Qt.AlignTop)

        self.linkCardView.addCard(
            ':/gallery/images/logo.png',
            self.tr("Guide d'utilisation"),
            self.tr('Guide version espresso concentré'),
            HELP_URL
        )

        self.linkCardView.addCard(
            FluentIcon.GITHUB,
            self.tr('GitHub'),
            self.tr(
                "Découvre le code sur GitHub."),
            REPO_URL
        )

        self.linkCardView.addCard(
            FluentIcon.FINGERPRINT,
            self.tr('Scan Rapide'),
            self.tr(
                "Un clic, un scan, des failles révélées."),
            EXAMPLE_URL
        )

        self.linkCardView.addCard(
            FluentIcon.DICTIONARY,
            self.tr('Rapports'),
            self.tr(
                "C'est comme ouvrir une boîte de pandore."),
            EXAMPLE_URL
        )
