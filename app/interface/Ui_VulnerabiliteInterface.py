# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'c:\GitHub\ASI-M1CB-PenToolBox\app\interface\ui\VulnerabiliteInterface.ui'
#
# Created by: PyQt5 UI code generator 5.15.10
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_VulnerabiliteInterface(object):
    def setupUi(self, VulnerabiliteInterface):
        VulnerabiliteInterface.setObjectName("VulnerabiliteInterface")
        VulnerabiliteInterface.resize(1520, 1024)
        VulnerabiliteInterface.setMinimumSize(QtCore.QSize(804, 858))
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(VulnerabiliteInterface)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.gridLayout = QtWidgets.QGridLayout()
        self.gridLayout.setContentsMargins(20, 40, 20, 20)
        self.gridLayout.setSpacing(12)
        self.gridLayout.setObjectName("gridLayout")
        self.gridLayout_3 = QtWidgets.QGridLayout()
        self.gridLayout_3.setContentsMargins(-1, -1, -1, 0)
        self.gridLayout_3.setObjectName("gridLayout_3")
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_4.setContentsMargins(-1, -1, -1, 0)
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_4.addItem(spacerItem)
        self.StrongBodyLabel_2 = StrongBodyLabel(VulnerabiliteInterface)
        self.StrongBodyLabel_2.setObjectName("StrongBodyLabel_2")
        self.horizontalLayout_4.addWidget(self.StrongBodyLabel_2)
        spacerItem1 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_4.addItem(spacerItem1)
        self.gridLayout_3.addLayout(self.horizontalLayout_4, 0, 0, 1, 1)
        self.horizontalLayout_5 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_5.setContentsMargins(-1, -1, -1, 0)
        self.horizontalLayout_5.setObjectName("horizontalLayout_5")
        self.scanvulnerabilite = PrimaryPushButton(VulnerabiliteInterface)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(":/images/strikeicon.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.scanvulnerabilite.setIcon(icon)
        self.scanvulnerabilite.setIconSize(QtCore.QSize(30, 30))
        self.scanvulnerabilite.setProperty("hasIcon", True)
        self.scanvulnerabilite.setObjectName("scanvulnerabilite")
        self.horizontalLayout_5.addWidget(self.scanvulnerabilite)
        self.gridLayout_3.addLayout(self.horizontalLayout_5, 1, 0, 1, 1)
        self.gridLayout.addLayout(self.gridLayout_3, 2, 0, 1, 1)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setContentsMargins(-1, 10, -1, 10)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.IconWidget_3 = IconWidget(VulnerabiliteInterface)
        self.IconWidget_3.setMinimumSize(QtCore.QSize(50, 50))
        self.IconWidget_3.setMaximumSize(QtCore.QSize(50, 50))
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap(":/images/vulnerabilite.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.IconWidget_3.setIcon(icon1)
        self.IconWidget_3.setObjectName("IconWidget_3")
        self.horizontalLayout.addWidget(self.IconWidget_3)
        self.StrongBodyLabel = StrongBodyLabel(VulnerabiliteInterface)
        font = QtGui.QFont()
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.StrongBodyLabel.setFont(font)
        self.StrongBodyLabel.setAlignment(QtCore.Qt.AlignCenter)
        self.StrongBodyLabel.setObjectName("StrongBodyLabel")
        self.horizontalLayout.addWidget(self.StrongBodyLabel)
        spacerItem2 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem2)
        self.gridLayout.addLayout(self.horizontalLayout, 0, 0, 1, 1)
        self.gridLayout_2 = QtWidgets.QGridLayout()
        self.gridLayout_2.setContentsMargins(-1, 0, 0, 0)
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.reseauciblecard = CardWidget(VulnerabiliteInterface)
        self.reseauciblecard.setEnabled(True)
        self.reseauciblecard.setMinimumSize(QtCore.QSize(0, 0))
        self.reseauciblecard.setObjectName("reseauciblecard")
        self.verticalLayout_6 = QtWidgets.QVBoxLayout(self.reseauciblecard)
        self.verticalLayout_6.setObjectName("verticalLayout_6")
        self.verticalLayout_5 = QtWidgets.QVBoxLayout()
        self.verticalLayout_5.setObjectName("verticalLayout_5")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        spacerItem3 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_2.addItem(spacerItem3)
        self.IconWidget = IconWidget(self.reseauciblecard)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(30)
        sizePolicy.setVerticalStretch(30)
        sizePolicy.setHeightForWidth(self.IconWidget.sizePolicy().hasHeightForWidth())
        self.IconWidget.setSizePolicy(sizePolicy)
        self.IconWidget.setMinimumSize(QtCore.QSize(30, 30))
        self.IconWidget.setMaximumSize(QtCore.QSize(30, 30))
        icon2 = QtGui.QIcon()
        icon2.addPixmap(QtGui.QPixmap(":/images/target.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.IconWidget.setIcon(icon2)
        self.IconWidget.setObjectName("IconWidget")
        self.horizontalLayout_2.addWidget(self.IconWidget)
        self.TitleLabel = TitleLabel(self.reseauciblecard)
        font = QtGui.QFont()
        font.setPointSize(16)
        font.setBold(True)
        font.setWeight(75)
        self.TitleLabel.setFont(font)
        self.TitleLabel.setObjectName("TitleLabel")
        self.horizontalLayout_2.addWidget(self.TitleLabel)
        spacerItem4 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_2.addItem(spacerItem4)
        self.verticalLayout_5.addLayout(self.horizontalLayout_2)
        self.verticalLayout_6.addLayout(self.verticalLayout_5)
        self.HorizontalSeparator_2 = HorizontalSeparator(self.reseauciblecard)
        self.HorizontalSeparator_2.setObjectName("HorizontalSeparator_2")
        self.verticalLayout_6.addWidget(self.HorizontalSeparator_2)
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_3.setContentsMargins(-1, 10, -1, 20)
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.vulnerabilitetable = TableWidget(self.reseauciblecard)
        self.vulnerabilitetable.setMinimumSize(QtCore.QSize(700, 500))
        self.vulnerabilitetable.setObjectName("vulnerabilitetable")
        self.vulnerabilitetable.setColumnCount(0)
        self.vulnerabilitetable.setRowCount(0)
        self.horizontalLayout_3.addWidget(self.vulnerabilitetable)
        self.verticalLayout_6.addLayout(self.horizontalLayout_3)
        self.gridLayout_2.addWidget(self.reseauciblecard, 0, 0, 1, 1)
        self.gridLayout.addLayout(self.gridLayout_2, 1, 0, 1, 1)
        self.verticalLayout_2.addLayout(self.gridLayout)

        self.retranslateUi(VulnerabiliteInterface)
        QtCore.QMetaObject.connectSlotsByName(VulnerabiliteInterface)

    def retranslateUi(self, VulnerabiliteInterface):
        _translate = QtCore.QCoreApplication.translate
        VulnerabiliteInterface.setWindowTitle(_translate("VulnerabiliteInterface", "Form"))
        self.StrongBodyLabel_2.setText(_translate("VulnerabiliteInterface", "Après avoir vérifier les vulnérabilités, vous pouvez passer à la phase d\'évaluation des vulnérabilités"))
        self.scanvulnerabilite.setText(_translate("VulnerabiliteInterface", "     Evaluations des vulnérabilités"))
        self.StrongBodyLabel.setText(_translate("VulnerabiliteInterface", "Exploitation - Vulnérabilités Détectées"))
        self.TitleLabel.setText(_translate("VulnerabiliteInterface", "Liste des vulnérabilités potentielles détectées"))
from qfluentwidgets import CardWidget, HorizontalSeparator, IconWidget, PrimaryPushButton, StrongBodyLabel, TableWidget, TitleLabel
import app.resource.resource_rc
