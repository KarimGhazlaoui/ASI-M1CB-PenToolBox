# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'c:\GitHub\ASI-M1CB-PenToolBox-Interface\app\interface\ui\EngagementInterface.ui'
#
# Created by: PyQt5 UI code generator 5.15.10
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_EngagementInterface(object):
    def setupUi(self, EngagementInterface):
        EngagementInterface.setObjectName("EngagementInterface")
        EngagementInterface.resize(1093, 464)
        EngagementInterface.setMinimumSize(QtCore.QSize(1093, 429))
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(EngagementInterface)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.gridLayout = QtWidgets.QGridLayout()
        self.gridLayout.setContentsMargins(20, 40, 20, 20)
        self.gridLayout.setSpacing(12)
        self.gridLayout.setObjectName("gridLayout")
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setContentsMargins(-1, 10, -1, 10)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.IconWidget_3 = IconWidget(EngagementInterface)
        self.IconWidget_3.setMinimumSize(QtCore.QSize(50, 50))
        self.IconWidget_3.setMaximumSize(QtCore.QSize(50, 50))
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(":/images/agreement.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.IconWidget_3.setIcon(icon)
        self.IconWidget_3.setObjectName("IconWidget_3")
        self.horizontalLayout.addWidget(self.IconWidget_3)
        self.StrongBodyLabel = StrongBodyLabel(EngagementInterface)
        font = QtGui.QFont()
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.StrongBodyLabel.setFont(font)
        self.StrongBodyLabel.setAlignment(QtCore.Qt.AlignCenter)
        self.StrongBodyLabel.setObjectName("StrongBodyLabel")
        self.horizontalLayout.addWidget(self.StrongBodyLabel)
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem)
        self.gridLayout.addLayout(self.horizontalLayout, 0, 0, 1, 1)
        self.gridLayout_2 = QtWidgets.QGridLayout()
        self.gridLayout_2.setContentsMargins(-1, 0, 0, 0)
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.reseauciblecard = CardWidget(EngagementInterface)
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
        spacerItem1 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_2.addItem(spacerItem1)
        self.TitleLabel = TitleLabel(self.reseauciblecard)
        font = QtGui.QFont()
        font.setPointSize(16)
        font.setBold(True)
        font.setWeight(75)
        self.TitleLabel.setFont(font)
        self.TitleLabel.setObjectName("TitleLabel")
        self.horizontalLayout_2.addWidget(self.TitleLabel)
        spacerItem2 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_2.addItem(spacerItem2)
        self.verticalLayout_5.addLayout(self.horizontalLayout_2)
        self.verticalLayout_6.addLayout(self.verticalLayout_5)
        self.HorizontalSeparator_2 = HorizontalSeparator(self.reseauciblecard)
        self.HorizontalSeparator_2.setObjectName("HorizontalSeparator_2")
        self.verticalLayout_6.addWidget(self.HorizontalSeparator_2)
        self.gridLayout_3 = QtWidgets.QGridLayout()
        self.gridLayout_3.setContentsMargins(-1, -1, -1, 0)
        self.gridLayout_3.setVerticalSpacing(0)
        self.gridLayout_3.setObjectName("gridLayout_3")
        self.CheckBox_2 = CheckBox(self.reseauciblecard)
        self.CheckBox_2.setMinimumSize(QtCore.QSize(29, 22))
        self.CheckBox_2.setObjectName("CheckBox_2")
        self.gridLayout_3.addWidget(self.CheckBox_2, 3, 0, 1, 1)
        self.CheckBox = CheckBox(self.reseauciblecard)
        self.CheckBox.setMinimumSize(QtCore.QSize(29, 22))
        self.CheckBox.setObjectName("CheckBox")
        self.gridLayout_3.addWidget(self.CheckBox, 2, 0, 1, 1)
        self.CaptionLabel = CaptionLabel(self.reseauciblecard)
        self.CaptionLabel.setObjectName("CaptionLabel")
        self.gridLayout_3.addWidget(self.CaptionLabel, 9, 0, 1, 1)
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_3.setContentsMargins(-1, -1, -1, 0)
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.PrimaryPushButton = PrimaryPushButton(self.reseauciblecard)
        font = QtGui.QFont()
        font.setPointSize(11)
        font.setBold(True)
        font.setWeight(75)
        self.PrimaryPushButton.setFont(font)
        self.PrimaryPushButton.setObjectName("PrimaryPushButton")
        self.horizontalLayout_3.addWidget(self.PrimaryPushButton)
        spacerItem3 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_3.addItem(spacerItem3)
        self.gridLayout_3.addLayout(self.horizontalLayout_3, 7, 0, 1, 1)
        self.horizontalLayout_6 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_6.setContentsMargins(-1, -1, -1, 20)
        self.horizontalLayout_6.setObjectName("horizontalLayout_6")
        self.gridLayout_3.addLayout(self.horizontalLayout_6, 4, 0, 1, 1)
        self.TitleLabel_2 = TitleLabel(self.reseauciblecard)
        self.TitleLabel_2.setObjectName("TitleLabel_2")
        self.gridLayout_3.addWidget(self.TitleLabel_2, 0, 0, 1, 1)
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_4.setContentsMargins(-1, -1, -1, 20)
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        self.gridLayout_3.addLayout(self.horizontalLayout_4, 6, 0, 1, 1)
        self.HorizontalSeparator = HorizontalSeparator(self.reseauciblecard)
        self.HorizontalSeparator.setObjectName("HorizontalSeparator")
        self.gridLayout_3.addWidget(self.HorizontalSeparator, 5, 0, 1, 1)
        self.horizontalLayout_5 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_5.setContentsMargins(-1, -1, -1, 20)
        self.horizontalLayout_5.setObjectName("horizontalLayout_5")
        self.gridLayout_3.addLayout(self.horizontalLayout_5, 1, 0, 1, 1)
        self.horizontalLayout_7 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_7.setContentsMargins(-1, -1, -1, 10)
        self.horizontalLayout_7.setObjectName("horizontalLayout_7")
        self.gridLayout_3.addLayout(self.horizontalLayout_7, 8, 0, 1, 1)
        self.verticalLayout_6.addLayout(self.gridLayout_3)
        self.gridLayout_2.addWidget(self.reseauciblecard, 0, 0, 1, 1)
        self.gridLayout.addLayout(self.gridLayout_2, 1, 0, 1, 1)
        spacerItem4 = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.gridLayout.addItem(spacerItem4, 2, 0, 1, 1)
        self.verticalLayout_2.addLayout(self.gridLayout)

        self.retranslateUi(EngagementInterface)
        QtCore.QMetaObject.connectSlotsByName(EngagementInterface)

    def retranslateUi(self, EngagementInterface):
        _translate = QtCore.QCoreApplication.translate
        EngagementInterface.setWindowTitle(_translate("EngagementInterface", "Form"))
        self.StrongBodyLabel.setText(_translate("EngagementInterface", "Interactions Pré-engagement"))
        self.TitleLabel.setText(_translate("EngagementInterface", "KGB PenToolBox - CONFIRMATION DES INTERACTIONS PRÉ-ENGAGEMENT"))
        self.CheckBox_2.setText(_translate("EngagementInterface", "Je comprends qu\'un défaut de réalisation des interactions pré-engagement peut entraîner des tests non autorisés et des conséquences légales."))
        self.CheckBox.setText(_translate("EngagementInterface", "Je confirme que des discussions pré-engagement ont eu lieu et que toutes les parties ont accepté les règles d\'engagement, la portée et les considérations légales."))
        self.CaptionLabel.setText(_translate("EngagementInterface", "Veuillez cocher les cases pour confirmer, puis appuyez sur [Continuer] pour déverrouiller l\'interface de la PenToolBox."))
        self.PrimaryPushButton.setText(_translate("EngagementInterface", "Continuer"))
        self.TitleLabel_2.setText(_translate("EngagementInterface", "<html><head/><body><p><span style=\" font-size:10pt;\">Avant d\'accéder aux fonctionnalités du PenToolBox, veuillez confirmer que les étapes préliminaires de discussion ont été réalisées.</span></p></body></html>"))
from qfluentwidgets import CaptionLabel, CardWidget, CheckBox, HorizontalSeparator, IconWidget, PrimaryPushButton, StrongBodyLabel, TitleLabel
import app.resource.resource_rc