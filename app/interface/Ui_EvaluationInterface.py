# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'c:\GitHub\ASI-M1CB-PenToolBox\app\interface\ui\EvaluationInterface.ui'
#
# Created by: PyQt5 UI code generator 5.15.10
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_EvaluationInterface(object):
    def setupUi(self, EvaluationInterface):
        EvaluationInterface.setObjectName("EvaluationInterface")
        EvaluationInterface.resize(1290, 1031)
        EvaluationInterface.setMinimumSize(QtCore.QSize(1290, 1031))
        self.gridLayout_4 = QtWidgets.QGridLayout(EvaluationInterface)
        self.gridLayout_4.setObjectName("gridLayout_4")
        self.gridLayout = QtWidgets.QGridLayout()
        self.gridLayout.setContentsMargins(20, 40, 20, 20)
        self.gridLayout.setObjectName("gridLayout")
        self.gridLayout_2 = QtWidgets.QGridLayout()
        self.gridLayout_2.setContentsMargins(-1, 0, 0, 0)
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.reseauciblecard = CardWidget(EvaluationInterface)
        self.reseauciblecard.setEnabled(True)
        self.reseauciblecard.setMinimumSize(QtCore.QSize(1230, 812))
        self.reseauciblecard.setObjectName("reseauciblecard")
        self.verticalLayout_6 = QtWidgets.QVBoxLayout(self.reseauciblecard)
        self.verticalLayout_6.setObjectName("verticalLayout_6")
        self.gridLayout_5 = QtWidgets.QGridLayout()
        self.gridLayout_5.setContentsMargins(20, 20, 20, 20)
        self.gridLayout_5.setObjectName("gridLayout_5")
        spacerItem = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.gridLayout_5.addItem(spacerItem, 4, 1, 1, 1)
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_3.setContentsMargins(0, -1, -1, -1)
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        spacerItem1 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_3.addItem(spacerItem1)
        self.IconWidget_2 = IconWidget(self.reseauciblecard)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(30)
        sizePolicy.setVerticalStretch(30)
        sizePolicy.setHeightForWidth(self.IconWidget_2.sizePolicy().hasHeightForWidth())
        self.IconWidget_2.setSizePolicy(sizePolicy)
        self.IconWidget_2.setMinimumSize(QtCore.QSize(30, 30))
        self.IconWidget_2.setMaximumSize(QtCore.QSize(30, 30))
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(":/images/tests.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.IconWidget_2.setIcon(icon)
        self.IconWidget_2.setObjectName("IconWidget_2")
        self.horizontalLayout_3.addWidget(self.IconWidget_2)
        self.TitleLabel_4 = TitleLabel(self.reseauciblecard)
        font = QtGui.QFont()
        font.setPointSize(16)
        font.setBold(True)
        font.setWeight(75)
        self.TitleLabel_4.setFont(font)
        self.TitleLabel_4.setObjectName("TitleLabel_4")
        self.horizontalLayout_3.addWidget(self.TitleLabel_4)
        spacerItem2 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_3.addItem(spacerItem2)
        self.gridLayout_5.addLayout(self.horizontalLayout_3, 1, 3, 1, 1)
        spacerItem3 = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.gridLayout_5.addItem(spacerItem3, 4, 3, 1, 1)
        spacerItem4 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_5.addItem(spacerItem4, 2, 4, 1, 1)
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        spacerItem5 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_2.addItem(spacerItem5)
        self.IconWidget = IconWidget(self.reseauciblecard)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(30)
        sizePolicy.setVerticalStretch(30)
        sizePolicy.setHeightForWidth(self.IconWidget.sizePolicy().hasHeightForWidth())
        self.IconWidget.setSizePolicy(sizePolicy)
        self.IconWidget.setMinimumSize(QtCore.QSize(30, 30))
        self.IconWidget.setMaximumSize(QtCore.QSize(30, 30))
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap(":/images/target.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.IconWidget.setIcon(icon1)
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
        spacerItem6 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_2.addItem(spacerItem6)
        self.gridLayout_5.addLayout(self.horizontalLayout_2, 1, 1, 1, 1)
        spacerItem7 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_5.addItem(spacerItem7, 2, 0, 1, 1)
        self.CardWidget = CardWidget(self.reseauciblecard)
        self.CardWidget.setMinimumSize(QtCore.QSize(480, 120))
        self.CardWidget.setMaximumSize(QtCore.QSize(700, 100))
        self.CardWidget.setObjectName("CardWidget")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.CardWidget)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.TitleLabel_2 = TitleLabel(self.CardWidget)
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.TitleLabel_2.setFont(font)
        self.TitleLabel_2.setObjectName("TitleLabel_2")
        self.verticalLayout_2.addWidget(self.TitleLabel_2)
        self.horizontalLayout_6 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_6.setContentsMargins(-1, 10, -1, 100)
        self.horizontalLayout_6.setObjectName("horizontalLayout_6")
        spacerItem8 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_6.addItem(spacerItem8)
        self.CaptionLabel = CaptionLabel(self.CardWidget)
        self.CaptionLabel.setMinimumSize(QtCore.QSize(0, 30))
        self.CaptionLabel.setObjectName("CaptionLabel")
        self.horizontalLayout_6.addWidget(self.CaptionLabel)
        self.hydracomboboxtarget = ComboBox(self.CardWidget)
        self.hydracomboboxtarget.setMinimumSize(QtCore.QSize(250, 30))
        self.hydracomboboxtarget.setObjectName("hydracomboboxtarget")
        self.horizontalLayout_6.addWidget(self.hydracomboboxtarget)
        self.VerticalSeparator = VerticalSeparator(self.CardWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.VerticalSeparator.sizePolicy().hasHeightForWidth())
        self.VerticalSeparator.setSizePolicy(sizePolicy)
        self.VerticalSeparator.setMinimumSize(QtCore.QSize(3, 30))
        self.VerticalSeparator.setObjectName("VerticalSeparator")
        self.horizontalLayout_6.addWidget(self.VerticalSeparator)
        self.hydraexecution = PrimaryPushButton(self.CardWidget)
        self.hydraexecution.setMinimumSize(QtCore.QSize(0, 30))
        self.hydraexecution.setObjectName("hydraexecution")
        self.horizontalLayout_6.addWidget(self.hydraexecution)
        spacerItem9 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_6.addItem(spacerItem9)
        self.verticalLayout_2.addLayout(self.horizontalLayout_6)
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_4.setContentsMargins(-1, -1, -1, 0)
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        self.hydra_progressbar = IndeterminateProgressBar(self.CardWidget)
        self.hydra_progressbar.setObjectName("hydra_progressbar")
        self.hydra_progressbar.setVisible(False)
        self.horizontalLayout_4.addWidget(self.hydra_progressbar)
        self.verticalLayout_2.addLayout(self.horizontalLayout_4)
        self.gridLayout_5.addWidget(self.CardWidget, 2, 1, 1, 1)
        self.CardWidget_2 = CardWidget(self.reseauciblecard)
        self.CardWidget_2.setMinimumSize(QtCore.QSize(480, 120))
        self.CardWidget_2.setMaximumSize(QtCore.QSize(700, 100))
        self.CardWidget_2.setObjectName("CardWidget_2")
        self.verticalLayout_4 = QtWidgets.QVBoxLayout(self.CardWidget_2)
        self.verticalLayout_4.setObjectName("verticalLayout_4")
        self.TitleLabel_3 = TitleLabel(self.CardWidget_2)
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.TitleLabel_3.setFont(font)
        self.TitleLabel_3.setObjectName("TitleLabel_3")
        self.verticalLayout_4.addWidget(self.TitleLabel_3)
        self.horizontalLayout_7 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_7.setContentsMargins(-1, 0, -1, 0)
        self.horizontalLayout_7.setObjectName("horizontalLayout_7")
        spacerItem10 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_7.addItem(spacerItem10)
        self.CaptionLabel_2 = CaptionLabel(self.CardWidget_2)
        self.CaptionLabel_2.setMinimumSize(QtCore.QSize(0, 30))
        self.CaptionLabel_2.setObjectName("CaptionLabel_2")
        self.horizontalLayout_7.addWidget(self.CaptionLabel_2)
        self.passwordchecker = PasswordLineEdit(self.CardWidget_2)
        self.passwordchecker.setMinimumSize(QtCore.QSize(300, 33))
        self.passwordchecker.setObjectName("passwordchecker")
        self.horizontalLayout_7.addWidget(self.passwordchecker)
        spacerItem11 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_7.addItem(spacerItem11)
        self.verticalLayout_4.addLayout(self.horizontalLayout_7)
        self.verticalLayout_7 = QtWidgets.QVBoxLayout()
        self.verticalLayout_7.setContentsMargins(-1, -1, -1, 0)
        self.verticalLayout_7.setObjectName("verticalLayout_7")
        self.complexitepassword = QtWidgets.QLineEdit(self.CardWidget_2)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.complexitepassword.setFont(font)
        self.complexitepassword.setText("")
        self.complexitepassword.setFrame(False)
        self.complexitepassword.setAlignment(QtCore.Qt.AlignCenter)
        self.complexitepassword.setReadOnly(True)
        self.complexitepassword.setObjectName("complexitepassword")
        self.verticalLayout_7.addWidget(self.complexitepassword)
        self.complexitevisuel = QtWidgets.QLabel(self.CardWidget_2)
        self.complexitevisuel.setBaseSize(QtCore.QSize(0, 5))
        self.complexitevisuel.setStyleSheet("background-color: red")
        self.complexitevisuel.setText("")
        self.complexitevisuel.setObjectName("complexitevisuel")
        self.complexitevisuel.setVisible(False)
        self.verticalLayout_7.addWidget(self.complexitevisuel)
        self.verticalLayout_4.addLayout(self.verticalLayout_7)
        self.gridLayout_5.addWidget(self.CardWidget_2, 2, 3, 1, 1)
        spacerItem12 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout_5.addItem(spacerItem12, 2, 2, 1, 1)
        self.verticalLayout_6.addLayout(self.gridLayout_5)
        spacerItem13 = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.verticalLayout_6.addItem(spacerItem13)
        self.verticalLayout_8 = QtWidgets.QVBoxLayout()
        self.verticalLayout_8.setContentsMargins(-1, -1, -1, 0)
        self.verticalLayout_8.setSpacing(6)
        self.verticalLayout_8.setObjectName("verticalLayout_8")
        self.CaptionLabel_3 = CaptionLabel(self.reseauciblecard)
        self.CaptionLabel_3.setMaximumSize(QtCore.QSize(16777215, 25))
        self.CaptionLabel_3.setObjectName("CaptionLabel_3")
        self.verticalLayout_8.addWidget(self.CaptionLabel_3)
        self.evaluationterminal = TextEdit(self.reseauciblecard)
        self.evaluationterminal.setMaximumSize(QtCore.QSize(16777215, 200))
        self.evaluationterminal.setReadOnly(True)
        self.evaluationterminal.setObjectName("evaluationterminal")
        self.verticalLayout_8.addWidget(self.evaluationterminal)
        self.verticalLayout_6.addLayout(self.verticalLayout_8)
        self.gridLayout_2.addWidget(self.reseauciblecard, 0, 0, 1, 1)
        self.gridLayout.addLayout(self.gridLayout_2, 1, 0, 1, 1)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setSizeConstraint(QtWidgets.QLayout.SetDefaultConstraint)
        self.horizontalLayout.setContentsMargins(-1, 0, -1, 0)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.IconWidget_3 = IconWidget(EvaluationInterface)
        self.IconWidget_3.setMinimumSize(QtCore.QSize(50, 50))
        self.IconWidget_3.setMaximumSize(QtCore.QSize(50, 50))
        icon2 = QtGui.QIcon()
        icon2.addPixmap(QtGui.QPixmap(":/images/strike.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.IconWidget_3.setIcon(icon2)
        self.IconWidget_3.setObjectName("IconWidget_3")
        self.horizontalLayout.addWidget(self.IconWidget_3)
        self.StrongBodyLabel = StrongBodyLabel(EvaluationInterface)
        font = QtGui.QFont()
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.StrongBodyLabel.setFont(font)
        self.StrongBodyLabel.setAlignment(QtCore.Qt.AlignCenter)
        self.StrongBodyLabel.setObjectName("StrongBodyLabel")
        self.horizontalLayout.addWidget(self.StrongBodyLabel)
        spacerItem14 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem14)
        self.gridLayout.addLayout(self.horizontalLayout, 0, 0, 1, 1)
        self.gridLayout_4.addLayout(self.gridLayout, 0, 0, 1, 1)

        self.retranslateUi(EvaluationInterface)
        QtCore.QMetaObject.connectSlotsByName(EvaluationInterface)

    def retranslateUi(self, EvaluationInterface):
        _translate = QtCore.QCoreApplication.translate
        EvaluationInterface.setWindowTitle(_translate("EvaluationInterface", "Form"))
        self.TitleLabel_4.setText(_translate("EvaluationInterface", "Liste des tests disponibles"))
        self.TitleLabel.setText(_translate("EvaluationInterface", "Liste des attaques disponibles"))
        self.TitleLabel_2.setText(_translate("EvaluationInterface", "Hydra by van Hauser/THC & David Maciejak"))
        self.CaptionLabel.setText(_translate("EvaluationInterface", "Cibles disponible :"))
        self.hydraexecution.setText(_translate("EvaluationInterface", "Exécuter"))
        self.TitleLabel_3.setText(_translate("EvaluationInterface", "Contrôle de fiabilité de Mot de Passe"))
        self.CaptionLabel_2.setText(_translate("EvaluationInterface", "Mot de passe à vérifier :"))
        self.passwordchecker.setPlaceholderText(_translate("EvaluationInterface", "Entrer le mot de passe à vérifier"))
        self.CaptionLabel_3.setText(_translate("EvaluationInterface", "Console des actions en cours :"))
        self.StrongBodyLabel.setText(_translate("EvaluationInterface", "Exploitation - Evaluation des Vulnérabilités"))
from qfluentwidgets import CaptionLabel, CardWidget, ComboBox, IconWidget, IndeterminateProgressBar, PasswordLineEdit, PrimaryPushButton, StrongBodyLabel, TextEdit, TitleLabel, VerticalSeparator
import app.resource.resource_rc