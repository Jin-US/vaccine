# -*- coding: utf-8 -*-
import hashlib    # MD5를 구하기 위해 import
import shutil
import os
import getpass
import sys
sys.setrecursionlimit(3000000)#재귀 리미트 제한 해제

filePath = []
full_fname = []
u_name = getpass.getuser()
p_path = "C:\\Users\\"+u_name
fp = []
hashValue = []
hash =[]
temp_rute=[]
num2=0
num3=0
l_hash = []
res_n = []
addDB_d = ''



import PyQt5
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from PyQt5 import uic

CalUI = '../_uiFiles/TestMain.ui'

class MainDialog(QDialog):
    def __init__(self):
        QDialog.__init__(self, None)
        uic.loadUi(CalUI, self)

        self.page1.show()
        self.page2.hide()
        self.page3.hide()
        self.page4.hide()
        self.page5.hide()
        self.page6.hide()

        self.detect_Button.clicked.connect(self.detect)  # 탐지
        self.del_Button.clicked.connect(self.dele)  # 삭제
        self.add_Button.clicked.connect(self.upDB)  # 악성코드추가
        self.fin_Button.clicked.connect(self.fin)  # 종료
        self.first_B.clicked.connect(self.first)

        if os.path.exists('DB.txt'):
            QMessageBox.question(self, "알림", "\t프로그램을 실행 합니다.\t", QMessageBox.Yes)
        else:
            fDB = open("DB.txt", 'w')
            fDB.write('d44a0f63f6f8110067e56a2b5bd0f721\n')
            fDB.write('123123123214141231241\n')
            fDB.write('6b202dd60f6b02b05175aeab0f7e096c6\n')
            fDB.close()
            QMessageBox.question(self, "알림", "\tDB를 생성하였습니다.\t", QMessageBox.Yes)


    def dele(self):
        print('삭제기능')

    def upDB(self):
        global addDB_d
        self.page1.hide()
        self.page2.hide()
        self.page3.hide()
        self.page4.show()
        self.page5.hide()
        self.page6.hide()
        self.addDb_label.setText('여기에 경로를 입력하세요.')
        addDB_d, ok = QInputDialog.getText(self, 'Input', 'Enter your filePath')

        if ok:
            self.addDb_label.setText(str(addDB_d))
        self.addDb_B.clicked.connect(self.addDB)
        self.DBL_B.clicked.connect(self.DbList)

    # C:\Users\lj\Downloads\testFile\testfile.txt
    def addDB(self):
        global addDB_d, fp, hashValue, marDB, lines
        self.page1.hide()
        self.page2.hide()
        self.page3.hide()
        self.page4.show()
        self.page5.hide()
        self.page6.hide()

        fDB = open('DB.TXT')
        lines= fDB.readlines()
        for k in range(len(lines)):
            l_hash = lines[k]
            lines[k]=str(l_hash.strip())

        try:
            fp = open(addDB_d, 'rb')
            fbuf = fp.read()
            fp.close()
            f = hashlib.md5()  # MD5 hash function
            f.update(fbuf)  # hashing!
            hashValue = f.hexdigest()
            if hashValue in str(lines):
                self.addDb_label2.setText('이미 등록되어있는 파일 입니다.')
            else:
                f1 = open("DB.txt", 'a')
                marDB = hashValue
                f1.write(marDB + "\n")
                f1.close()  # 열려진 파일 객체를 닫는다.
                self.addDb_label2.setText(str(hashValue))

        except:
            self.addDb_label2.setText('해당 파일이 없습니다. 다시 입력 하세요')
            self.addDb_label.setText('여기에 경로를 다시 입력하세요.')
            addDB_d, ok = QInputDialog.getText(self, 'ReInput', 'Enter your filePath')

            if ok:
                self.addDb_label.setText(str(addDB_d))



    def DbList(self):
        global hashValue, lines, l_hash, fDB
        self.page1.hide()
        self.page2.hide()
        self.page3.hide()
        self.page4.hide()
        self.page5.show()
        self.page6.hide()

        if hashValue == []:
            self.addDBL_label.setText("최근 추가 항목 없음")
        else:
            self.addDBL_label.setText(str(hashValue))

        fDB = open('DB.TXT')
        lines = fDB.readlines()

        modelDb = QStandardItemModel()
        for k in range(len(lines)):
            l_hash = lines[k]
            lines[k] = str(l_hash.strip())
            modelDb.appendRow(QStandardItem(l_hash))

        self.listViewDB.setModel(modelDb)

    def detect(self):
        self.page1.hide()
        self.page2.show()
        self.page3.hide()
        self.page4.hide()
        self.page5.hide()
        self.page6.hide()
        self.inputr_label.hide()
        self.Next_B.hide()
        self.C_Button.clicked.connect(self.cr)
        self.D_Button.clicked.connect(self.dr)
        self.Dl_Button.clicked.connect(self.dl)
        self.Ir_Button.clicked.connect(self.ir)
        self.Next_B.clicked.connect(self.NextB)

    def cr(self):
        global select
        select = 1
        self.inputr_label.show()
        self.Next_B.show()
        self.inputr_label.setText('C 드라이브를 탐색합니다')
        self.route()


    def dr(self):
        global select
        select = 2
        self.inputr_label.show()
        self.Next_B.show()
        self.inputr_label.setText('D 드라이브를 탐색합니다')
        self.route()

    def dl(self):
        global select
        select = 3
        self.inputr_label.show()
        self.Next_B.show()
        self.inputr_label.setText('Downloads 를 탐색합니다')
        self.route()

    def ir(self):
        global select
        select = 4
        # self.inputr_label.show()
        # self.Next_B.show()
        # self.inputr_label.setText('경로를 입력하세요.')
        # self.route()
        self.page1.hide()
        self.page2.hide()
        self.page3.hide()
        self.page4.hide()
        self.page5.hide()
        self.page6.show()
        self.rpb.hide()
        self.next.hide()
        self.pb.show()
        self.pb.clicked.connect(self.findfile)


    def fin(self):
        self.fin_Button.clicked.connect(QCoreApplication.instance().quit)

    def route(self):
        global select, filePath
        if select == 1:
            self.Ir_Button.hide()
            filePath = 'C:\\'

        elif select == 2:
            self.Ir_Button.hide()
            filePath = 'D:\\'

        elif select == 3:
            self.Ir_Button.hide()
            filePath = p_path + '\\Downloads'

        elif select == 4:
            # self.inputr_label.setText('여기에 경로를 입력하세요.')
            # filePath, ok = QInputDialog.getText(self, 'Input', 'Enter your filePath')
            #
            # if ok:
            #     self.inputr_label.setText(str(filePath))
            self.Ir_Button.show()
            self.rpb.show()
            self.next.show()
            self.pb.hide()

            if self.lb.Text == '선택된 파일':
                self.rpb.clicked.connect(self.ir)
            else:
                self.rpb.hide()
                self.next.hide()
                self.pb.show()
                self.next.clicked.connect(self.route)
                self.rpb.clicked.connect(self.ir)

    def NextB(self):
        global filePath
        self.page1.hide()
        self.page2.hide()
        self.page3.show()
        self.page4.hide()
        self.page5.hide()
        self.page6.hide()
        self.readDir()

    def first(self):
        self.Ir_Button.show()
        self.page1.show()
        self.page2.hide()
        self.page3.hide()
        self.page4.hide()
        self.page5.hide()
        self.page6.hide()


    def readDir(self):  # 파일 이름 찾기 함수
        global res_n, fp, fbuf, hashValue, k, temp_rute, num2, num3, l_hash,filePath
        fDB = open('DB.txt')  # DB읽어오는 부분
        lines = fDB.readlines()
        for k in range(len(lines)):
            l_hash = lines[k]
            lines[k] = str(l_hash.strip())

        model = QStandardItemModel()

        try:
            for root, dirs, files in os.walk(filePath):
                rootpath = os.path.join(os.path.abspath(filePath), root)

                for file in files:
                    filePath = os.path.join(rootpath, file)
                    model.appendRow(QStandardItem(filePath))
                    try:
                        fp = open(filePath, 'rb')  # 반드시 바이너리 모드로 읽어들여 파일객체 생성
                    except:
                        continue
                    try:
                        fbuf = fp.read()  # 파일객체로부터 내용 읽어들여 버퍼에 저장
                    except:
                        continue

                    fp.close()
                    f = hashlib.md5()  # MD5 hash function
                    f.update(fbuf)  # hashing!
                    hashValue = f.hexdigest()  # 메시지 다이제스트를 얻음(16진수 해시값)
                    # self.scan_label.setText("\n" + filePath + " -> 검사중")
                    self.listView.setModel(model)
                    print("\n" + filePath + " -> 검사중")  # 지울예정
                    if hashValue in str(lines):  # EICAR test 파일의 MD5 해시값
                        temp_rute.append(filePath)  # 탐지된 악성코드 경로 저장
                        num2 += 1
        except:
            pass

        for txt in temp_rute:  # 탐지된 악성코드 격리파일로 이동
            if num3 == 0:
                num3 += 1

                self.result_label.setText('악성코드 발견!')

                if os.path.exists(p_path + '/Desktop/격리폴더'):
                    shutil.move(txt, p_path + '/Desktop/격리폴더')
                else:
                    os.mkdir(p_path + '/Desktop/격리폴더')
                    shutil.move(txt, p_path + '/Desktop/격리폴더')

            self.result2_label.setText('파일을 격리시켰습니다')
            self.result3_label.setText("바탕화면의 격리소 폴더를 확인하세요.")

        if num2 == 0:
            self.result2_label.setText("악성코드가 발견되지 않았습니다.")

    def findfile(self):
        self.page1.hide()
        self.page2.hide()
        self.page3.hide()
        self.page4.hide()
        self.page5.hide()
        self.page6.show()
        self.setWindowTitle("QFileDialLog")
        box = QBoxLayout(QBoxLayout.TopToBottom)

        box.addWidget(self.lb)
        box.addWidget(self.pb)
        self.setLayout(box)
        self.pb.clicked.connect(self.get_file_name)


    def get_file_name(self):
        filename = QFileDialog.getOpenFileName()
        self.lb.setText(filename[0])
        print(filename)

    def closeEvent(self, QCloseEvent):
        QMessageBox.question(self, "종료 확인", "종료", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)


app = QApplication(sys.argv)
main_dialog = MainDialog()
main_dialog.show()
app.exec_()