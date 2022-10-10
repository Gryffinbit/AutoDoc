import codecs
import re
import os, sys


def sidReturn():
    return sid


class Auto:
    # 不需要输出和输入、自动化进行替换
    def __init__(self):
        self.contents_rule = None
        self.contents_tmpl = None

    def init(self):
        self.read()
        self.replace()
        self.test()
        sidReturn()

    def read(self):
        # 读取规则文档
        with open('rule.txt', 'r', encoding='gb2312') as f0:
            contents_rule = f0.read()
            self.contents_rule = contents_rule

        # 读取Template规则文档
        with open('Template_ICS.txt', 'r', encoding='gb2312') as f1:
            contents_tmpl = f1.read()
            self.contents_tmpl = contents_tmpl

    def replace(self):
        # 在rule中查找sid、cve编号
        sid_loc_rule = self.contents_rule.rfind('sid:')
        sid_row_rule = self.contents_rule[int(sid_loc_rule) + 4:]
        cve_loc_rule = self.contents_rule.rfind('cve')
        cve_row_rule = self.contents_rule[int(cve_loc_rule) + 4:]
        # 提取已经获取到的sid、cve
        global sid
        global cve
        sid = sid_row_rule.split(";")[0]  # 提取分割后的前半部分。引号中的是查找的特定内容
        cve = str("CVE-") + cve_row_rule.split(";")[0]
        # 替换Template规则文档的sid、cve
        self.contents_tmpl = self.contents_tmpl.replace("__SID__", str(sid))
        self.contents_tmpl = self.contents_tmpl.replace("__CVE__", str(cve))

        # 将已经替换好的内容写入
        with open('Template_ICS.txt', 'w', encoding='gb2312') as f2:
            f2.write(self.contents_tmpl)

    def test(self):
        # print(self.contents_rule)
        print("自动化替换成功\n-------------------")


class Interact:
    # 手动替换，需要进行输出输入，进行人工的交互
    def __init__(self):
        self.contents_tmpl_interact = None
        self.contents_rule_interact = None

    def init(self):
        self.read()
        self.display()
        self.write()

    def read(self):
        # 读取规则文档
        with open('rule.txt', 'r', encoding='gb2312') as f3:
            contents_rule_interact = f3.read()
            self.contents_rule_interact = contents_rule_interact

        # 读取Template规则文档
        with open('Template_ICS.txt', 'r', encoding='gb2312') as f4:
            contents_tmpl_interact = f4.read()
            self.contents_tmpl_interact = contents_tmpl_interact

    def display(self):
        # 最开始需要一个输出，读取rule文件，将msg、cve打印出来。适用于那些需要查资料的部分。
        print(cve)
        msg_loc_rule = self.contents_rule_interact.rfind('msg:')
        msg_row_rule = self.contents_rule_interact[int(msg_loc_rule) + 4:]
        msg = msg_row_rule.split(";")[0]
        print(msg)

    def write(self):
        """ msg翻译内容 """
        print("输入msg翻译")
        msg_ch = input()
        # 替换到相应的位置
        self.contents_tmpl_interact = self.contents_tmpl_interact.replace("__MSG__", str(msg_ch))
        # 将已经替换好的内容写入
        with open('Template_ICS.txt', 'w', encoding='gb2312') as f5:
            f5.write(self.contents_tmpl_interact)

        """ 漏洞造成的影响 """
        print("输入漏洞造成的影响")
        info = input()
        # 替换到相应的位置
        self.contents_tmpl_interact = self.contents_tmpl_interact.replace("__info__", str(info))
        # 将已经替换好的内容写入
        with open('Template_ICS.txt', 'w', encoding='gb2312') as f5:
            f5.write(self.contents_tmpl_interact)

        """ CVE内容 """
        print("输入CVE的内容")
        cve_info = input()
        # 替换到相应的位置
        self.contents_tmpl_interact = self.contents_tmpl_interact.replace("__CVEINFO__", str(cve_info))
        # 将已经替换好的内容写入
        with open('Template_ICS.txt', 'w', encoding='gb2312') as f5:
            f5.write(self.contents_tmpl_interact)

        """ 影响的系统 """
        print("输入影响的系统")
        affect_s = input()
        # 替换到相应的位置
        self.contents_tmpl_interact = self.contents_tmpl_interact.replace("__AS__", str(affect_s))
        # 将已经替换好的内容写入
        with open('Template_ICS.txt', 'w', encoding='gb2312') as f5:
            f5.write(self.contents_tmpl_interact)

        """ 漏洞类型（其他漏洞利用、信息泄露漏洞利用等）"""
        print("输入漏洞类型")
        cve_type = input()
        # 替换到相应的位置
        self.contents_tmpl_interact = self.contents_tmpl_interact.replace("__Type__", str(cve_type))
        # 将已经替换好的内容写入
        with open('Template_ICS.txt', 'w', encoding='gb2312') as f5:
            f5.write(self.contents_tmpl_interact)

        """ 所属攻击链（可属于不同阶段、执行等）"""
        print("输入所属攻击链")
        kill_chain = input()
        # 替换到相应的位置
        self.contents_tmpl_interact = self.contents_tmpl_interact.replace("__KCType__", str(kill_chain))
        # 将已经替换好的内容写入
        with open('Template_ICS.txt', 'w', encoding='gb2312') as f5:
            f5.write(self.contents_tmpl_interact)


if __name__ == '__main__':
    Auto().init()
    Interact().init()
    # 文档改好后，需要修改文件名，改成sid.txt
    name = sidReturn() + ".txt"
    os.rename("当前工作/Template_ICS.txt",
              "当前工作" + name)
