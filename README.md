# AutoDoc 自动化编写库文档

> 工作涉密内容，文档已经改动，和main.py非正常适配，仅供参考代码思想

## 开发思路

### 分类

分成不同的类别。工控、木马、漏洞。每个类别下面，配套相应的模板。

### **txt**

文档有固定的模板，和文字内容。需要替换一些特定的部分，比如sid，比如cve，比如msg。将这些需要替换的部分，写入变量，python运行的时候，可以在终端输入要填入的变量部分。然后写回txt。手动写回部分，可以适用于那些需要查资料才能写出来的东西。

### **rules**

python也需要一个自动化填写的部分，依然是在txt里面设置变量。但是python也需要读取rule文件，将msg、sid、cve自动匹配读取出来，填入txt的相应变量中。这些过程自动实现，读取rule，写入txt。

### **最终思路**

**手动写回功能**

适用于那些需要查资料的部分。这部分的py，最开始需要一个输出，读取rule文件，将msg、cve打印出来。

需要输入，按顺序来提示相应的txt变量部分。查资料后，手动将这部分内容输入。需要手动输入的内容有：msg的翻译，漏洞导致的结果、CVE内容、造成的影响（和msg翻译内容一样，所以采用一个变量，统一填入）、影响的系统、漏洞类型、攻击链（对于漏洞模板来说，等级、攻击链这些变动的不多，所以可以适当减少变量。根据模板不同来调整）、目标设备（和影响的系统一致，采用一个变量，统一填入）

**自动写入功能**

适用于可以从rule中直接读取，然后填入txt中的内容。py将会自动化实现。需要自动匹配的内容有：sid、CVE编号。读入rule，写进txt。

**修改文件名**

文件最终需要修改为sid.txt

**自动生成language.txt**

将获取到的手动输入的自动翻译，生成一个翻译文档



## 实现过程

### 难点一：解决txt中变量定义的问题

在固定位置设置特殊字符`__SID__`来占位。之后用具体的数据来替换掉这个占位符，就可以起到一个变量的作用

### 难点二：一个rule文件有多条rule，怎么能准确匹配到需要的那个rule

在每个py功能执行前，都需要输入sid。在读取文本时，会先根据sid，再读特定的rule。去匹配。但是这个功能不好实现。暂时先不实现。手动将所有的rule都提取出来，变成一个单独的文本。

手动替换文档里的rule.txt。每次一条

### 难点三：获取文本中特定的内容

查找位置（返回的是查找内容所在数组位置）https://blog.csdn.net/weixin_43718786/article/details/114102454

分割（找到之后，如何将需要的内容提取出来） https://blog.csdn.net/weixin_43718786/article/details/114102454

输出特定位置的字符：https://blog.csdn.net/qq_51574759/article/details/116807925

### 难点四：更复杂的匹配

匹配想要内容的时候，可以用正则匹配【待定】
