## 参数编辑在burp.py前30行

<br>

## 功能:对url路径进行拆分并探测是否存在备份文件

如：对于https://a.com/a/b.jpg/c/d

会探测是否存在https://a.com/a.zip、https://a.com/a/b.jpg/c.zip、https://a.com/a/b.jpg/c/d.zip
（此处除zip外还含其他备份后缀，可编辑参数）

