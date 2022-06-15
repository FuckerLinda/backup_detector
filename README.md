## 参数编辑在burp.py前30行

<br>

## 功能:对url路径进行拆分并探测是否存在备份文件

如：对于https://a.com/a/b.jpg/c/d

会探测是否存在https://a.com/a.zip、https://a.com/a/b.jpg/c.zip、https://a.com/a/b.jpg/c/d.zip
（此处除zip外还含其他备份后缀，可编辑参数）

用法:burp suite->Project options->Misc->Logging勾选Proxy的Requests,保存后缀为.log（若后缀为其他，在使用脚本时可能会出现编码错误）,会将burp浏览记录保存到log中,使用burp.py对log中内容进行探测。
