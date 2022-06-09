import requests
import time

#每次获取url的间隔时间
sleep_time=0.5
#爬虫超时时间
time_out=5
#探测的后缀名
suffix=[".zip",".rar",".tar",".tar.gz",".bak",".7z"]
#burp log里存在的url
usable_dictionary="dictionary.txt"
#探测结果成功的url保存至success_url文件
success_url="200.txt"
#探测结果成功的url+返回结果+返回长度保存至details文件
details="detail.txt"
#过滤整理后的结果（若当前url与前一个url探测的文件返回长度相同，则将被过滤）保存至result文件
#已淘汰
#result="result.txt"
#（未授权探测）host含以下字符串，则不进行探测
blacklist=['.cn','.gov']

#为了尽可能过滤垃圾结果：
# 假设对某路径的访问存在：加上 suffix列表（即.zip、.rar、.tar.......）中的一种元素后能被成功访问，且为二进制。
# 若这样的情况存在多种（例如，不仅存在路径+.rar，还存在路径+.tar皆能被成功访问，且返回头Accept-Ranges为二进制）
# 则对此url的探测一律不予考虑
#目前代码逻辑即如上（同时，误判过滤的正确结果也可能变多）
#如果想保留尽可能多的探测结果（同时，误判产生的垃圾结果也可能变多），可考虑移除所有存在"#tttttttttt"的行（其实影响不大）

#未授权探测函数
def Unauthorized(host):
	for i in blacklist:
		if host.find(i)!=-1:
			return False
	return True



#将url拆分为多块，处理后传入列表
def parse_url(host,path,urllist):
	#以/划分path
	file_list=path.split("/")
	new_path=""
	#从父路径向子路径方向合成url。
	for file in file_list:
		#如果存在子目录就合成url
		#如果不存在就不管
		if file!='':
			#如果存在参数(2022/06/08新增):
			if file.find('?')!=-1:
				new_path=new_path+"/"+file[:file.find('?')]
				url=host+new_path
				if url not in urllist and file.find('.') == -1:
					urllist.append(url)
				file=file[file.find('?'):]
				new_path = new_path + file
			else:
				new_path=new_path+"/"+file
			url=host+new_path
			#如果url不在urllist中，且该子路径不含.（即子路径是个目录），则添加
			if url not in urllist and file.find('.')==-1:
				urllist.append(url)

urllist=[]
log=input("请输入burp日志绝对路径：")
with open(log, 'r') as f:
	i = f.read()
	line1=0
	line2=0
	line3=-1

	#检索'======================================================'，每3个为一组
	#如果没有检索到，linex都返回-1
	#反之，linex皆不为-1
	while 1:
		line1=i.find('======================================================',line3+1)
		line2=i.find('======================================================',line1+1)
		line3=i.find('======================================================',line2+1)
		if line1==-1:
			break
		host_begin=i.find('http',line1)
		host_end=i.find(' ',host_begin)
		if host_end-host_begin>50:
			host_end = i.find('\n', host_begin)
		path_begin=i.find('/', line2)
		path_end=i.find(' ', path_begin)
		#截取host、path并拼成url
		host=i[host_begin:host_end]
		if Unauthorized(host):
			continue
		path= i[path_begin:path_end]
		url=host+path
		#将url保存到urllist中
		#(一共有zip、rar、tar、tar.gz、bak五种后缀)
		parse_url(host,path,urllist)

		#print("url = "+url)
		#print("line1="+str(line1)+","+"line2="+str(line2)+","+"line3="+str(line3))
	print(urllist)


#写入文件
with open(usable_dictionary, 'w') as f:
	for i in urllist:
		f.write(i+"\n")
print("======================")
print("根据BurpLog,url字典生成完毕")
print("======================")
usablelist=[]
code_list=[]
body_len_list=[]

#一个url最多允许1次status_code=2xx，否则视为无此压缩包
#times即2xx次数
times=0																	#tttttttttt
#一个url有count种后缀，每种对应一个回合(round)，起始回合为0
#为了防止同一网站
round=0
#后缀类型数(一共有zip、rar、tar、tar.gz、bak五种后缀)
counts=len(suffix)
#进度
progress=0

print("开始请求字典url页面:")
for url in urllist:
	print(str(progress) + "/" + str(len(urllist)))
	progress = progress + 1

	#过滤最后的\n
	# request请求网页内容，并返回网页状态码
	protocols_end=url.find('//')
	host_end=url.find('/',protocols_end+2)
	# headers = {
	# 	'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
	# 	'Referer': 'https://github.com/',
	# 	'Host': 'github.com'
	# }
	headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
            'Referer': url[:host_end+1],
            'Host': url[protocols_end+2:host_end]
        }
	try:
		while round<counts:
			time.sleep(sleep_time)
			newurl=url+suffix[round]
			html = requests.get(newurl, headers=headers,timeout=time_out)
			code = html.status_code
			#print("newurl="+newurl)
			#print(code="+str(code)+"\n")
			if code >= 200 and code < 300 :  #and len(html.content) not in body_len_list# 网页正常访问,且返回长度不重复,且为二进制文件
				#若返回头Accept-Ranges为二进制
				if html.headers['Accept-Ranges']=='bytes':
					# 要执行的操作
					#print(html.content)
					body_len = len(html.content)
					code_list.append(code)
					body_len_list.append(body_len)
					#print(newurl)
					usablelist.append(newurl)
					times=times+1										#tttttttttt
			round=round+1
			if times > 1:												#tttttttttt
				break													#tttttttttt
		#如果.zip、.rar等多种后缀返回结果都为2xx，则表示存在异常，故移除访问的url
		if times>1:														#tttttttttt
			usablelist.pop()											#tttttttttt
			code_list.pop()												#tttttttttt
			body_len_list.pop()											#tttttttttt
			usablelist.pop()											#tttttttttt
			code_list.pop()												#tttttttttt
			body_len_list.pop()											#tttttttttt
		times=0															#tttttttttt
		round=0
	except:
		continue

print("======================")
print("======================")
print(usablelist)
print("======================")
#写入文件
with open(success_url, 'w') as f:
	for i in usablelist:
		f.write(i+"\n")

print("探测成功结果写入完毕")
print("======================")
with open(details, 'w') as f:
	for (i,j,k) in zip(usablelist,code_list,body_len_list):
		f.write(i + "\n")
		f.write(str(j) + ":" + str(k) + "\n\n")

print("探测细节写入完毕")
# 强过滤已在上方完成，故下方无需
# print("======================")
#
# filter=[]
#
# with open(result, 'w') as f:
# 	f.write(usablelist[0] + "\n")
# 	f.write(str(body_len_list[0]) + "\n\n")
# 	for i in range(1,len(code_list)):
# 		if body_len_list[i]!=body_len_list[i-1]:
# 			f.write(usablelist[i]+"\n")
# 			f.write(str(body_len_list[i])+"\n\n")
#
# print("初步过滤结束，结果整理完毕")