'''
使用python3版本进行编写。
author：Mr.wang
'''
#coding=utf-8
import urllib3
import requests
import sys
import time
import ssl
import urllib.request
import json

class scanner:
    def __init__(self,file,address):
        self.file=file
        self.head={'X-Auth':"1986ad8c0a5b3df4d7028d5f3c06e936ca5c2eea4eeef44b4b25e0ba903ad2688"
                   ,'Content-type':"application/json"
                   ,"User-agent":r"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.0"}
        self.adders=address


    def scans(self):
        url = r"https://localhost:3443/api/v1/scans"
        Data={
            'target_id':str(self.targets_id),
            'profile_id':"11111111-1111-1111-1111-111111111111",
            'schedule':{"disable":False,"start_date":None,"time_sensitive":False}
            }
        Data=json.dumps(Data)
        try:
            response=requests.post(url,headers=self.head,data=Data,verify=False,timeout=30)
            if response.status_code == 200 or response.status_code ==201:
                print("任务开始.....")
            else:
                print("任务创建失败，返回值"+'\t'+str(response.status_code)+'\n')
        except Exception as e:
            print(str(e))
            return



    def add_targets(self):
        url=r"https://localhost:3443/api/v1/targets"
        Data={"address":self.adders,
              "description":"请求目标",
              "criticality":"30"
              }
        Data=json.dumps(Data)
        try:
            response=requests.post(url,headers=self.head,data=Data,verify=False,timeout=30)
            self.targets_id=json.loads(response.content)['target_id']


        except Exception as e:
            print(str(e))
            return
        print("任务添加成功，目标IP:"+'\t'+self.adders +'\t'+"任务ID"+'\t'+self.targets_id+'\n')



    def del_scan(self,target_id):
        url=r"https://localhost:3443/api/v1/scans/"+str(target_id)
        try:
            response=requests.delete(url,headers=self.head,verify=False,timeout=30)
            print("ID为"+'\t'+str(target_id)+'\t'+"任务删除成功...")
        except Exception as e:
            print("ID为"+'\t'+str(target_id)+'\t'+"任务删除失败...")
            print(str(e))



    def get_all(self):
        fp = open(r'D://1.txt', 'a+')
        url = r"https://localhost:3443/api/v1/scans"
        response=requests.get(url,headers=self.head,verify=False,timeout=30)
        #print(json.loads(response.content))
        target_context = json.loads(response.content)['scans'] # 目标id

        for target_long in target_context:
            if ((target_long['current_session'])['severity_counts'])['high'] >0:
                #print(((target_long['current_session'])['severity_counts'])['high'])
                print("漏洞等级为高的url为："+'\t'+(target_long['target'])['address'])
                fp.write(str(target_long))#   只写入威胁等级高的漏洞
                fp.write('\r\n'+"----------------------------------------------"+'\r\n')
        fp.close()


    def get_vulnerabilities(self):
        status="open" #状态，open公开，fied已修复，ignord忽略，false_positive误报，！open不公开
        url = r"https://localhost:3443/api/v1/vulnerabilities?q=status:"+status
        response=requests.get(url,headers=self.head,verify=False,timeout=30)
        #print(json.loads(response.content)['vulnerabilities'])
        for vuln in json.loads(response.content)['vulnerabilities']:
            print(vuln['vuln_id'])# 漏洞id，查询单个id的时候使用
            print("漏洞类型为:"+'\t'+str(vuln['tags'])+'\t'+"漏洞详情:"+'\t'+str(vuln['vt_name']))


if __name__ == '__main__':
    urllib3.disable_warnings()
    file=r"c:\\1.txt"
    test1=scanner(file,r"www.baidu.com")    #初始化一个类,预留file参数从文件里直接读url
   # test1.add_targets()             #添加任务方法
    #time.sleep(1)
    #test1.scans()                     #开始扫描
    #test1.get_all()                     #获取所有任务状态
   # test1.get_vulnerabilities()       #获取所有的漏洞

   