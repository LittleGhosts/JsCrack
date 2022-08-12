import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import requests
import argparse
import execjs


parser = argparse.ArgumentParser("36 氪逆向Demo")
parser.add_argument("-p", default='', dest="url", help="文章链接")
parser.add_argument("-s", default='', dest="keyword", help="搜索关键词")
args = parser.parse_args()
if not args.url and not args.keyword:
    parser.print_help()


headers = {
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'en,zh-CN;q=0.9,zh;q=0.8',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36',
}


def run_article(url):
    resp = requests.get(url, headers=headers)
    html = resp.text
    ciphertext = html.split('initialState={"state":"')[-1].split('","isEncryp')[0]
    aes = AES.new("efabccee-b754-4c".encode('utf-8'), AES.MODE_ECB)
    plaintext = aes.decrypt(base64.b64decode(ciphertext))
    return plaintext.decode("utf-8")


def run_search(keyword):
    ctx = execjs.compile(open("./36kr.js", "r", encoding="utf-8").read())
    session = requests.Session()
    resp_1 = session.get(f"https://36kr.com/search/articles/{keyword}", headers=headers)
    arg1 = resp_1.text.split(";")[0].split("arg1='")[-1]
    print("arg1: ", arg1)
    acw_sc__v2 = ctx.call('get_acw_tc', arg1)
    print("acw_sc__v2: ", acw_sc__v2)
    session.cookies.set(
        name="acw_sc__v2",
        value=acw_sc__v2
    )
    resp_2 = session.get(f"https://36kr.com/search/articles/{keyword}", headers=headers)
    print(resp_2.text)
    return resp_2.text


def main():
    if args.url:
        plaintext = run_article(args.url)
        print(plaintext)

    if args.keyword:
        html = run_search(args.keyword)


if __name__ == "__main__":
    main()


