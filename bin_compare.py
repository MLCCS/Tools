'''
二进制(字节)比较两个文件的相同处，用于寻找绕过php的
imagecreatefromjpeg()的位置，但失败了。
使用：python image_compare.py <im1.jpg> <im2.jpg>
'''
#!/usr/bin/python
# -*- coding:utf-8 -*-
import binascii   
import sys


# 想要插入的payload,其长度即为字串比对的长度,根据需要修改
payload = "<?phpinfo();?>"

def bin_compare():
    """
    比对两个文件相同处并输出。
    """

    l = len(payload)
    s = b""
    # 比对的文件(可能会根据结果对其修改)
    compare = sys.argv[1]
    # 被比对的文件
    compared = sys.argv[2]
    with open(compare,"rb") as f:
        with open(compared,"rb") as ff:
            s = f.read(l)
            comp = ff.read()
            while True:
                if s in comp:
                    print(binascii.b2a_hex(s))
                s = s[1:]
                tmp = f.read(1)
                if not tmp:
                    break
                else:
                    s += tmp

if __name__ == "__main__":
    bin_compare()