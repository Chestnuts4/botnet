
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import idaapi
import idc
import idautils
import struct


def decrypt_data(start_ea, input):
    off = 0
    remine = len(input)
    while remine > 0:
        current_len = input[off] ^ input[off+1] ^ input[off+2]
        dec = ''
        for i in range(off + 3, off + 3 + current_len):
            tmp = ((input[i] ^ input[off + 1]) - input[off+1]) & 0xff
            tmp = tmp ^ input[off]
            dec += chr(tmp)
        print(hex(start_ea + off), "==>", dec)
        remine = remine - 3 - current_len - 1
        off = off + 3 + current_len + 1


def find_data_segment():
    """
    查找数据段
    """
    for segment in idautils.Segments():
        seg_name = idc.get_segm_name(segment)
        if seg_name == '.data':  # 根据实际段名修改
            return segment
    return None


def decrypt_and_write_data():
    """
    解密数据段数据并写回
    """
    try:
        # 获取数据段
        data_seg = find_data_segment()
        if not data_seg:
            print("未找到数据段！")
            return False

        # 获取数据段的起始和结束地址
        start_ea = idc.get_segm_start(data_seg)
        end_ea = idc.get_segm_end(data_seg)

        print(f"数据段范围: 0x{start_ea:X} - 0x{end_ea:X}")

        # 读取加密数据
        encrypted_data = idc.get_bytes(start_ea, end_ea - start_ea)
        if not encrypted_data:
            print("读取数据失败！")
            return False
        decrypt_data(start_ea, encrypted_data)
        return True

    except Exception as e:
        print(f"发生错误: {e}")
        return False


def main():
    print("开始解密数据段...")
    if decrypt_and_write_data():
        print("操作完成！")
    else:
        print("操作失败！")


if __name__ == "__main__":
    main()
