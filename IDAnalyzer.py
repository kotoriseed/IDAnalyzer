from openai import OpenAI
import os
import idaapi
import idc
import ida_hexrays

def add_comment_to_pseudocode(comment_text):
    ea = idc.here()
    
    func = idaapi.get_func(ea)
    if not func:
        print("当前地址不在函数中")
        return

    cfunc = ida_hexrays.decompile(func.start_ea())
    if not cfunc:
        print("Failed to decompile the function.")
        return

    # 为反编译函数添加注释
    cfunc.set_comment(0, comment_text)
    idaapi.refresh_idaview_anyway()

def get_decompile():
    if not ida_hexrays.init_hexrays_plugin():
        print("Hex-Rays未正常加载")
    else:
        current_ea = idaapi.get_screen_ea()
        func = idaapi.get_func(current_ea)
        if not func:
            print("当前地址不在函数中")
        else:
            try:
                cfunc = ida_hexrays.decompile(func.start_ea)
                
                if cfunc:
                    pseudocode = cfunc.get_pseudocode()
                    decompiled_text = ""
                    for line_info in pseudocode:
                        # 处理颜色标签
                        clean_line = idaapi.tag_remove(line_info.line)
                        decompiled_text += clean_line + "\n"
                    
                    # print(decompiled_text)
                    return decompiled_text, cfunc
                else:
                    print("反编译失败")
                    
            except ida_hexrays.DecompilationFailure as e:
                print(f"反编译失败: {e}")
    return None

client = OpenAI(
    # defaults to os.environ.get("OPENAI_API_KEY")
    api_key="<your API key here>",
    base_url="https://api.chatanywhere.tech/v1"
    # base_url="https://api.chatanywhere.org/v1"
)

def gpt_35_api(messages: list):
    completion = client.chat.completions.create(model="gpt-3.5-turbo", messages=messages)
    print(completion.choices[0].message.content)
    return completion.choices[0].message.content

prefix = '请帮我分析以下伪代码，注意换行美观：'

message, cfunc = get_decompile()
message = prefix + message
cur_request = [{'role': 'user', 'content': '1'},]

cur_request[0]['content'] = message
# print(cur_request)
comment_text = gpt_35_api(cur_request)

idc.set_func_cmt(idc.here(), comment_text, 0)
cfunc.refresh_func_ctext()
idaapi.refresh_idaview_anyway()