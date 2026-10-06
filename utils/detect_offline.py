import time

def offline_detection():
    # 模拟离线检测过程
    time.sleep(5)  # 模拟检测耗时
    return "离线检测完成，未发现恶意流量。"

if __name__ == '__main__':
    result = offline_detection()
    print(result)